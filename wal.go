package velocity

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// WAL (Write-Ahead Log) for durability
type WAL struct {
	file     *os.File
	buffer   *bytes.Buffer
	mutex    sync.Mutex
	ticker   *time.Ticker
	stopChan chan struct{}
	closed   bool
	crypto   *CryptoProvider

	// Rotation policy
	rotationThreshold int64  // bytes; rotate when file >= this size (0 disables)
	archiveDir        string // where to move rotated WALs (must be same FS for atomic rename)
	maxBackups        int    // keep only this many rotated files (0 = keep all)
	maxAgeDays        int    // remove rotated files older than this (0 = no age pruning)

	// Time-based rotation
	rotationInterval time.Duration // rotate at least this often (0 disables)
	lastRotationTime time.Time     // last time rotation occurred
}

func NewWAL(path string, crypto *CryptoProvider) (*WAL, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	if crypto == nil {
		return nil, fmt.Errorf("encryption provider is required for WAL")
	}

	wal := &WAL{
		file:     file,
		buffer:   bytes.NewBuffer(make([]byte, 0, WALBufferSize)),
		ticker:   time.NewTicker(WALSyncInterval),
		stopChan: make(chan struct{}),
		crypto:   crypto,
		// defaults: rotation disabled
		rotationThreshold: 0,
		archiveDir:        "",
		maxBackups:        0,
		maxAgeDays:        0,
		rotationInterval:  0,
		lastRotationTime:  time.Now().UTC(),
	}

	// Background sync + rotation goroutine
	go wal.syncLoop()

	return wal, nil
}

func (w *WAL) Write(entry *Entry) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	// Encrypt value using AEAD with entry metadata as AAD
	nonce, ciphertext, err := w.crypto.Encrypt(entry.Value, buildEntryAAD(entry.Key, entry.Timestamp, entry.Deleted))
	if err != nil {
		return err
	}

	keyLen := uint32(len(entry.Key))
	nonceLen := uint16(len(nonce))
	valueLen := uint32(len(ciphertext))

	binary.Write(w.buffer, binary.LittleEndian, keyLen)
	w.buffer.Write(entry.Key)
	binary.Write(w.buffer, binary.LittleEndian, nonceLen)
	w.buffer.Write(nonce)
	binary.Write(w.buffer, binary.LittleEndian, valueLen)
	w.buffer.Write(ciphertext)
	binary.Write(w.buffer, binary.LittleEndian, entry.Timestamp)

	var deleted uint8
	if entry.Deleted {
		deleted = 1
	}
	binary.Write(w.buffer, binary.LittleEndian, deleted)
	binary.Write(w.buffer, binary.LittleEndian, entry.checksum)

	// Sync if buffer is full
	if w.buffer.Len() >= WALBufferSize {
		return w.syncUnsafe()
	}

	return nil
}

func (w *WAL) syncLoop() {
	for {
		select {
		case <-w.ticker.C:
			// sync without holding lock for the entire rotation check
			w.mutex.Lock()
			w.syncUnsafe()
			w.mutex.Unlock()
			// Check rotation policy (may perform rotation under lock)
			_ = w.CheckRotation()
		case <-w.stopChan:
			return
		}
	}
}

// SetRotationPolicy configures WAL rotation behaviour.
// thresholdBytes: rotate when file size >= thresholdBytes (0 disables)
// archiveDir: directory to move archived WAL files into (if empty, uses <waldir>/wal_archive)
// maxBackups: keep at most this many rotated files (0 = keep all)
// maxAgeDays: delete rotated files older than this many days (0 = ignore age)
func (w *WAL) SetRotationPolicy(thresholdBytes int64, archiveDir string, maxBackups int, maxAgeDays int) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.rotationThreshold = thresholdBytes
	w.archiveDir = archiveDir
	w.maxBackups = maxBackups
	w.maxAgeDays = maxAgeDays
}

// SetRotationInterval sets a time-based rotation interval (0 disables).
func (w *WAL) SetRotationInterval(d time.Duration) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.rotationInterval = d
}

// CheckRotation forces a rotation check (size and time) and rotates if needed.
func (w *WAL) CheckRotation() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	// size-based
	if w.rotationThreshold > 0 {
		stat, err := w.file.Stat()
		if err == nil && stat.Size() >= w.rotationThreshold {
			return w.rotateUnlocked()
		}
	}
	// time-based
	if w.rotationInterval > 0 && time.Since(w.lastRotationTime) >= w.rotationInterval {
		return w.rotateUnlocked()
	}
	return nil
}

// Sync forces the WAL buffer to be persisted to disk.
func (w *WAL) Sync() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.syncUnsafe()
}

func (w *WAL) syncUnsafe() error {
	if w.buffer.Len() == 0 {
		return nil
	}

	_, err := w.file.Write(w.buffer.Bytes())
	if err != nil {
		return err
	}

	err = w.file.Sync()
	if err != nil {
		return err
	}

	w.buffer.Reset()
	return nil
}

func (w *WAL) Close() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	// Prevent double-closing
	if w.closed {
		return nil
	}
	w.closed = true

	defer func() {
		if r := recover(); r != nil {
			log.Printf("WAL.Close() panic recovered: %v", r)
		}
	}()

	close(w.stopChan)
	w.ticker.Stop()

	w.syncUnsafe()
	return w.file.Close()
}

// Truncate truncates the WAL file to zero length after ensuring data has been flushed.
func (w *WAL) Truncate() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if err := w.syncUnsafe(); err != nil {
		return err
	}

	// Truncate file
	if err := w.file.Truncate(0); err != nil {
		return err
	}
	// Seek to beginning so subsequent appends go to start
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	w.buffer.Reset()
	return nil
}

// RotateNow performs an immediate rotation of the WAL into the archive dir and
// applies retention (maxBackups / maxAgeDays). The WAL file will be moved and a
// new WAL file opened at the same path.
func (w *WAL) RotateNow() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.rotateUnlocked()
}

func (w *WAL) rotateIfNeeded() error {
	// assumes caller holds lock
	stat, err := w.file.Stat()
	if err != nil {
		return err
	}
	if stat.Size() < w.rotationThreshold || w.rotationThreshold == 0 {
		return nil
	}
	return w.rotateUnlocked()
}

func (w *WAL) rotateUnlocked() error {
	// caller must hold lock
	// Ensure buffer / file are synced
	if err := w.syncUnsafe(); err != nil {
		return err
	}

	orig := w.file.Name()
	// Determine archive dir
	archive := w.archiveDir
	if archive == "" {
		archive = filepath.Join(filepath.Dir(orig), "wal_archive")
	}
	if err := os.MkdirAll(archive, 0755); err != nil {
		return err
	}

	// Create destination
	timestamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	dest := filepath.Join(archive, fmt.Sprintf("wal_%s.log", timestamp))

	// Close current file and rename
	if err := w.file.Close(); err != nil {
		return err
	}
	if err := os.Rename(orig, dest); err != nil {
		// Attempt to reopen original file in case rename failed
		w.file, _ = os.OpenFile(orig, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		return err
	}

	// Open new WAL file
	newf, err := os.OpenFile(orig, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// Try to restore original by renaming back (best-effort)
		_ = os.Rename(dest, orig)
		return err
	}
	w.file = newf
	w.buffer.Reset()
	w.lastRotationTime = time.Now().UTC()

	// Retention: by age
	if w.maxAgeDays > 0 {
		files, _ := os.ReadDir(archive)
		cutoff := time.Now().Add(-time.Duration(w.maxAgeDays) * 24 * time.Hour)
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			if !strings.HasPrefix(f.Name(), "wal_") {
				continue
			}
			info, err := f.Info()
			if err != nil {
				continue
			}
			if info.ModTime().Before(cutoff) {
				_ = os.Remove(filepath.Join(archive, f.Name()))
			}
		}
	}

	// Retention: by count (keep most recent)
	if w.maxBackups > 0 {
		files, _ := os.ReadDir(archive)
		var walFiles []os.DirEntry
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			if strings.HasPrefix(f.Name(), "wal_") {
				walFiles = append(walFiles, f)
			}
		}
		if len(walFiles) > w.maxBackups {
			// Sort by name which includes timestamp
			sort.Slice(walFiles, func(i, j int) bool { return walFiles[i].Name() > walFiles[j].Name() })
			for i := w.maxBackups; i < len(walFiles); i++ {
				_ = os.Remove(filepath.Join(archive, walFiles[i].Name()))
			}
		}
	}

	return nil
}

// ArchiveStats reports basic information about rotated WAL archives in the
// configured archive directory. It returns the number of archive files, their
// total size, and the list of filenames (sorted newest-first).
func (w *WAL) ArchiveStats() (int, int64, []string, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	orig := w.file.Name()
	archive := w.archiveDir
	if archive == "" {
		archive = filepath.Join(filepath.Dir(orig), "wal_archive")
	}

	files, err := os.ReadDir(archive)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, nil, nil
		}
		return 0, 0, nil, err
	}

	var walFiles []os.DirEntry
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if strings.HasPrefix(f.Name(), "wal_") {
			walFiles = append(walFiles, f)
		}
	}

	// Sort newest-first by filename (timestamp embedded)
	sort.Slice(walFiles, func(i, j int) bool { return walFiles[i].Name() > walFiles[j].Name() })

	var total int64
	var names []string
	for _, f := range walFiles {
		info, err := f.Info()
		if err != nil {
			continue
		}
		total += info.Size()
		names = append(names, f.Name())
	}

	return len(names), total, names, nil
}

// Replay reads and returns all entries from the WAL file in order.
// It does not modify the WAL file; callers should decide whether to truncate
// the WAL after successfully flushing entries to SSTables.
func (w *WAL) Replay() ([]*Entry, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	// Ensure file is synced to disk before reading
	if err := w.file.Sync(); err != nil {
		return nil, err
	}

	// Open file for reading from start
	f, err := os.Open(w.file.Name())
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []*Entry
	for {
		var keyLen uint32
		if err := binary.Read(f, binary.LittleEndian, &keyLen); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		key := make([]byte, keyLen)
		if _, err := io.ReadFull(f, key); err != nil {
			return nil, err
		}

		var nonceLen uint16
		if err := binary.Read(f, binary.LittleEndian, &nonceLen); err != nil {
			return nil, err
		}
		nonce := make([]byte, nonceLen)
		if _, err := io.ReadFull(f, nonce); err != nil {
			return nil, err
		}

		var valueLen uint32
		if err := binary.Read(f, binary.LittleEndian, &valueLen); err != nil {
			return nil, err
		}
		ciphertext := make([]byte, valueLen)
		if _, err := io.ReadFull(f, ciphertext); err != nil {
			return nil, err
		}

		var timestamp uint64
		if err := binary.Read(f, binary.LittleEndian, &timestamp); err != nil {
			return nil, err
		}

		var deleted uint8
		if err := binary.Read(f, binary.LittleEndian, &deleted); err != nil {
			return nil, err
		}

		var checksum uint32
		if err := binary.Read(f, binary.LittleEndian, &checksum); err != nil {
			return nil, err
		}

		// Decrypt
		plaintext, err := w.crypto.Decrypt(nonce, ciphertext, buildEntryAAD(key, timestamp, deleted == 1))
		if err != nil {
			// Decryption error likely means corruption; stop and return what we have
			return nil, fmt.Errorf("WAL replay: decrypt failed for key %x: %w", key, err)
		}

		entry := &Entry{
			Key:       append([]byte{}, key...),
			Value:     append([]byte{}, plaintext...),
			Timestamp: timestamp,
			Deleted:   deleted == 1,
			checksum:  checksum,
		}

		// basic checksum verification
		calc := crc32.ChecksumIEEE(append(entry.Key, entry.Value...))
		if entry.Deleted {
			calc = crc32.ChecksumIEEE(entry.Key)
		}
		if calc != entry.checksum {
			return nil, fmt.Errorf("WAL replay: checksum mismatch for key %x: expected %08x got %08x", key, entry.checksum, calc)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}
