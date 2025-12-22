package velocity

import (
	"fmt"
	"hash/crc32"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oarkflow/convert"
)

// Configuration constants
const (
	// Memory table settings
	// Reduced default memtable size to keep Hybrid memory-efficient by default
	DefaultMemTableSize    = 16 * 1024 * 1024 // 16MB (reduced default)
	DefaultBlockSize       = 4096
	DefaultBloomFilterBits = 10

	// WAL settings
	// Reduce WAL buffer to lower peak memory usage while keeping batching benefits
	WALBufferSize   = 1 * 1024 * 1024 // 1MB
	WALSyncInterval = 1 * time.Second

	// Compaction settings
	MaxLevels       = 7
	CompactionRatio = 4

	// File format constants
	MagicNumber = 0xDEADBEEF
	Version     = 1
)

// DB - Main database struct
type DB struct {
	path       string
	memTable   *MemTable
	wal        *WAL
	sstables   []*SSTable
	mutex      sync.RWMutex
	compacting atomic.Bool
	cache      *LRUCache
	crypto     *CryptoProvider

	// Configuration
	memTableSize int64
	// Files storage
	filesDir       string
	maxUploadSize  int64
	useFileStorage bool
}

var defaultPath = "./data/velocity"

func init() {
	path, err := os.UserHomeDir()
	if err == nil {
		defaultPath = filepath.Join(path, ".velocity")
	}
	if _, err := os.Stat(defaultPath); os.IsNotExist(err) {
		os.MkdirAll(defaultPath, 0755)
	}
}

type Config struct {
	Path           string
	EncryptionKey  []byte
	MaxUploadSize  int64 // bytes; 0 means use default
	UseFileStorage bool  // store files on filesystem instead of in-DB blobs
}

const (
	DefaultMaxUploadSize = 100 * 1024 * 1024 // 100 MB
)

func New(path ...string) (*DB, error) {
	cfg := Config{}
	if len(path) > 0 && path[0] != "" {
		cfg.Path = path[0]
	}
	return NewWithConfig(cfg)
}

func NewWithConfig(cfg Config) (*DB, error) {
	currentPath := cfg.Path
	if currentPath == "" {
		currentPath = defaultPath
	}
	if err := os.MkdirAll(currentPath, 0755); err != nil {
		return nil, err
	}

	if cfg.MaxUploadSize == 0 {
		cfg.MaxUploadSize = DefaultMaxUploadSize
	}

	key, err := ensureMasterKey(currentPath, cfg.EncryptionKey)
	if err != nil {
		return nil, err
	}

	cryptoProvider, err := newCryptoProvider(key)
	if err != nil {
		return nil, err
	}

	walPath := filepath.Join(currentPath, "wal.log")
	wal, err := NewWAL(walPath, cryptoProvider)
	if err != nil {
		return nil, err
	}

	// Replay WAL to restore memtable state
	entries, err := wal.Replay()
	if err != nil {
		// If the WAL is corrupted, it's safer to surface the error so callers
		// can decide how to proceed (repair, delete WAL, etc.)
		return nil, fmt.Errorf("failed to replay WAL: %w", err)
	}

	db := &DB{
		path:           currentPath,
		memTable:       NewMemTable(),
		wal:            wal,
		sstables:       make([]*SSTable, 0),
		memTableSize:   DefaultMemTableSize,
		cache:          nil,
		crypto:         cryptoProvider,
		maxUploadSize:  cfg.MaxUploadSize,
		useFileStorage: cfg.UseFileStorage,
	}
	if db.useFileStorage {
		db.filesDir = filepath.Join(db.path, "files")
		os.MkdirAll(db.filesDir, 0755)
	}

	// Load entries from WAL into memtable
	if len(entries) > 0 {
		db.memTable.LoadEntries(entries)
		log.Printf("velocity: WAL replay restored %d entries", len(entries))
	}

	// Load existing SSTables from disk
	files, err := os.ReadDir(currentPath)
	if err == nil {
		for _, f := range files {
			name := f.Name()
			if !(len(name) > 4 && name[:4] == "sst_") {
				continue
			}
			if filepath.Ext(name) != ".db" {
				continue
			}
			path := filepath.Join(currentPath, name)
			sst, err := LoadSSTable(path, cryptoProvider)
			if err != nil {
				log.Printf("velocity: failed to load sstable %s: %v", name, err)
				continue
			}
			db.sstables = append(db.sstables, sst)
		}
	}

	// Start background compaction
	// go db.compactionLoop()

	return db, nil
}

// SetPerformanceMode toggles high-level performance profiles for the DB.
// "performance": maximize throughput (larger memtable, larger cache, larger WAL buffer)
// "balanced": reasonable tradeoff
// "aggressive": minimal memory footprint
func (db *DB) SetPerformanceMode(mode string) {
	// Compute desired parameters without holding the DB lock to avoid nested locking
	var memSize int64
	var cacheMode string
	var walBuf int
	var walInterval time.Duration

	switch mode {
	case "performance":
		memSize = 128 * 1024 * 1024 // 128MB
		cacheMode = "performance"
		walBuf = 8 * 1024 * 1024
		walInterval = 200 * time.Millisecond
	case "balanced":
		memSize = 32 * 1024 * 1024 // 32MB
		cacheMode = "balanced"
		walBuf = 1 * 1024 * 1024
		walInterval = 1 * time.Second
	case "aggressive":
		memSize = 16 * 1024 * 1024 // 16MB
		cacheMode = "aggressive"
		walBuf = 512 * 1024
		walInterval = 2 * time.Second
	default:
		// fall back to balanced
		memSize = 32 * 1024 * 1024
		cacheMode = "balanced"
		walBuf = 1 * 1024 * 1024
		walInterval = 1 * time.Second
	}

	// Apply the memtable sizing under lock
	db.mutex.Lock()
	db.memTableSize = memSize
	db.mutex.Unlock()

	// Use the existing SetCacheMode (it handles its own locking)
	db.SetCacheMode(cacheMode)

	// Configure WAL without holding the DB lock
	if db.wal != nil {
		db.wal.SetBufferSize(walBuf)
		db.wal.SetSyncInterval(walInterval)
	}
}

func (db *DB) Put(key, value []byte) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	return db.put(key, value)
}

// Internal put method without locking - used when already holding a lock
func (db *DB) put(key, value []byte) error {
	// Get an entry from pool to reduce allocations
	e := entryPool.Get().(*Entry)
	e.Key = append(e.Key[:0], key...)
	e.Value = append(e.Value[:0], value...)
	e.Timestamp = uint64(time.Now().UnixNano())
	e.Deleted = false
	// Compute checksum using streaming to avoid temporary concatenation
	h := crc32.NewIEEE()
	h.Write(e.Key)
	h.Write(e.Value)
	e.checksum = h.Sum32()

	// Write to WAL first for durability
	err := db.wal.Write(e)
	if err != nil {
		entryPool.Put(e)
		return err
	}

	// Write to memtable (memtable will use its own pool)
	db.memTable.Put(key, value)

	// Update cache
	if db.cache != nil {
		db.cache.Put(string(key), append([]byte{}, value...))
	}

	// Return entry buffer to pool
	entryPool.Put(e)
	if db.memTable.Size() > db.memTableSize {
		go db.flushMemTable()
	}

	return nil
}

func (db *DB) Get(key []byte) ([]byte, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	return db.get(key)
}

// Internal get method without locking - used when already holding a lock
func (db *DB) get(key []byte) ([]byte, error) {
	keyStr := string(key)
	if db.cache != nil {
		if val, ok := db.cache.Get(keyStr); ok {
			return val, nil
		}
	}

	// Check memtable first
	if entry := db.memTable.Get(key); entry != nil {
		if entry.Deleted {
			return nil, fmt.Errorf("key not found")
		}
		value := entry.Value
		if db.cache != nil {
			db.cache.Put(keyStr, append([]byte{}, value...))
		}
		return value, nil
	}

	// Check SSTables
	sstables := make([]*SSTable, len(db.sstables))
	copy(sstables, db.sstables)

	// Search SSTables in reverse order (newest first)
	for i := len(sstables) - 1; i >= 0; i-- {
		entry, err := sstables[i].Get(key)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			if entry.Deleted {
				return nil, fmt.Errorf("key not found")
			}
			value := entry.Value
			if db.cache != nil {
				db.cache.Put(keyStr, append([]byte{}, value...))
			}
			return value, nil
		}
	}

	return nil, fmt.Errorf("key not found")
}

func (db *DB) Delete(key []byte) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	entry := &Entry{
		Key:       append([]byte{}, key...),
		Value:     nil,
		Timestamp: uint64(time.Now().UnixNano()),
		Deleted:   true,
	}

	// Compute checksum for tombstone
	entry.checksum = crc32.ChecksumIEEE(entry.Key)

	err := db.wal.Write(entry)
	if err != nil {
		return err
	}

	db.memTable.Delete(key)

	if db.cache != nil {
		db.cache.Remove(string(key))
	}

	return nil
}

func (db *DB) flushMemTable() error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	// Create new memtable
	oldMemTable := db.memTable
	db.memTable = NewMemTable()

	// Collect all entries
	var entries []*Entry
	oldMemTable.entries.Range(func(key, value any) bool {
		entries = append(entries, value.(*Entry))
		return true
	})

	if len(entries) == 0 {
		return nil
	}

	// Sort entries by key
	sort.Slice(entries, func(i, j int) bool {
		return compareKeys(entries[i].Key, entries[j].Key) < 0
	})

	// Create new SSTable
	sstPath := filepath.Join(db.path, fmt.Sprintf("sst_%d.db", time.Now().UnixNano()))
	sst, err := NewSSTable(sstPath, entries, db.crypto)
	if err != nil {
		return err
	}

	db.sstables = append(db.sstables, sst)

	// Truncate WAL after successfully flushing memtable to SSTable
	if err := db.wal.Truncate(); err != nil {
		log.Printf("velocity: WAL truncation failed: %v", err)
		return err
	}

	return nil
}

func (db *DB) Close() error {
	db.flushMemTable()

	db.mutex.RLock()
	defer db.mutex.RUnlock()

	for _, sst := range db.sstables {
		sst.Close()
	}

	return db.wal.Close()
}

func (db *DB) Has(key []byte) bool {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	if db.cache != nil {
		if _, ok := db.cache.Get(string(key)); ok {
			return true
		}
	}

	// Check memtable first
	if entry := db.memTable.Get(key); entry != nil {
		return !entry.Deleted
	}

	// Check SSTables
	sstables := make([]*SSTable, len(db.sstables))
	copy(sstables, db.sstables)

	// Search SSTables in reverse order (newest first)
	for i := len(sstables) - 1; i >= 0; i-- {
		entry, err := sstables[i].Get(key)
		if err != nil {
			log.Printf("velocity: integrity verification failed for key %x: %v", key, err)
			continue
		}
		if entry != nil {
			return !entry.Deleted
		}
	}

	return false
}

func (db *DB) incr(key []byte, incr float64, action string) (any, error) {
	// Use write lock to ensure atomicity of read-modify-write operation
	db.mutex.Lock()
	defer db.mutex.Unlock()

	// Get current value
	current, err := db.get(key) // Use internal get method to avoid double locking
	if err != nil {
		// If not found, assume 0
		current = []byte("0")
	}

	currentFloat, err := strconv.ParseFloat(string(current), 64)
	if err != nil {
		return nil, fmt.Errorf("current value is not a number")
	}

	var newVal float64
	switch action {
	case "incr":
		newVal = currentFloat + incr
	case "decr":
		newVal = currentFloat - incr
	default:
		return nil, fmt.Errorf("invalid action")
	}

	// Store as string using internal put method to avoid double locking
	newValStr := strconv.FormatFloat(newVal, 'f', -1, 64)
	err = db.put(key, []byte(newValStr))
	if err != nil {
		return nil, err
	}

	return newVal, nil
}

func (db *DB) Incr(key []byte, step ...any) (any, error) {
	var val float64 = 1
	if len(step) > 0 {
		if floatVal, ok := convert.ToFloat64(step[0]); ok {
			val = floatVal
		}
	}
	return db.incr(key, val, "incr")
}

func (db *DB) Decr(key []byte, step ...any) (any, error) {
	var val float64 = 1
	if len(step) > 0 {
		if floatVal, ok := convert.ToFloat64(step[0]); ok {
			val = floatVal
		}
	}
	return db.incr(key, val, "decr")
}

// KeysPage returns a page of keys (offset, limit) without loading the entire dataset into memory.
// It returns the page of keys and the total number of keys.
func (db *DB) KeysPage(offset, limit int) ([][]byte, int) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	seen := make(map[string]bool)
	var keys [][]byte

	// Helper to append key if not seen and not deleted
	appendKey := func(k []byte) {
		s := string(k)
		if seen[s] {
			return
		}
		seen[s] = true
		keys = append(keys, append([]byte{}, k...))
	}

	// From memtable (recent keys override older sstable keys)
	db.memTable.entries.Range(func(key, value any) bool {
		entry := value.(*Entry)
		if !entry.Deleted {
			appendKey(entry.Key)
		}
		// stop early if we've collected enough for requested pages
		if limit > 0 && len(keys) >= offset+limit {
			return false
		}
		return true
	})

	// If database is small-ish, materialize all keys for deterministic ordering and accurate pagination
	// (this keeps behavior deterministic for the HTTP API and tests)
	totalEstimate := 0
	for _, sst := range db.sstables {
		totalEstimate += sst.entryCount
	}
	// memtable entries count is hard to obtain directly; assume small
	if totalEstimate <= 100000 {
		// materialize full key set and sort
		allKeys := make([]string, 0, totalEstimate+1000)
		// include keys we've already collected
		for k := range seen {
			allKeys = append(allKeys, k)
		}
		// scan remaining sstables to add keys
		for _, sst := range db.sstables {
			idxPos := uint32(0)
			for i := 0; i < sst.entryCount; i++ {
				entry, err := sst.readIndexEntryAt(idxPos)
				if err != nil {
					break
				}
				if !entryIsDeletedInMemTable(db.memTable, entry.Key) {
					allKeys = append(allKeys, string(entry.Key))
				}
				idxEntrySize := 4 + len(entry.Key) + 8 + 4
				idxPos += uint32(idxEntrySize)
			}
		}
		// deduplicate and sort
		uniq := make(map[string]bool)
		uKeys := make([]string, 0, len(allKeys))
		for _, s := range allKeys {
			if !uniq[s] {
				uniq[s] = true
				uKeys = append(uKeys, s)
			}
		}
		sort.Strings(uKeys)
		// convert back to [][]byte
		keys = make([][]byte, 0, len(uKeys))
		for _, s := range uKeys {
			keys = append(keys, []byte(s))
		}
		total := len(keys)
		if limit == 0 {
			return keys, total
		}
		start := offset
		if start > len(keys) {
			start = len(keys)
		}
		end := offset + limit
		if end > len(keys) {
			end = len(keys)
		}
		return keys[start:end], total
	}

	// From SSTables — sequential scan, stop once we've collected enough
	sstables := make([]*SSTable, len(db.sstables))
	copy(sstables, db.sstables)

	for _, sst := range sstables {
		// iterate index region sequentially until we have enough
		idxPos := uint32(0)
		for i := 0; i < sst.entryCount; i++ {
			entry, err := sst.readIndexEntryAt(idxPos)
			if err != nil {
				break
			}
			if !entryIsDeletedInMemTable(db.memTable, entry.Key) { // ensure not deleted by memtable
				appendKey(entry.Key)
			}
			idxEntrySize := 4 + len(entry.Key) + 8 + 4
			idxPos += uint32(idxEntrySize)
			if limit > 0 && len(keys) >= offset+limit {
				break
			}
		}
		if limit > 0 && len(keys) >= offset+limit {
			break
		}
	}

	// compute total conservatively as number of unique keys we've seen plus remaining entries across SSTables not yet scanned
	total := len(seen)
	// we can approximate total as unique keys + sum of sst.entryCount to avoid extra scans
	for _, sst := range db.sstables {
		total += sst.entryCount
	}

	if limit == 0 {
		return keys, total
	}

	start := offset
	if start > len(keys) {
		start = len(keys)
	}
	end := offset + limit
	if end > len(keys) {
		end = len(keys)
	}
	return keys[start:end], total
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func entryIsDeletedInMemTable(mt *MemTable, key []byte) bool {
	if v, ok := mt.entries.Load(string(key)); ok {
		e := v.(*Entry)
		return e.Deleted
	}
	return false
}
