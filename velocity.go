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
	DefaultMemTableSize    = 256 * 1024 * 1024 // 256MB
	DefaultBlockSize       = 4096
	DefaultBloomFilterBits = 10

	// WAL settings
	WALBufferSize   = 10 * 1024 * 1024 // 10MB
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
	Path          string
	EncryptionKey []byte
}

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
		path:         currentPath,
		memTable:     NewMemTable(),
		wal:          wal,
		sstables:     make([]*SSTable, 0),
		memTableSize: DefaultMemTableSize,
		cache:        nil,
		crypto:       cryptoProvider,
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

func (db *DB) Put(key, value []byte) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	return db.put(key, value)
}

// Internal put method without locking - used when already holding a lock
func (db *DB) put(key, value []byte) error {
	entry := &Entry{
		Key:       append([]byte{}, key...),
		Value:     append([]byte{}, value...),
		Timestamp: uint64(time.Now().UnixNano()),
		Deleted:   false,
	}

	// Compute checksum before writing to WAL so replay can verify integrity
	entry.checksum = crc32.ChecksumIEEE(append(entry.Key, entry.Value...))

	// Write to WAL first for durability
	err := db.wal.Write(entry)
	if err != nil {
		return err
	}

	// Write to memtable
	db.memTable.Put(key, value)

	// Update cache
	if db.cache != nil {
		db.cache.Put(string(key), append([]byte{}, value...))
	}

	// Check if memtable needs to be flushed
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

func (db *DB) Keys() [][]byte {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	keysMap := make(map[string]bool)

	// From memtable
	db.memTable.entries.Range(func(key, value any) bool {
		entry := value.(*Entry)
		if !entry.Deleted {
			keysMap[string(entry.Key)] = true
		}
		return true
	})

	// From SSTables
	sstables := make([]*SSTable, len(db.sstables))
	copy(sstables, db.sstables)

	for _, sst := range sstables {
		for _, idx := range sst.indexData {
			keysMap[string(idx.Key)] = true
		}
	}

	var keys [][]byte
	for k := range keysMap {
		keys = append(keys, []byte(k))
	}

	return keys
}
