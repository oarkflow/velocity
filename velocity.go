package velocity

import (
	"fmt"
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

	// Configuration
	memTableSize int64
}

func New(path string) (*DB, error) {
	err := os.MkdirAll(path, 0755)
	if err != nil {
		return nil, err
	}

	walPath := filepath.Join(path, "wal.log")
	wal, err := NewWAL(walPath)
	if err != nil {
		return nil, err
	}

	db := &DB{
		path:         path,
		memTable:     NewMemTable(),
		wal:          wal,
		sstables:     make([]*SSTable, 0),
		memTableSize: DefaultMemTableSize,
		cache:        nil,
	}

	// Start background compaction
	// go db.compactionLoop()

	return db, nil
}

func (db *DB) Put(key, value []byte) error {
	entry := &Entry{
		Key:       append([]byte{}, key...),
		Value:     append([]byte{}, value...),
		Timestamp: uint64(time.Now().UnixNano()),
		Deleted:   false,
	}

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
	db.mutex.RLock()
	sstables := make([]*SSTable, len(db.sstables))
	copy(sstables, db.sstables)
	db.mutex.RUnlock()

	// Search SSTables in reverse order (newest first)
	for i := len(sstables) - 1; i >= 0; i-- {
		if entry := sstables[i].Get(key); entry != nil {
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
	entry := &Entry{
		Key:       append([]byte{}, key...),
		Value:     nil,
		Timestamp: uint64(time.Now().UnixNano()),
		Deleted:   true,
	}

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
	sst, err := NewSSTable(sstPath, entries)
	if err != nil {
		return err
	}

	db.sstables = append(db.sstables, sst)

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
	db.mutex.RLock()
	sstables := make([]*SSTable, len(db.sstables))
	copy(sstables, db.sstables)
	db.mutex.RUnlock()

	// Search SSTables in reverse order (newest first)
	for i := len(sstables) - 1; i >= 0; i-- {
		if entry := sstables[i].Get(key); entry != nil {
			return !entry.Deleted
		}
	}

	return false
}

func (db *DB) incr(key []byte, incr float64, action string) (any, error) {
	// Get current value
	current, err := db.Get(key)
	if err != nil {
		// If not found, assume 0
		current = []byte("0")
	}

	currentFloat, err := strconv.ParseFloat(string(current), 64)
	if err != nil {
		return nil, fmt.Errorf("current value is not a number")
	}

	var newVal float64
	if action == "incr" {
		newVal = currentFloat + incr
	} else if action == "decr" {
		newVal = currentFloat - incr
	} else {
		return nil, fmt.Errorf("invalid action")
	}

	// Store as string
	newValStr := strconv.FormatFloat(newVal, 'f', -1, 64)
	err = db.Put(key, []byte(newValStr))
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
	db.mutex.RLock()
	sstables := make([]*SSTable, len(db.sstables))
	copy(sstables, db.sstables)
	db.mutex.RUnlock()

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
