package velocity

import (
	"fmt"
	"hash/crc32"
	"log"
	"os"
	"path"
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
	levels     [][]*SSTable // levels[0] = L0, levels[1] = L1, etc.
	mutex      sync.RWMutex
	compacting atomic.Bool
	cache      *LRUCache
	crypto     *CryptoProvider

	// Configuration
	memTableSize int64
	// Files storage
	filesDir      string
	MaxUploadSize int64

	// Master key management
	masterKeyManager *MasterKeyManager
	masterKey        []byte // Store the master key
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
	Path              string
	EncryptionKey     []byte
	MasterKey         []byte // If provided and valid, use this as the master key
	MaxUploadSize     int64  // bytes; 0 means use default
	MasterKeyConfig   MasterKeyConfig // New: flexible master key configuration
	DeviceFingerprint bool   // Enable device fingerprint validation
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

func (db *DB) GetWAL() *WAL {
	return db.wal
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

	// Initialize master key configuration if not provided
	if cfg.MasterKeyConfig == (MasterKeyConfig{}) {
		cfg.MasterKeyConfig = DefaultMasterKeyConfig()
	}

	// Create master key manager
	masterKeyManager := NewMasterKeyManager(currentPath, cfg.MasterKeyConfig)

	// Get master key using the manager
	// Priority: MasterKey from config > EncryptionKey from config > manager default behavior
	var explicitKey []byte
	if len(cfg.MasterKey) > 0 {
		explicitKey = cfg.MasterKey
	} else if len(cfg.EncryptionKey) > 0 {
		explicitKey = cfg.EncryptionKey
	}
	key, err := ensureMasterKeyWithManager(masterKeyManager, explicitKey)
	if err != nil {
		return nil, err
	}

	// Apply device fingerprint key binding if enabled
	if cfg.DeviceFingerprint {
		key, err = combineWithDeviceKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to bind key to device: %w", err)
		}
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
		path:             currentPath,
		memTable:         NewMemTable(),
		wal:              wal,
		levels:           make([][]*SSTable, MaxLevels),
		memTableSize:     DefaultMemTableSize,
		cache:            nil,
		crypto:           cryptoProvider,
		MaxUploadSize:    cfg.MaxUploadSize,
		masterKeyManager: masterKeyManager,
		masterKey:        key,
	}
	// Ensure files directory exists for object storage
	db.filesDir = filepath.Join(db.path, "objects")
	os.MkdirAll(db.filesDir, 0755)

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
			// Parse level from filename, e.g., sst_L0_001.db -> level 0
			level := 0
			if len(name) > 6 && name[4:6] == "L" {
				if l, err := strconv.Atoi(name[5:6]); err == nil && l < MaxLevels {
					level = l
				}
			}
			if level >= len(db.levels) {
				db.levels = append(db.levels, make([][]*SSTable, level-len(db.levels)+1)...)
			}
			db.levels[level] = append(db.levels[level], sst)
		}
	}

	// Start background compaction
	go db.compactionLoop()

	return db, nil
}

func (db *DB) MasterKey() []byte {
	return db.masterKey
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

// PutWithTTL stores a key with a TTL. If ttl <= 0 the key will not expire.
func (db *DB) PutWithTTL(key, value []byte, ttl time.Duration) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	// Build entry
	e := entryPool.Get().(*Entry)
	e.Key = append(e.Key[:0], key...)
	e.Value = append(e.Value[:0], value...)
	e.Timestamp = uint64(time.Now().UnixNano())
	if ttl > 0 {
		e.ExpiresAt = uint64(time.Now().Add(ttl).UnixNano())
	} else {
		e.ExpiresAt = 0
	}
	e.Deleted = false
	// checksum
	h := crc32.NewIEEE()
	h.Write(e.Key)
	h.Write(e.Value)
	e.checksum = h.Sum32()

	// Write to WAL
	if err := db.wal.Write(e); err != nil {
		entryPool.Put(e)
		return err
	}

	// Put into memtable
	db.memTable.PutEntry(e)

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
		// Check expiry
		if entry.ExpiresAt != 0 && time.Now().UnixNano() > int64(entry.ExpiresAt) {
			return nil, fmt.Errorf("key not found")
		}
		if entry.Deleted {
			return nil, fmt.Errorf("key not found")
		}
		value := entry.Value
		if db.cache != nil {
			db.cache.Put(keyStr, append([]byte{}, value...))
		}
		return value, nil
	}

	// Check SSTables by level
	for level := 0; level < len(db.levels); level++ {
		sstables := db.levels[level]
		// Search SSTables in reverse order (newest first) within level
		for i := len(sstables) - 1; i >= 0; i-- {
			entry, err := sstables[i].Get(key)
			if err != nil {
				return nil, err
			}
			if entry != nil {
				// Check expiry
				if entry.ExpiresAt != 0 && time.Now().UnixNano() > int64(entry.ExpiresAt) {
					return nil, fmt.Errorf("key not found")
				}
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

	// Create new SSTable in L0
	level := 0
	sstPath := filepath.Join(db.path, fmt.Sprintf("sst_L%d_%d.db", level, time.Now().UnixNano()))
	sst, err := NewSSTable(sstPath, entries, db.crypto)
	if err != nil {
		return err
	}

	db.levels[level] = append(db.levels[level], sst)

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

	for _, level := range db.levels {
		for _, sst := range level {
			sst.Close()
		}
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

	// Check SSTables by level
	for level := 0; level < len(db.levels); level++ {
		sstables := db.levels[level]
		// Search SSTables in reverse order (newest first) within level
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

// TTL returns the remaining time to live for key. If key has no expiry, it
// returns -1 duration and nil error. If key does not exist or is expired, it
// returns 0 and an error.
func (db *DB) TTL(key []byte) (time.Duration, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	// Check memtable first
	if entry := db.memTable.Get(key); entry != nil {
		// deleted or expired
		if entry.Deleted {
			return 0, fmt.Errorf("key not found")
		}
		if entry.ExpiresAt == 0 {
			return time.Duration(-1), nil
		}
		remaining := time.Until(time.Unix(0, int64(entry.ExpiresAt)))
		if remaining <= 0 {
			return 0, fmt.Errorf("key not found")
		}
		return remaining, nil
	}

	// Check SSTables by level
	for level := 0; level < len(db.levels); level++ {
		sstables := db.levels[level]
		for i := len(sstables) - 1; i >= 0; i-- {
			entry, err := sstables[i].Get(key)
			if err != nil {
				return 0, err
			}
			if entry != nil {
				if entry.Deleted {
					return 0, fmt.Errorf("key not found")
				}
				if entry.ExpiresAt == 0 {
					return time.Duration(-1), nil
				}
				remaining := time.Until(time.Unix(0, int64(entry.ExpiresAt)))
				if remaining <= 0 {
					return 0, fmt.Errorf("key not found")
				}
				return remaining, nil
			}
		}
	}

	return 0, fmt.Errorf("key not found")
}

// Keys returns all keys that match the provided shell-style pattern. If pattern
// is empty it behaves like "*". Uses path.Match for globbing semantics.
func (db *DB) Keys(pattern string) ([]string, error) {
	if pattern == "" {
		pattern = "*"
	}
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	seen := make(map[string]bool)
	var keys []string
	match := func(s string) bool {
		ok, _ := path.Match(pattern, s)
		return ok
	}

	// memtable: recent entries override
	db.memTable.entries.Range(func(k, v any) bool {
		e := v.(*Entry)
		s := string(e.Key)
		if e.Deleted {
			return true
		}
		if e.ExpiresAt != 0 && time.Now().UnixNano() > int64(e.ExpiresAt) {
			return true
		}
		if match(s) && !seen[s] {
			seen[s] = true
			keys = append(keys, s)
		}
		return true
	})

	// For small DBs we materialize all keys for deterministic ordering
	totalEstimate := 0
	for _, level := range db.levels {
		for _, sst := range level {
			totalEstimate += sst.entryCount
		}
	}
	if totalEstimate <= 100000 {
		allKeys := make([]string, 0, totalEstimate+1000)
		for k := range seen {
			allKeys = append(allKeys, k)
		}
		for _, level := range db.levels {
			for _, sst := range level {
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
		}
		uniq := make(map[string]bool)
		uKeys := make([]string, 0, len(allKeys))
		for _, s := range allKeys {
			if !uniq[s] && match(s) {
				uniq[s] = true
				uKeys = append(uKeys, s)
			}
		}
		sort.Strings(uKeys)
		return uKeys, nil
	}

	// Large DB: sequential scan
	for _, level := range db.levels {
		for _, sst := range level {
			idxPos := uint32(0)
			for i := 0; i < sst.entryCount; i++ {
				entry, err := sst.readIndexEntryAt(idxPos)
				if err != nil {
					break
				}
				if !entryIsDeletedInMemTable(db.memTable, entry.Key) {
					s := string(entry.Key)
					if match(s) && !seen[s] {
						seen[s] = true
						keys = append(keys, s)
					}
				}
				idxEntrySize := 4 + len(entry.Key) + 8 + 4
				idxPos += uint32(idxEntrySize)
			}
		}
	}

	sort.Strings(keys)
	return keys, nil
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
	// When the DB is small we want to materialize the full set of keys, so always
	// iterate the memtable completely. For large DBs we may stop early in the
	// sequential SSTable scan below to avoid scanning the entire dataset.
	db.memTable.entries.Range(func(key, value any) bool {
		entry := value.(*Entry)
		if !entry.Deleted {
			appendKey(entry.Key)
		}
		return true
	})

	// If database is small-ish, materialize all keys for deterministic ordering and accurate pagination
	// (this keeps behavior deterministic for the HTTP API and tests)
	totalEstimate := 0
	for _, level := range db.levels {
		for _, sst := range level {
			totalEstimate += sst.entryCount
		}
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
		for _, level := range db.levels {
			for _, sst := range level {
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
	for _, level := range db.levels {
		for _, sst := range level {
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
		if limit > 0 && len(keys) >= offset+limit {
			break
		}
	}

	// compute total conservatively as number of unique keys we've seen plus remaining entries across SSTables not yet scanned
	total := len(seen)
	// we can approximate total as unique keys + sum of sst.entryCount to avoid extra scans
	for _, level := range db.levels {
		for _, sst := range level {
			total += sst.entryCount
		}
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

// compactionLoop runs in the background and performs compaction when levels exceed size thresholds
func (db *DB) compactionLoop() {
	ticker := time.NewTicker(10 * time.Second) // Check every 10 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			db.performCompaction()
		}
	}
}

// performCompaction checks levels and compacts if necessary
func (db *DB) performCompaction() {
	if db.compacting.Load() {
		return // Already compacting
	}
	db.compacting.Store(true)
	defer db.compacting.Store(false)

	db.mutex.Lock()
	defer db.mutex.Unlock()

	// Calculate level sizes
	levelSizes := make([]int64, MaxLevels)
	for level, sstables := range db.levels {
		for _, sst := range sstables {
			// Approximate size as entryCount * average entry size (rough estimate)
			levelSizes[level] += int64(sst.entryCount * 100) // Assume 100 bytes per entry
		}
	}

	// Check each level for compaction
	for level := 0; level < MaxLevels-1; level++ {
		nextLevelSize := levelSizes[level+1]
		if nextLevelSize == 0 {
			nextLevelSize = 1 // Avoid division by zero
		}
		if float64(levelSizes[level]) > float64(CompactionRatio)*float64(nextLevelSize) {
			db.compactLevel(level)
			break // Compact one level at a time
		}
	}
}

// compactLevel merges level with level+1
func (db *DB) compactLevel(level int) {
	if level >= MaxLevels-1 {
		return
	}

	// Collect all entries from current level and next level
	var allEntries []*Entry
	iterators := make([]*SSTableIterator, 0)

	// Add iterators for current level
	for _, sst := range db.levels[level] {
		iter, err := NewSSTableIterator(sst)
		if err != nil {
			log.Printf("velocity: failed to create iterator for sstable: %v", err)
			continue
		}
		iterators = append(iterators, iter)
	}

	// Add iterators for next level
	for _, sst := range db.levels[level+1] {
		iter, err := NewSSTableIterator(sst)
		if err != nil {
			log.Printf("velocity: failed to create iterator for sstable: %v", err)
			continue
		}
		iterators = append(iterators, iter)
	}

	// Merge iterators
	merged := NewMergedIterator(iterators...)

	// Collect all entries, resolving duplicates (newer timestamps win)
	seen := make(map[string]*Entry)
	for merged.Next() {
		entry := merged.Entry()
		keyStr := string(entry.Key)
		if existing, ok := seen[keyStr]; !ok || entry.Timestamp > existing.Timestamp {
			seen[keyStr] = entry
		}
	}

	for _, entry := range seen {
		allEntries = append(allEntries, entry)
	}

	// Sort entries
	sort.Slice(allEntries, func(i, j int) bool {
		return compareKeys(allEntries[i].Key, allEntries[j].Key) < 0
	})

	// Create new SSTables for next level
	newSSTables := make([]*SSTable, 0)
	batchSize := 10000 // Entries per SSTable
	for i := 0; i < len(allEntries); i += batchSize {
		end := i + batchSize
		if end > len(allEntries) {
			end = len(allEntries)
		}
		batch := allEntries[i:end]

		sstPath := filepath.Join(db.path, fmt.Sprintf("sst_L%d_%d.db", level+1, time.Now().UnixNano()))
		sst, err := NewSSTable(sstPath, batch, db.crypto)
		if err != nil {
			log.Printf("velocity: failed to create compacted sstable: %v", err)
			continue
		}
		newSSTables = append(newSSTables, sst)
	}

	// Close and remove old SSTables
	for _, sst := range db.levels[level] {
		sst.Close()
		os.Remove(sst.file.Name())
	}
	for _, sst := range db.levels[level+1] {
		sst.Close()
		os.Remove(sst.file.Name())
	}

	// Update levels
	db.levels[level] = nil // Clear current level
	db.levels[level+1] = newSSTables

	log.Printf("velocity: compacted level %d into level %d, created %d sstables", level, level+1, len(newSSTables))
}
