package velocity

import "github.com/oarkflow/velocity/pkg/storage"

// EnableCache enables the embedded DB read cache.
func (db *DB) EnableCache(cacheSize int) {
	// cacheSize is interpreted as bytes (e.g., 50 * 1024 * 1024 for 50MB).
	// If cacheSize == 0, the cache is sized adaptively by pkg/storage.
	db.mutex.Lock()
	defer db.mutex.Unlock()
	db.cache = storage.NewLRUCache(cacheSize)
}

// SetCacheMode sets a high-level cache sizing policy.
// Modes:
//   - "aggressive": tiny memory footprint (<= 16MB)
//   - "balanced": reasonable memory/perf tradeoff (<= 32MB)
//   - "performance": prioritize performance (<= 128MB)
func (db *DB) SetCacheMode(mode string) {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	var capBytes int
	switch mode {
	case "aggressive":
		capBytes = 16 * 1024 * 1024
	case "balanced":
		capBytes = 32 * 1024 * 1024
	case "performance":
		capBytes = 128 * 1024 * 1024
	default:
		capBytes = 32 * 1024 * 1024
	}
	db.cache = storage.NewLRUCache(capBytes)
}
