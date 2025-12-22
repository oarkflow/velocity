package velocity

import (
	"bufio"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// LRUCache is a byte-limited LRU cache with a simple buffer pool to reduce allocations.
// capacity is the total byte capacity (not item count).
type LRUCache struct {
	capacityBytes int64
	totalBytes    int64
	items         map[string]*cacheItem
	evictList     *list
	mutex         sync.Mutex
	bufPool       *bufferPool
}

// bounded buffer pool to avoid unbounded memory retention
type bufferPool struct {
	ch chan []byte
}

func newBufferPool(max int) *bufferPool {
	return &bufferPool{ch: make(chan []byte, max)}
}

func (p *bufferPool) Get(minSize int) []byte {
	select {
	case b := <-p.ch:
		if cap(b) >= minSize {
			return b[:minSize]
		}
		// not big enough, drop it
		return make([]byte, minSize)
	default:
		return make([]byte, minSize)
	}
}

func (p *bufferPool) Put(b []byte) {
	select {
	case p.ch <- b[:0]:
		// stored
	default:
		// pool full, drop
	}
}

type cacheItem struct {
	key   string
	value []byte
	node  *listNode
}

type listNode struct {
	prev, next *listNode
	item       *cacheItem
}

type list struct {
	head, tail *listNode
}

func newList() *list {
	head := &listNode{}
	tail := &listNode{}
	head.next = tail
	tail.prev = head
	return &list{head: head, tail: tail}
}

func (l *list) pushFront(node *listNode) {
	node.prev = l.head
	node.next = l.head.next
	l.head.next.prev = node
	l.head.next = node
}

func (l *list) remove(node *listNode) {
	node.prev.next = node.next
	node.next.prev = node.prev
}

func (l *list) moveToFront(node *listNode) {
	l.remove(node)
	l.pushFront(node)
}

func (l *list) removeLast() *listNode {
	last := l.tail.prev
	if last == l.head {
		return nil
	}
	l.remove(last)
	return last
}

// detectTotalMemory tries to detect system memory in bytes. Falls back to 1GB on failure.
func detectTotalMemory() int64 {
	// macOS: use sysctl hw.memsize
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
		if err == nil {
			s := strings.TrimSpace(string(out))
			if v, err := strconv.ParseInt(s, 10, 64); err == nil {
				return v
			}
		}
	}

	// Linux: parse /proc/meminfo
	f, err := os.Open("/proc/meminfo")
	if err == nil {
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := s.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if v, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						return v * 1024 // kB -> bytes
					}
				}
			}
		}
	}

	// Fallback
	return 1 * 1024 * 1024 * 1024
}

// NewLRUCache creates a new byte-capacity LRU cache. If capacityBytes == 0 cache size is chosen adaptively.
func NewLRUCache(capacityBytes int) *LRUCache {
	c := &LRUCache{
		items:     make(map[string]*cacheItem),
		evictList: newList(),
	}

	// Adaptive sizing when 0 is passed
	if capacityBytes == 0 {
		total := detectTotalMemory()
		// Target ~2% of system memory with reasonable bounds
		suggest := int64(float64(total) * 0.02)
		if suggest < 4*1024*1024 {
			suggest = 4 * 1024 * 1024
		}
		// Lower adaptive cap to 32MB by default to keep hybrid lightweight
		if suggest > 32*1024*1024 {
			suggest = 32 * 1024 * 1024
		}
		c.capacityBytes = suggest
	} else {
		c.capacityBytes = int64(capacityBytes)
	}

	c.bufPool = newBufferPool(1024) // bounded to avoid holding unlimited buffers
	return c
}

func (c *LRUCache) Get(key string) ([]byte, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if item, exists := c.items[key]; exists {
		c.evictList.moveToFront(item.node)
		// Return a copy to avoid callers mutating internal buffer
		out := make([]byte, len(item.value))
		copy(out, item.value)
		return out, true
	}
	return nil, false
}

func (c *LRUCache) Put(key string, value []byte) {
	if c.capacityBytes == 0 {
		return
	}

	sz := int64(len(value))

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if item, exists := c.items[key]; exists {
		// replace value and adjust size
		c.totalBytes -= int64(len(item.value))
		buf := make([]byte, len(value))
		copy(buf, value)
		item.value = buf
		c.totalBytes += int64(len(item.value))
		c.evictList.moveToFront(item.node)
		// evict if over capacity
		for c.totalBytes > c.capacityBytes {
			if oldest := c.evictList.removeLast(); oldest != nil {
				c.totalBytes -= int64(len(oldest.item.value))
				delete(c.items, oldest.item.key)
				// recycle small buffers
				if cap(oldest.item.value) <= 64*1024 {
					c.bufPool.Put(oldest.item.value[:0])
				}
			}
		}
		return
	}

	// allocate buffer (try pool)
	var buf []byte
	buf = c.bufPool.Get(len(value))
	copy(buf, value)

	item := &cacheItem{
		key:   key,
		value: buf,
	}
	node := &listNode{item: item}
	item.node = node

	c.items[key] = item
	c.evictList.pushFront(node)
	c.totalBytes += sz

	// Evict until under capacity
	for c.totalBytes > c.capacityBytes {
		if oldest := c.evictList.removeLast(); oldest != nil {
			c.totalBytes -= int64(len(oldest.item.value))
			delete(c.items, oldest.item.key)
			if cap(oldest.item.value) <= 64*1024 {
				c.bufPool.Put(oldest.item.value[:0])
			}
		} else {
			break
		}
	}
}

func (c *LRUCache) Remove(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if item, exists := c.items[key]; exists {
		c.evictList.remove(item.node)
		c.totalBytes -= int64(len(item.value))
		delete(c.items, key)
		if cap(item.value) <= 64*1024 {
			c.bufPool.Put(item.value[:0])
		}
	}
}

// Enhanced VelocityDB with caching
func (db *DB) EnableCache(cacheSize int) {
	// cacheSize is interpreted as bytes (e.g., 50 * 1024 * 1024 for 50MB).
	// If cacheSize == 0, the cache will be sized adaptively (now capped to 32MB by default).
	db.mutex.Lock()
	defer db.mutex.Unlock()
	db.cache = NewLRUCache(cacheSize)
}

// SetCacheMode sets a high-level cache sizing policy.
// Modes:
//  - "aggressive": tiny memory footprint (<= 16MB)
//  - "balanced": reasonable memory/perf tradeoff (<= 32MB)
//  - "performance": prioritize performance (<= 128MB)
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
		// default to balanced
		capBytes = 32 * 1024 * 1024
	}
	db.cache = NewLRUCache(capBytes)
}
