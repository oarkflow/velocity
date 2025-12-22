package velocity

import (
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

// NewLRUCache creates a new byte-capacity LRU cache. capacityBytes is total bytes allowed.
func NewLRUCache(capacityBytes int) *LRUCache {
	c := &LRUCache{
		capacityBytes: int64(capacityBytes),
		items:         make(map[string]*cacheItem),
		evictList:     newList(),
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
	// cacheSize is interpreted as bytes (e.g., 50 * 1024 * 1024 for 50MB)
	db.mutex.Lock()
	defer db.mutex.Unlock()
	db.cache = NewLRUCache(cacheSize)
}
