package velocity

import "sync"

// Cache layer for hot data
type LRUCache struct {
	capacity  int
	items     map[string]*cacheItem
	evictList *list
	mutex     sync.RWMutex
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

func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity:  capacity,
		items:     make(map[string]*cacheItem),
		evictList: newList(),
	}
}

func (c *LRUCache) Get(key string) ([]byte, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if item, exists := c.items[key]; exists {
		c.evictList.moveToFront(item.node)
		return item.value, true
	}
	return nil, false
}

func (c *LRUCache) Put(key string, value []byte) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if item, exists := c.items[key]; exists {
		item.value = value
		c.evictList.moveToFront(item.node)
		return
	}

	// Add new item
	item := &cacheItem{
		key:   key,
		value: append([]byte{}, value...),
	}
	node := &listNode{item: item}
	item.node = node

	c.items[key] = item
	c.evictList.pushFront(node)

	// Evict if necessary
	if len(c.items) > c.capacity {
		if oldest := c.evictList.removeLast(); oldest != nil {
			delete(c.items, oldest.item.key)
		}
	}
}

func (c *LRUCache) Remove(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if item, exists := c.items[key]; exists {
		c.evictList.remove(item.node)
		delete(c.items, key)
	}
}

// Enhanced VelocityDB with caching
func (db *DB) EnableCache(cacheSize int) {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	db.cache = NewLRUCache(cacheSize)
}
