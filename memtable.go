package velocity

import (
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"
	"sync"
	"sync/atomic"
	"time"
)

// Entry represents a key-value pair with metadata
type Entry struct {
	Key       []byte
	Value     []byte
	Timestamp uint64
	Deleted   bool
	checksum  uint32
}

// EntryPool for reducing GC pressure
var entryPool = sync.Pool{
	New: func() interface{} {
		return &Entry{
			Key:   make([]byte, 0, 64),
			Value: make([]byte, 0, 256),
		}
	},
}

// MemTable represents an in-memory table using concurrent map
type MemTable struct {
	entries sync.Map
	size    int64
}

func NewMemTable() *MemTable {
	return &MemTable{
		size: 0,
	}
}

func (mt *MemTable) Put(key, value []byte) {
	entry := entryPool.Get().(*Entry)
	entry.Key = append(entry.Key[:0], key...)
	entry.Value = append(entry.Value[:0], value...)
	entry.Timestamp = uint64(time.Now().UnixNano())
	entry.Deleted = false
	entry.checksum = crc32.ChecksumIEEE(append(key, value...))

	oldSize := int64(0)
	if old, ok := mt.entries.Load(string(key)); ok {
		oldSize = int64(len(old.(*Entry).Key) + len(old.(*Entry).Value))
	}

	mt.entries.Store(string(key), entry)
	atomic.AddInt64(&mt.size, int64(len(entry.Key)+len(entry.Value))-oldSize)
}

func (mt *MemTable) Get(key []byte) *Entry {
	if val, ok := mt.entries.Load(string(key)); ok {
		return val.(*Entry)
	}
	return nil
}

func (mt *MemTable) Delete(key []byte) {
	entry := entryPool.Get().(*Entry)
	entry.Key = append(entry.Key[:0], key...)
	entry.Value = entry.Value[:0]
	entry.Timestamp = uint64(time.Now().UnixNano())
	entry.Deleted = true
	entry.checksum = crc32.ChecksumIEEE(key)

	mt.entries.Store(string(key), entry)
}

func (mt *MemTable) Size() int64 {
	return atomic.LoadInt64(&mt.size)
}

// Skip List implementation optimized for performance
const MaxLevel = 16

type SkipListNode struct {
	entry   *Entry
	forward []*SkipListNode
}

type SkipList struct {
	header *SkipListNode
	level  int
	rng    *fastRand
}

// Fast random number generator to avoid mutex contention
type fastRand struct {
	state uint64
}

func newFastRand() *fastRand {
	var seed [8]byte
	rand.Read(seed[:])
	return &fastRand{state: binary.LittleEndian.Uint64(seed[:])}
}

func (r *fastRand) Uint32() uint32 {
	r.state = r.state*1103515245 + 12345
	return uint32(r.state >> 32)
}

func NewSkipList() *SkipList {
	header := &SkipListNode{
		forward: make([]*SkipListNode, MaxLevel),
	}
	return &SkipList{
		header: header,
		level:  0,
		rng:    newFastRand(),
	}
}

func (sl *SkipList) randomLevel() int {
	level := 0
	for sl.rng.Uint32()&0x3 == 0 && level < MaxLevel-1 {
		level++
	}
	return level
}

func compareKeys(a, b []byte) int {
	return compareKeysFast(a, b)
}

func (sl *SkipList) Put(key []byte, entry *Entry) {
	update := make([]*SkipListNode, MaxLevel)
	current := sl.header

	// Find insertion point
	for i := sl.level; i >= 0; i-- {
		for current.forward[i] != nil && compareKeys(current.forward[i].entry.Key, key) < 0 {
			current = current.forward[i]
		}
		update[i] = current
	}

	current = current.forward[0]

	// Update existing node
	if current != nil && compareKeys(current.entry.Key, key) == 0 {
		current.entry = entry
		return
	}

	// Insert new node
	newLevel := sl.randomLevel()
	if newLevel > sl.level {
		for i := sl.level + 1; i <= newLevel; i++ {
			update[i] = sl.header
		}
		sl.level = newLevel
	}

	newNode := &SkipListNode{
		entry:   entry,
		forward: make([]*SkipListNode, newLevel+1),
	}

	for i := 0; i <= newLevel; i++ {
		newNode.forward[i] = update[i].forward[i]
		update[i].forward[i] = newNode
	}
}

func (sl *SkipList) Get(key []byte) *Entry {
	current := sl.header

	for i := sl.level; i >= 0; i-- {
		for current.forward[i] != nil && compareKeys(current.forward[i].entry.Key, key) < 0 {
			current = current.forward[i]
		}
	}

	current = current.forward[0]
	if current != nil && compareKeys(current.entry.Key, key) == 0 {
		return current.entry
	}

	return nil
}
