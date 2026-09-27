package replication

import (
	"hash/crc32"
	"sort"
	"strconv"
	"sync"
)

// hashRing is a consistent-hash ring with virtual nodes, ported from v1's
// pkg/core/consistent_hash.go (ConsistentHashRing). Used by Membership to
// answer NodeForKey without requiring every node to store every key.
type hashRing struct {
	mu           sync.RWMutex
	ring         []uint32
	nodeMap      map[uint32]string
	nodes        map[string]bool
	virtualNodes int
}

func newHashRing(virtualNodes int) *hashRing {
	if virtualNodes <= 0 {
		virtualNodes = 256
	}
	return &hashRing{
		ring:         make([]uint32, 0),
		nodeMap:      make(map[uint32]string),
		nodes:        make(map[string]bool),
		virtualNodes: virtualNodes,
	}
}

func (r *hashRing) AddNode(nodeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.nodes[nodeID] {
		return
	}
	r.nodes[nodeID] = true
	for i := 0; i < r.virtualNodes; i++ {
		hash := r.hashKey(nodeID + "#" + strconv.Itoa(i))
		r.ring = append(r.ring, hash)
		r.nodeMap[hash] = nodeID
	}
	sort.Slice(r.ring, func(i, j int) bool { return r.ring[i] < r.ring[j] })
}

func (r *hashRing) RemoveNode(nodeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.nodes[nodeID] {
		return
	}
	delete(r.nodes, nodeID)
	newRing := make([]uint32, 0, len(r.ring))
	for _, hash := range r.ring {
		if r.nodeMap[hash] != nodeID {
			newRing = append(newRing, hash)
		} else {
			delete(r.nodeMap, hash)
		}
	}
	r.ring = newRing
}

func (r *hashRing) GetNode(key string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.ring) == 0 {
		return ""
	}
	hash := r.hashKey(key)
	idx := sort.Search(len(r.ring), func(i int) bool { return r.ring[i] >= hash })
	if idx >= len(r.ring) {
		idx = 0
	}
	return r.nodeMap[r.ring[idx]]
}

func (r *hashRing) NodeCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.nodes)
}

func (r *hashRing) hashKey(key string) uint32 {
	return crc32.ChecksumIEEE([]byte(key))
}
