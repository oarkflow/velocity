package velocity

import (
	"hash/crc32"
	"sort"
	"strconv"
	"sync"
)

// ConsistentHashRing implements consistent hashing for distributed key routing
type ConsistentHashRing struct {
	ring         []uint32
	nodeMap      map[uint32]string
	nodes        map[string]bool
	virtualNodes int
	mu           sync.RWMutex
}

// NewConsistentHashRing creates a new consistent hash ring
func NewConsistentHashRing(virtualNodes int) *ConsistentHashRing {
	if virtualNodes <= 0 {
		virtualNodes = 256
	}
	return &ConsistentHashRing{
		ring:         make([]uint32, 0),
		nodeMap:      make(map[uint32]string),
		nodes:        make(map[string]bool),
		virtualNodes: virtualNodes,
	}
}

// AddNode adds a node with virtual nodes to the ring
func (chr *ConsistentHashRing) AddNode(nodeID string) {
	chr.mu.Lock()
	defer chr.mu.Unlock()

	if chr.nodes[nodeID] {
		return
	}

	chr.nodes[nodeID] = true

	for i := 0; i < chr.virtualNodes; i++ {
		hash := chr.hashKey(nodeID + "#" + strconv.Itoa(i))
		chr.ring = append(chr.ring, hash)
		chr.nodeMap[hash] = nodeID
	}

	sort.Slice(chr.ring, func(i, j int) bool {
		return chr.ring[i] < chr.ring[j]
	})
}

// RemoveNode removes a node from the ring
func (chr *ConsistentHashRing) RemoveNode(nodeID string) {
	chr.mu.Lock()
	defer chr.mu.Unlock()

	if !chr.nodes[nodeID] {
		return
	}

	delete(chr.nodes, nodeID)

	// Remove all virtual nodes
	newRing := make([]uint32, 0, len(chr.ring)-chr.virtualNodes)
	for _, hash := range chr.ring {
		if chr.nodeMap[hash] != nodeID {
			newRing = append(newRing, hash)
		} else {
			delete(chr.nodeMap, hash)
		}
	}

	chr.ring = newRing
}

// GetNode returns the node responsible for a key
func (chr *ConsistentHashRing) GetNode(key string) string {
	chr.mu.RLock()
	defer chr.mu.RUnlock()

	if len(chr.ring) == 0 {
		return ""
	}

	hash := chr.hashKey(key)

	// Binary search for the first ring position >= hash
	idx := sort.Search(len(chr.ring), func(i int) bool {
		return chr.ring[i] >= hash
	})

	// Wrap around
	if idx >= len(chr.ring) {
		idx = 0
	}

	return chr.nodeMap[chr.ring[idx]]
}

// GetNodes returns N distinct nodes for replication
func (chr *ConsistentHashRing) GetNodes(key string, count int) []string {
	chr.mu.RLock()
	defer chr.mu.RUnlock()

	if len(chr.ring) == 0 {
		return nil
	}

	uniqueNodes := len(chr.nodes)
	if count > uniqueNodes {
		count = uniqueNodes
	}

	hash := chr.hashKey(key)
	idx := sort.Search(len(chr.ring), func(i int) bool {
		return chr.ring[i] >= hash
	})

	if idx >= len(chr.ring) {
		idx = 0
	}

	seen := make(map[string]bool)
	result := make([]string, 0, count)

	for len(result) < count {
		nodeID := chr.nodeMap[chr.ring[idx]]
		if !seen[nodeID] {
			seen[nodeID] = true
			result = append(result, nodeID)
		}

		idx++
		if idx >= len(chr.ring) {
			idx = 0
		}

		// Safety: break if we've gone all the way around
		if len(seen) >= uniqueNodes {
			break
		}
	}

	return result
}

// GetRebalanceMap returns keys that need to move when adding a new node
func (chr *ConsistentHashRing) GetRebalanceMap(newNodeID string) map[string][]string {
	// Returns a map of sourceNodeID -> list of key ranges that should move to newNodeID
	// This is used during node addition to plan data migration
	rebalance := make(map[string][]string)

	chr.mu.RLock()
	defer chr.mu.RUnlock()

	if chr.nodes[newNodeID] {
		return rebalance
	}

	// Simulate adding the node and find which ranges would move
	for i := 0; i < chr.virtualNodes; i++ {
		hash := chr.hashKey(newNodeID + "#" + strconv.Itoa(i))

		// Find the current owner of this hash position
		idx := sort.Search(len(chr.ring), func(j int) bool {
			return chr.ring[j] >= hash
		})

		if idx >= len(chr.ring) {
			idx = 0
		}

		if idx < len(chr.ring) {
			currentOwner := chr.nodeMap[chr.ring[idx]]
			if currentOwner != newNodeID {
				rebalance[currentOwner] = append(rebalance[currentOwner], strconv.FormatUint(uint64(hash), 16))
			}
		}
	}

	return rebalance
}

// NodeCount returns the number of nodes in the ring
func (chr *ConsistentHashRing) NodeCount() int {
	chr.mu.RLock()
	defer chr.mu.RUnlock()
	return len(chr.nodes)
}

// HasNode checks if a node is in the ring
func (chr *ConsistentHashRing) HasNode(nodeID string) bool {
	chr.mu.RLock()
	defer chr.mu.RUnlock()
	return chr.nodes[nodeID]
}

// ListNodes returns all node IDs in the ring
func (chr *ConsistentHashRing) ListNodes() []string {
	chr.mu.RLock()
	defer chr.mu.RUnlock()

	nodes := make([]string, 0, len(chr.nodes))
	for id := range chr.nodes {
		nodes = append(nodes, id)
	}
	sort.Strings(nodes)
	return nodes
}

func (chr *ConsistentHashRing) hashKey(key string) uint32 {
	return crc32.ChecksumIEEE([]byte(key))
}
