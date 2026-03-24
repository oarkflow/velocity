package velocity

import (
	"math/rand"
	"sort"
	"sync/atomic"
)

// LoadBalanceStrategy defines the algorithm used to select nodes.
type LoadBalanceStrategy int

const (
	// StrategyConsistentHash routes based on the cluster's consistent hash ring.
	StrategyConsistentHash LoadBalanceStrategy = iota
	// StrategyRoundRobin cycles through healthy nodes in order.
	StrategyRoundRobin
	// StrategyLeastLoad picks the node with the lowest load metric.
	StrategyLeastLoad
	// StrategyRandom picks a healthy node at random.
	StrategyRandom
)

// LoadBalancer selects cluster nodes for read and write operations.
type LoadBalancer struct {
	cluster  *ClusterManager
	strategy LoadBalanceStrategy
	rrCount  atomic.Uint64 // round-robin counter
}

// NewLoadBalancer creates a LoadBalancer with the given strategy.
func NewLoadBalancer(cluster *ClusterManager, strategy LoadBalanceStrategy) *LoadBalancer {
	return &LoadBalancer{
		cluster:  cluster,
		strategy: strategy,
	}
}

// GetNode returns a single node selected by the configured strategy.
// The key is used by strategies that need deterministic routing (consistent hash).
// Returns nil when no healthy node is available.
func (lb *LoadBalancer) GetNode(key string) *ClusterNode {
	switch lb.strategy {
	case StrategyConsistentHash:
		return lb.getConsistentHashNode(key)
	case StrategyRoundRobin:
		return lb.getRoundRobinNode()
	case StrategyLeastLoad:
		return lb.getLeastLoadNode()
	case StrategyRandom:
		return lb.getRandomNode()
	default:
		return lb.getConsistentHashNode(key)
	}
}

// GetReadNodes returns up to count nodes suitable for a read quorum.
// For consistent hash the primary owner is first, followed by its ring
// successors. For other strategies, nodes are selected by strategy order
// and then filled with additional healthy nodes.
func (lb *LoadBalancer) GetReadNodes(key string, count int) []*ClusterNode {
	return lb.getNodes(key, count)
}

// GetWriteNodes returns up to count nodes suitable for a write quorum.
// Behaviour is identical to GetReadNodes; the distinction exists so callers
// can evolve read/write placement independently.
func (lb *LoadBalancer) GetWriteNodes(key string, count int) []*ClusterNode {
	return lb.getNodes(key, count)
}

// HealthFilter returns only the nodes that are in NodeStateActive.
func HealthFilter(nodes []*ClusterNode) []*ClusterNode {
	healthy := make([]*ClusterNode, 0, len(nodes))
	for _, n := range nodes {
		if n.State == NodeStateActive {
			healthy = append(healthy, n)
		}
	}
	return healthy
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// healthyNodes returns all active cluster nodes.
func (lb *LoadBalancer) healthyNodes() []*ClusterNode {
	return HealthFilter(lb.cluster.GetNodes())
}

// getConsistentHashNode delegates to the cluster's hash ring and validates
// that the selected node is healthy.
func (lb *LoadBalancer) getConsistentHashNode(key string) *ClusterNode {
	node := lb.cluster.GetNodeForKey(key)
	if node != nil && node.State == NodeStateActive {
		return node
	}
	// Fallback: if the primary is unhealthy, scan healthy nodes.
	nodes := lb.healthyNodes()
	if len(nodes) == 0 {
		return nil
	}
	return nodes[0]
}

// getRoundRobinNode cycles through healthy nodes using an atomic counter.
func (lb *LoadBalancer) getRoundRobinNode() *ClusterNode {
	nodes := lb.healthyNodes()
	if len(nodes) == 0 {
		return nil
	}
	// Stable ordering so the same counter value always hits the same node.
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})
	idx := lb.rrCount.Add(1) - 1
	return nodes[idx%uint64(len(nodes))]
}

// getLeastLoadNode returns the healthy node with the lowest load.
// Load is measured as DiskUsed/DiskTotal ratio; when disk info is absent,
// ObjectCount is used as a fallback.
func (lb *LoadBalancer) getLeastLoadNode() *ClusterNode {
	nodes := lb.healthyNodes()
	if len(nodes) == 0 {
		return nil
	}

	best := nodes[0]
	bestScore := nodeLoadScore(best)

	for _, n := range nodes[1:] {
		score := nodeLoadScore(n)
		if score < bestScore {
			bestScore = score
			best = n
		}
	}
	return best
}

// nodeLoadScore produces a comparable score for a node's current load.
// Lower is better. Returns the disk usage ratio (0.0 - 1.0) when disk
// info is available, otherwise falls back to ObjectCount.
func nodeLoadScore(n *ClusterNode) float64 {
	if n.DiskTotal > 0 {
		return float64(n.DiskUsed) / float64(n.DiskTotal)
	}
	return float64(n.ObjectCount)
}

// getRandomNode picks a random healthy node.
func (lb *LoadBalancer) getRandomNode() *ClusterNode {
	nodes := lb.healthyNodes()
	if len(nodes) == 0 {
		return nil
	}
	return nodes[rand.Intn(len(nodes))]
}

// getNodes selects up to count unique healthy nodes using the configured
// strategy. The first node is chosen by the strategy; the remainder are
// filled from the hash ring successors (for consistent hash) or from the
// remaining healthy pool (for other strategies).
func (lb *LoadBalancer) getNodes(key string, count int) []*ClusterNode {
	healthy := lb.healthyNodes()
	if len(healthy) == 0 {
		return nil
	}
	if count > len(healthy) {
		count = len(healthy)
	}
	if count <= 0 {
		return nil
	}

	switch lb.strategy {
	case StrategyConsistentHash:
		return lb.getConsistentHashNodes(key, count, healthy)
	case StrategyRoundRobin:
		return lb.getRoundRobinNodes(count, healthy)
	case StrategyLeastLoad:
		return lb.getLeastLoadNodes(count, healthy)
	case StrategyRandom:
		return lb.getRandomNodes(count, healthy)
	default:
		return lb.getConsistentHashNodes(key, count, healthy)
	}
}

// getConsistentHashNodes returns count nodes starting from the ring owner.
func (lb *LoadBalancer) getConsistentHashNodes(key string, count int, healthy []*ClusterNode) []*ClusterNode {
	// Build a set of healthy IDs for quick lookup.
	healthySet := make(map[string]*ClusterNode, len(healthy))
	for _, n := range healthy {
		healthySet[n.ID] = n
	}

	// Ask the ring for ordered candidate IDs.
	ringIDs := lb.cluster.ring.GetNodes(key, len(healthy))

	result := make([]*ClusterNode, 0, count)
	for _, id := range ringIDs {
		if n, ok := healthySet[id]; ok {
			result = append(result, n)
			if len(result) == count {
				return result
			}
		}
	}

	// Fallback: fill from healthy nodes not yet included.
	seen := make(map[string]bool, len(result))
	for _, n := range result {
		seen[n.ID] = true
	}
	for _, n := range healthy {
		if !seen[n.ID] {
			result = append(result, n)
			if len(result) == count {
				break
			}
		}
	}
	return result
}

// getRoundRobinNodes returns count nodes starting from the current RR position.
func (lb *LoadBalancer) getRoundRobinNodes(count int, healthy []*ClusterNode) []*ClusterNode {
	sort.Slice(healthy, func(i, j int) bool {
		return healthy[i].ID < healthy[j].ID
	})

	start := lb.rrCount.Add(1) - 1
	result := make([]*ClusterNode, 0, count)
	n := uint64(len(healthy))
	for i := uint64(0); i < uint64(count); i++ {
		result = append(result, healthy[(start+i)%n])
	}
	return result
}

// getLeastLoadNodes returns the count nodes with the lowest load scores.
func (lb *LoadBalancer) getLeastLoadNodes(count int, healthy []*ClusterNode) []*ClusterNode {
	sorted := make([]*ClusterNode, len(healthy))
	copy(sorted, healthy)
	sort.Slice(sorted, func(i, j int) bool {
		return nodeLoadScore(sorted[i]) < nodeLoadScore(sorted[j])
	})
	return sorted[:count]
}

// getRandomNodes returns count randomly-chosen healthy nodes without repeats.
func (lb *LoadBalancer) getRandomNodes(count int, healthy []*ClusterNode) []*ClusterNode {
	perm := rand.Perm(len(healthy))
	result := make([]*ClusterNode, 0, count)
	for i := 0; i < count; i++ {
		result = append(result, healthy[perm[i]])
	}
	return result
}
