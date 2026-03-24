package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// NodeState represents the state of a cluster node
type NodeState int

const (
	NodeStateJoining NodeState = iota
	NodeStateActive
	NodeStateLeaving
	NodeStateDown
)

// ClusterNode represents a node in the cluster
type ClusterNode struct {
	ID          string    `json:"id"`
	Address     string    `json:"address"`
	APIAddress  string    `json:"api_address"`
	State       NodeState `json:"state"`
	Zone        string    `json:"zone"`
	DataDir     string    `json:"data_dir"`
	JoinedAt    time.Time `json:"joined_at"`
	LastSeen    time.Time `json:"last_seen"`
	DiskUsed    int64     `json:"disk_used"`
	DiskTotal   int64     `json:"disk_total"`
	ObjectCount int64     `json:"object_count"`
}

// ClusterConfig holds cluster configuration
type ClusterConfig struct {
	NodeID            string
	BindAddress       string
	APIAddress        string
	PeerAddresses     []string
	Zone              string
	DataDir           string
	HeartbeatInterval time.Duration
	FailureTimeout    time.Duration
}

// ClusterManager manages cluster membership and routing
type ClusterManager struct {
	config    ClusterConfig
	localNode *ClusterNode
	nodes     map[string]*ClusterNode
	ring      *ConsistentHashRing
	transport *NodeTransport
	mu        sync.RWMutex
	db        *DB
	running   atomic.Bool
	stopCh    chan struct{}
}

// NewClusterManager creates a new cluster manager
func NewClusterManager(db *DB, config ClusterConfig) *ClusterManager {
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 5 * time.Second
	}
	if config.FailureTimeout == 0 {
		config.FailureTimeout = 30 * time.Second
	}

	localNode := &ClusterNode{
		ID:         config.NodeID,
		Address:    config.BindAddress,
		APIAddress: config.APIAddress,
		State:      NodeStateJoining,
		Zone:       config.Zone,
		DataDir:    config.DataDir,
		JoinedAt:   time.Now().UTC(),
		LastSeen:   time.Now().UTC(),
	}

	cm := &ClusterManager{
		config:    config,
		localNode: localNode,
		nodes:     map[string]*ClusterNode{config.NodeID: localNode},
		ring:      NewConsistentHashRing(256),
		db:        db,
		stopCh:    make(chan struct{}),
	}

	cm.ring.AddNode(config.NodeID)

	return cm
}

// Start begins cluster operations
func (cm *ClusterManager) Start(ctx context.Context) error {
	if !cm.running.CompareAndSwap(false, true) {
		return fmt.Errorf("cluster already running")
	}

	// Start transport
	transport := NewNodeTransport(cm.config.NodeID, cm.config.BindAddress)
	cm.transport = transport

	// Register handlers (wrap to match MessageHandler signature)
	cm.transport.RegisterHandler(MsgHeartbeat, func(msg *WireMessage) *WireMessage {
		resp, _ := cm.handleHeartbeat(msg)
		return resp
	})
	cm.transport.RegisterHandler(MsgJoinRequest, func(msg *WireMessage) *WireMessage {
		resp, _ := cm.handleJoinRequest(msg)
		return resp
	})
	cm.transport.RegisterHandler(MsgNodeList, func(msg *WireMessage) *WireMessage {
		resp, _ := cm.handleNodeList(msg)
		return resp
	})

	if err := cm.transport.Start(); err != nil {
		cm.running.Store(false)
		return err
	}

	cm.localNode.State = NodeStateActive

	// Join existing peers
	for _, peer := range cm.config.PeerAddresses {
		go cm.JoinCluster(peer)
	}

	// Start heartbeat loop
	go cm.heartbeatLoop(ctx)

	// Start failure detection
	go cm.failureDetection(ctx)

	return nil
}

// Stop stops the cluster manager
func (cm *ClusterManager) Stop() error {
	if !cm.running.Load() {
		return nil
	}
	close(cm.stopCh)
	cm.running.Store(false)

	if cm.transport != nil {
		cm.transport.Stop()
	}

	return nil
}

// JoinCluster joins an existing cluster via a peer address
func (cm *ClusterManager) JoinCluster(peerAddress string) error {
	if cm.transport == nil {
		return fmt.Errorf("transport not started")
	}

	payload, _ := json.Marshal(cm.localNode)
	msg := &WireMessage{
		Type:      MsgJoinRequest,
		NodeID:    cm.config.NodeID,
		Timestamp: time.Now().UnixNano(),
		Payload:   payload,
	}

	resp, err := cm.transport.Send(peerAddress, msg)
	if err != nil {
		return fmt.Errorf("failed to join via %s: %w", peerAddress, err)
	}

	if resp != nil && resp.Type == MsgNodeList {
		var nodes []*ClusterNode
		if err := json.Unmarshal(resp.Payload, &nodes); err == nil {
			cm.mergeNodes(nodes)
		}
	}

	return nil
}

// LeaveCluster gracefully leaves the cluster
func (cm *ClusterManager) LeaveCluster() error {
	cm.localNode.State = NodeStateLeaving

	payload, _ := json.Marshal(cm.localNode)
	msg := &WireMessage{
		Type:      MsgLeaveNotify,
		NodeID:    cm.config.NodeID,
		Timestamp: time.Now().UnixNano(),
		Payload:   payload,
	}

	cm.mu.RLock()
	peers := make([]*ClusterNode, 0)
	for _, node := range cm.nodes {
		if node.ID != cm.config.NodeID && node.State == NodeStateActive {
			peers = append(peers, node)
		}
	}
	cm.mu.RUnlock()

	for _, peer := range peers {
		cm.transport.SendAsync(peer.Address, msg)
	}

	return cm.Stop()
}

// GetNodes returns all known cluster nodes
func (cm *ClusterManager) GetNodes() []*ClusterNode {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	nodes := make([]*ClusterNode, 0, len(cm.nodes))
	for _, node := range cm.nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// GetNodeForKey returns the node responsible for a given key
func (cm *ClusterManager) GetNodeForKey(key string) *ClusterNode {
	nodeID := cm.ring.GetNode(key)

	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return cm.nodes[nodeID]
}

// IsLocalKey checks if this node is responsible for the given key
func (cm *ClusterManager) IsLocalKey(key string) bool {
	nodeID := cm.ring.GetNode(key)
	return nodeID == cm.config.NodeID
}

// GetLocalNode returns the local node info
func (cm *ClusterManager) GetLocalNode() *ClusterNode {
	return cm.localNode
}

func (cm *ClusterManager) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(cm.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cm.stopCh:
			return
		case <-ticker.C:
			cm.sendHeartbeats()
		}
	}
}

func (cm *ClusterManager) sendHeartbeats() {
	cm.localNode.LastSeen = time.Now().UTC()

	payload, _ := json.Marshal(cm.localNode)
	msg := &WireMessage{
		Type:      MsgHeartbeat,
		NodeID:    cm.config.NodeID,
		Timestamp: time.Now().UnixNano(),
		Payload:   payload,
	}

	cm.mu.RLock()
	peers := make([]string, 0)
	for _, node := range cm.nodes {
		if node.ID != cm.config.NodeID && node.State == NodeStateActive {
			peers = append(peers, node.Address)
		}
	}
	cm.mu.RUnlock()

	for _, addr := range peers {
		go cm.transport.SendAsync(addr, msg)
	}
}

func (cm *ClusterManager) failureDetection(ctx context.Context) {
	ticker := time.NewTicker(cm.config.HeartbeatInterval * 2)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cm.stopCh:
			return
		case <-ticker.C:
			cm.checkNodeHealth()
		}
	}
}

func (cm *ClusterManager) checkNodeHealth() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	now := time.Now()
	for id, node := range cm.nodes {
		if id == cm.config.NodeID {
			continue
		}
		if node.State == NodeStateActive && now.Sub(node.LastSeen) > cm.config.FailureTimeout {
			node.State = NodeStateDown
			cm.ring.RemoveNode(id)
		}
	}
}

func (cm *ClusterManager) handleHeartbeat(msg *WireMessage) (*WireMessage, error) {
	var node ClusterNode
	if err := json.Unmarshal(msg.Payload, &node); err != nil {
		return nil, err
	}

	cm.mu.Lock()
	existing, ok := cm.nodes[node.ID]
	if ok {
		existing.LastSeen = time.Now().UTC()
		existing.DiskUsed = node.DiskUsed
		existing.DiskTotal = node.DiskTotal
		existing.ObjectCount = node.ObjectCount
		if existing.State == NodeStateDown {
			existing.State = NodeStateActive
			cm.ring.AddNode(node.ID)
		}
	} else {
		node.LastSeen = time.Now().UTC()
		cm.nodes[node.ID] = &node
		cm.ring.AddNode(node.ID)
	}
	cm.mu.Unlock()

	return nil, nil
}

func (cm *ClusterManager) handleJoinRequest(msg *WireMessage) (*WireMessage, error) {
	var newNode ClusterNode
	if err := json.Unmarshal(msg.Payload, &newNode); err != nil {
		return nil, err
	}

	newNode.State = NodeStateActive
	newNode.LastSeen = time.Now().UTC()

	cm.mu.Lock()
	cm.nodes[newNode.ID] = &newNode
	cm.ring.AddNode(newNode.ID)
	cm.mu.Unlock()

	// Respond with full node list
	nodes := cm.GetNodes()
	payload, _ := json.Marshal(nodes)

	return &WireMessage{
		Type:      MsgNodeList,
		NodeID:    cm.config.NodeID,
		Timestamp: time.Now().UnixNano(),
		Payload:   payload,
	}, nil
}

func (cm *ClusterManager) handleNodeList(msg *WireMessage) (*WireMessage, error) {
	var nodes []*ClusterNode
	if err := json.Unmarshal(msg.Payload, &nodes); err != nil {
		return nil, err
	}

	cm.mergeNodes(nodes)
	return nil, nil
}

func (cm *ClusterManager) mergeNodes(nodes []*ClusterNode) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for _, node := range nodes {
		if node.ID == cm.config.NodeID {
			continue
		}

		existing, ok := cm.nodes[node.ID]
		if !ok {
			cm.nodes[node.ID] = node
			if node.State == NodeStateActive {
				cm.ring.AddNode(node.ID)
			}
		} else if node.LastSeen.After(existing.LastSeen) {
			existing.LastSeen = node.LastSeen
			existing.State = node.State
			existing.DiskUsed = node.DiskUsed
			existing.DiskTotal = node.DiskTotal
		}
	}
}

// HashKey computes a consistent hash for a key
func HashKey(key string) uint32 {
	return crc32.ChecksumIEEE([]byte(key))
}

// GetNodeAddress returns the address for a node ID
func (cm *ClusterManager) GetNodeAddress(nodeID string) (string, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	node, ok := cm.nodes[nodeID]
	if !ok {
		return "", fmt.Errorf("node %s not found", nodeID)
	}

	return node.Address, nil
}

// IsHealthy checks if the local node is healthy
func (cm *ClusterManager) IsHealthy() bool {
	return cm.running.Load() && cm.localNode.State == NodeStateActive
}

// NodeCount returns the number of active nodes
func (cm *ClusterManager) NodeCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	count := 0
	for _, node := range cm.nodes {
		if node.State == NodeStateActive {
			count++
		}
	}
	return count
}

// UpdateLocalStats updates the local node's stats
func (cm *ClusterManager) UpdateLocalStats(diskUsed, diskTotal, objectCount int64) {
	cm.localNode.DiskUsed = diskUsed
	cm.localNode.DiskTotal = diskTotal
	cm.localNode.ObjectCount = objectCount
}

// Resolve a net.Addr (used internally)
func resolveAddr(address string) (*net.TCPAddr, error) {
	return net.ResolveTCPAddr("tcp", address)
}
