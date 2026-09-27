package replication

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// controlMsg is Membership's own small message envelope carried as the
// opaque payload over Transport/api.ReplicationTransport. Transport itself
// knows nothing about join/heartbeat/leave semantics — those live here.
type controlMsg struct {
	Type  string         `json:"type"` // "join", "nodelist", "heartbeat", "leave"
	Node  api.NodeInfo   `json:"node"`
	Nodes []api.NodeInfo `json:"nodes,omitempty"`
}

// Membership is the concrete api.ClusterMembership implementation, ported
// from v1's cluster.go node state machine (joining/active/leaving/down)
// plus gossip-style nodelist propagation, layered over Transport and a
// consistent-hash ring for NodeForKey.
type Membership struct {
	self api.NodeInfo

	transport *Transport
	ring      *hashRing
	bus       api.EventBus // may be nil (e.g. in unit tests without a kernel)

	heartbeatInterval time.Duration
	failAfter         time.Duration

	mu       sync.RWMutex
	members  map[string]api.NodeInfo
	lastSeen map[string]time.Time

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewMembership constructs a Membership for the given self node, sending
// and receiving control messages over t. Call SetEventBus before Start if
// TopicClusterJoin/TopicClusterLeave events should be published.
func NewMembership(self api.NodeInfo, t *Transport, heartbeatInterval, failAfter time.Duration) *Membership {
	if heartbeatInterval <= 0 {
		heartbeatInterval = 2 * time.Second
	}
	if failAfter <= 0 {
		failAfter = 10 * time.Second
	}
	m := &Membership{
		self:              self,
		transport:         t,
		ring:              newHashRing(0),
		heartbeatInterval: heartbeatInterval,
		failAfter:         failAfter,
		members:           make(map[string]api.NodeInfo),
		lastSeen:          make(map[string]time.Time),
		stopCh:            make(chan struct{}),
	}
	m.addMemberLocked(self)
	return m
}

// sendControl wraps msg in a frameEnvelope and sends it to target. All
// outbound Membership traffic goes through this so every peer sees the
// same envelope shape regardless of message type.
func (m *Membership) sendControl(ctx context.Context, target api.NodeInfo, msg controlMsg) error {
	data, err := json.Marshal(frameEnvelope{Kind: "control", Control: &msg})
	if err != nil {
		return err
	}
	return m.transport.Send(ctx, target, data)
}

func (m *Membership) SetEventBus(bus api.EventBus) { m.bus = bus }

func (m *Membership) addMemberLocked(n api.NodeInfo) {
	n.State = "active"
	m.members[n.ID] = n
	m.lastSeen[n.ID] = time.Now()
	m.ring.AddNode(n.ID)
}

func (m *Membership) removeMember(id string) {
	m.mu.Lock()
	_, existed := m.members[id]
	delete(m.members, id)
	delete(m.lastSeen, id)
	m.ring.RemoveNode(id)
	m.mu.Unlock()

	if existed && m.bus != nil {
		m.bus.Publish(context.Background(), api.Event{
			Topic:   api.TopicClusterLeave,
			Source:  "replication",
			Payload: api.NodeInfo{ID: id},
		})
	}
}

// HandleControl processes one already-decoded controlMsg received from
// from. Called by Plugin's central dispatcher (see plugin.go) after it
// decodes the frameEnvelope and routes Kind=="control" frames here.
func (m *Membership) HandleControl(from api.NodeInfo, msg controlMsg) {
	switch msg.Type {
	case "join":
		joiner := msg.Node
		if joiner.Address == "" {
			joiner.Address = from.Address
		}
		isNew := m.mergeMember(joiner)
		if isNew && m.bus != nil {
			m.bus.Publish(context.Background(), api.Event{Topic: api.TopicClusterJoin, Source: "replication", Payload: joiner})
		}
		// Reply with the full known member list so the joiner converges
		// quickly, and gossip the new member to everyone else we know.
		_ = m.sendControl(context.Background(), joiner, controlMsg{Type: "nodelist", Node: m.self, Nodes: m.Members()})
		m.gossipTo(joiner, controlMsg{Type: "nodelist", Node: m.self, Nodes: []api.NodeInfo{joiner}})

	case "nodelist":
		for _, n := range msg.Nodes {
			isNew := m.mergeMember(n)
			if isNew && m.bus != nil {
				m.bus.Publish(context.Background(), api.Event{Topic: api.TopicClusterJoin, Source: "replication", Payload: n})
			}
		}

	case "heartbeat":
		hb := msg.Node
		if hb.Address == "" {
			hb.Address = from.Address
		}
		m.mergeMember(hb)
		m.mu.Lock()
		m.lastSeen[hb.ID] = time.Now()
		m.mu.Unlock()

	case "leave":
		m.removeMember(msg.Node.ID)
	}
}

// mergeMember adds or refreshes a member entry. Returns true if the
// member was not previously known.
func (m *Membership) mergeMember(n api.NodeInfo) bool {
	if n.ID == "" || n.ID == m.self.ID {
		return false
	}
	m.mu.Lock()
	_, existed := m.members[n.ID]
	m.addMemberLocked(n)
	m.mu.Unlock()
	return !existed
}

func (m *Membership) gossipTo(exclude api.NodeInfo, msg controlMsg) {
	for _, n := range m.Members() {
		if n.ID == m.self.ID || n.ID == exclude.ID {
			continue
		}
		_ = m.sendControl(context.Background(), n, msg)
	}
}

// Join implements api.ClusterMembership. An empty seed means "bootstrap as
// the sole member" (Membership already contains self from construction).
// A non-empty seed sends an asynchronous join request; membership
// converges via gossip rather than synchronously, matching the
// eventually-consistent scope documented in doc.go.
func (m *Membership) Join(ctx context.Context, seed string) error {
	if seed == "" {
		return nil
	}
	return m.sendControl(ctx, api.NodeInfo{Address: seed}, controlMsg{Type: "join", Node: m.self})
}

// Leave implements api.ClusterMembership: announces departure to every
// known peer, then removes self locally.
func (m *Membership) Leave(ctx context.Context) error {
	msg := controlMsg{Type: "leave", Node: m.self}
	for _, n := range m.Members() {
		if n.ID == m.self.ID {
			continue
		}
		_ = m.sendControl(ctx, n, msg)
	}
	m.removeMember(m.self.ID)
	return nil
}

// Members implements api.ClusterMembership.
func (m *Membership) Members() []api.NodeInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]api.NodeInfo, 0, len(m.members))
	for _, n := range m.members {
		out = append(out, n)
	}
	return out
}

// NodeForKey implements api.ClusterMembership using the consistent-hash
// ring. Returns a zero-value NodeInfo if no node owns the ring yet.
func (m *Membership) NodeForKey(key []byte) api.NodeInfo {
	id := m.ring.GetNode(string(key))
	if id == "" {
		return api.NodeInfo{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.members[id]
}

// Start begins the heartbeat/failure-detection loop.
func (m *Membership) Start() {
	m.wg.Add(1)
	go m.heartbeatLoop()
}

// Stop halts the heartbeat loop.
func (m *Membership) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}

func (m *Membership) heartbeatLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.sendHeartbeats()
			m.reapDead()
		}
	}
}

func (m *Membership) sendHeartbeats() {
	msg := controlMsg{Type: "heartbeat", Node: m.self}
	for _, n := range m.Members() {
		if n.ID == m.self.ID {
			continue
		}
		_ = m.sendControl(context.Background(), n, msg)
	}
}

func (m *Membership) reapDead() {
	now := time.Now()
	var dead []string
	m.mu.RLock()
	for id, seen := range m.lastSeen {
		if id == m.self.ID {
			continue
		}
		if now.Sub(seen) > m.failAfter {
			dead = append(dead, id)
		}
	}
	m.mu.RUnlock()
	for _, id := range dead {
		m.removeMember(id)
	}
}

var _ api.ClusterMembership = (*Membership)(nil)
