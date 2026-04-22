package velocity

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MessageType identifies the type of inter-node message.
type MessageType uint8

const (
	MsgHeartbeat    MessageType = 1
	MsgJoinRequest  MessageType = 2
	MsgJoinResponse MessageType = 3
	MsgLeaveNotify  MessageType = 4
	MsgReplicateObj MessageType = 5
	MsgReplicateDel MessageType = 6
	MsgReplicateAck MessageType = 7
	MsgNodeList     MessageType = 8
	MsgHealthCheck  MessageType = 9
	MsgDataTransfer MessageType = 10
	MsgDataRequest  MessageType = 11
)

const (
	wireTimeout       = 5 * time.Second
	wireMaxMessageLen = 64 * 1024 * 1024 // 64MB max message size
	wirePoolSize      = 4                // connections per peer
)

// WireMessage is the envelope for all inter-node communication.
type WireMessage struct {
	Type      MessageType     `json:"type"`
	NodeID    string          `json:"node_id"`
	Timestamp int64           `json:"timestamp"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

// HeartbeatPayload carries node health information.
type HeartbeatPayload struct {
	Address     string `json:"address"`
	APIAddress  string `json:"api_address"`
	Zone        string `json:"zone"`
	DiskUsed    uint64 `json:"disk_used"`
	DiskTotal   uint64 `json:"disk_total"`
	ObjectCount int64  `json:"object_count"`
	State       string `json:"state"`
}

// JoinRequestPayload is sent when a node wants to join the cluster.
type JoinRequestPayload struct {
	NodeID     string `json:"node_id"`
	Address    string `json:"address"`
	APIAddress string `json:"api_address"`
	Zone       string `json:"zone"`
}

// JoinResponsePayload is the reply to a join request.
type JoinResponsePayload struct {
	Accepted bool          `json:"accepted"`
	Reason   string        `json:"reason,omitempty"`
	Nodes    []ClusterNode `json:"nodes,omitempty"`
}

// ReplicateObjPayload carries an object for replication.
type ReplicateObjPayload struct {
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
	Data   []byte `json:"data"`
	Meta   []byte `json:"meta"`
}

// ReplicateDelPayload requests deletion replication.
type ReplicateDelPayload struct {
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
}

// ReplicateAckPayload acknowledges a replication operation.
type ReplicateAckPayload struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Key     string `json:"key"`
}

// NodeListPayload carries the current known node list for gossip.
type NodeListPayload struct {
	Nodes []ClusterNode `json:"nodes"`
}

// DataRequestPayload requests data for a specific key.
type DataRequestPayload struct {
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
}

// DataTransferPayload carries data in response to a request.
type DataTransferPayload struct {
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
	Data   []byte `json:"data"`
	Meta   []byte `json:"meta"`
	Found  bool   `json:"found"`
}

// MessageHandler processes an incoming wire message and optionally returns a response.
type MessageHandler func(msg *WireMessage) *WireMessage

// connPool manages a pool of connections to a single peer.
type connPool struct {
	mu      sync.Mutex
	address string
	conns   []net.Conn
	maxSize int
}

func newConnPool(address string, maxSize int) *connPool {
	return &connPool{
		address: address,
		maxSize: maxSize,
		conns:   make([]net.Conn, 0, maxSize),
	}
}

func (p *connPool) get() (net.Conn, error) {
	p.mu.Lock()
	if len(p.conns) > 0 {
		conn := p.conns[len(p.conns)-1]
		p.conns = p.conns[:len(p.conns)-1]
		p.mu.Unlock()
		// Validate the connection is still alive
		if err := conn.SetDeadline(time.Now().Add(100 * time.Millisecond)); err == nil {
			_ = conn.SetDeadline(time.Time{})
			return conn, nil
		}
		conn.Close()
	} else {
		p.mu.Unlock()
	}
	return net.DialTimeout("tcp", p.address, wireTimeout)
}

func (p *connPool) put(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.conns) < p.maxSize {
		p.conns = append(p.conns, conn)
	} else {
		conn.Close()
	}
}

func (p *connPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range p.conns {
		conn.Close()
	}
	p.conns = nil
}

// NodeTransport handles all inter-node TCP communication.
type NodeTransport struct {
	nodeID   string
	bindAddr string
	listener net.Listener

	handlers  map[MessageType]MessageHandler
	handlerMu sync.RWMutex

	pools   map[string]*connPool
	poolsMu sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	messagesSent     atomic.Int64
	messagesReceived atomic.Int64
	bytesOut         atomic.Int64
	bytesIn          atomic.Int64
}

// NewNodeTransport creates a new transport layer for inter-node communication.
func NewNodeTransport(nodeID, bindAddr string) *NodeTransport {
	ctx, cancel := context.WithCancel(context.Background())
	return &NodeTransport{
		nodeID:   nodeID,
		bindAddr: bindAddr,
		handlers: make(map[MessageType]MessageHandler),
		pools:    make(map[string]*connPool),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start begins listening for incoming connections.
func (t *NodeTransport) Start() error {
	ln, err := net.Listen("tcp", t.bindAddr)
	if err != nil {
		return fmt.Errorf("transport: failed to listen on %s: %w", t.bindAddr, err)
	}
	t.listener = ln

	t.wg.Add(1)
	go t.acceptLoop()

	return nil
}

// Stop shuts down the transport layer gracefully.
func (t *NodeTransport) Stop() error {
	t.cancel()

	if t.listener != nil {
		t.listener.Close()
	}

	// Close all connection pools
	t.poolsMu.Lock()
	for _, pool := range t.pools {
		pool.close()
	}
	t.pools = make(map[string]*connPool)
	t.poolsMu.Unlock()

	t.wg.Wait()
	return nil
}

// RegisterHandler registers a handler for a specific message type.
func (t *NodeTransport) RegisterHandler(msgType MessageType, handler MessageHandler) {
	t.handlerMu.Lock()
	t.handlers[msgType] = handler
	t.handlerMu.Unlock()
}

// Send sends a message to the specified address and waits for a response.
func (t *NodeTransport) Send(address string, msg *WireMessage) (*WireMessage, error) {
	msg.NodeID = t.nodeID
	msg.Timestamp = time.Now().UnixNano()

	pool := t.getPool(address)
	conn, err := pool.get()
	if err != nil {
		return nil, fmt.Errorf("transport: connect to %s: %w", address, err)
	}

	if err := conn.SetDeadline(time.Now().Add(wireTimeout)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("transport: set deadline: %w", err)
	}

	if err := writeWireMessage(conn, msg); err != nil {
		conn.Close()
		return nil, fmt.Errorf("transport: write to %s: %w", address, err)
	}
	t.messagesSent.Add(1)

	resp, err := readWireMessage(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("transport: read from %s: %w", address, err)
	}
	t.messagesReceived.Add(1)

	_ = conn.SetDeadline(time.Time{})
	pool.put(conn)

	return resp, nil
}

// SendAsync sends a message without waiting for a response.
func (t *NodeTransport) SendAsync(address string, msg *WireMessage) error {
	msg.NodeID = t.nodeID
	msg.Timestamp = time.Now().UnixNano()

	pool := t.getPool(address)
	conn, err := pool.get()
	if err != nil {
		return fmt.Errorf("transport: connect to %s: %w", address, err)
	}

	if err := conn.SetDeadline(time.Now().Add(wireTimeout)); err != nil {
		conn.Close()
		return fmt.Errorf("transport: set deadline: %w", err)
	}

	if err := writeWireMessage(conn, msg); err != nil {
		conn.Close()
		return fmt.Errorf("transport: write to %s: %w", address, err)
	}
	t.messagesSent.Add(1)

	_ = conn.SetDeadline(time.Time{})
	pool.put(conn)

	return nil
}

func (t *NodeTransport) getPool(address string) *connPool {
	t.poolsMu.RLock()
	pool, ok := t.pools[address]
	t.poolsMu.RUnlock()
	if ok {
		return pool
	}

	t.poolsMu.Lock()
	defer t.poolsMu.Unlock()

	// Double-check after acquiring write lock
	pool, ok = t.pools[address]
	if ok {
		return pool
	}

	pool = newConnPool(address, wirePoolSize)
	t.pools[address] = pool
	return pool
}

func (t *NodeTransport) acceptLoop() {
	defer t.wg.Done()
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			select {
			case <-t.ctx.Done():
				return
			default:
				continue
			}
		}
		t.wg.Add(1)
		go t.handleConnection(conn)
	}
}

func (t *NodeTransport) handleConnection(conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return
		}

		msg, err := readWireMessage(conn)
		if err != nil {
			return
		}
		t.messagesReceived.Add(1)

		t.handlerMu.RLock()
		handler, ok := t.handlers[msg.Type]
		t.handlerMu.RUnlock()

		var resp *WireMessage
		if ok && handler != nil {
			resp = handler(msg)
		}

		if resp == nil {
			resp = &WireMessage{
				Type:      msg.Type,
				NodeID:    t.nodeID,
				Timestamp: time.Now().UnixNano(),
			}
		}

		if err := conn.SetWriteDeadline(time.Now().Add(wireTimeout)); err != nil {
			return
		}

		if err := writeWireMessage(conn, resp); err != nil {
			return
		}
		t.messagesSent.Add(1)
	}
}

// writeWireMessage writes a 4-byte length-prefixed JSON message.
func writeWireMessage(w io.Writer, msg *WireMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal wire message: %w", err)
	}

	if len(data) > wireMaxMessageLen {
		return fmt.Errorf("message too large: %d bytes (max %d)", len(data), wireMaxMessageLen)
	}

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	return nil
}

// readWireMessage reads a 4-byte length-prefixed JSON message.
func readWireMessage(r io.Reader) (*WireMessage, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}

	msgLen := binary.BigEndian.Uint32(lenBuf)
	if msgLen > uint32(wireMaxMessageLen) {
		return nil, fmt.Errorf("message too large: %d bytes (max %d)", msgLen, wireMaxMessageLen)
	}

	data := make([]byte, msgLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}

	var msg WireMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("unmarshal wire message: %w", err)
	}
	return &msg, nil
}

// TransportStats returns transport statistics.
type TransportStats struct {
	MessagesSent     int64 `json:"messages_sent"`
	MessagesReceived int64 `json:"messages_received"`
	BytesOut         int64 `json:"bytes_out"`
	BytesIn          int64 `json:"bytes_in"`
	ActivePools      int   `json:"active_pools"`
}

// Stats returns current transport statistics.
func (t *NodeTransport) Stats() TransportStats {
	t.poolsMu.RLock()
	poolCount := len(t.pools)
	t.poolsMu.RUnlock()

	return TransportStats{
		MessagesSent:     t.messagesSent.Load(),
		MessagesReceived: t.messagesReceived.Load(),
		BytesOut:         t.bytesOut.Load(),
		BytesIn:          t.bytesIn.Load(),
		ActivePools:      poolCount,
	}
}
