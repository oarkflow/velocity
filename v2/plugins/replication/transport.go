package replication

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

const (
	dialTimeout    = 5 * time.Second
	maxFrameLen    = 64 * 1024 * 1024 // 64MB
	poolSizePerAdr = 4
)

// connPool manages a small pool of live TCP connections to one peer
// address, ported from v1's wire_protocol.go connPool.
type connPool struct {
	mu      sync.Mutex
	address string
	conns   []net.Conn
	maxSize int
}

func newConnPool(address string, maxSize int) *connPool {
	return &connPool{address: address, maxSize: maxSize}
}

func (p *connPool) get() (net.Conn, error) {
	p.mu.Lock()
	if len(p.conns) > 0 {
		conn := p.conns[len(p.conns)-1]
		p.conns = p.conns[:len(p.conns)-1]
		p.mu.Unlock()
		if err := conn.SetDeadline(time.Now().Add(100 * time.Millisecond)); err == nil {
			_ = conn.SetDeadline(time.Time{})
			return conn, nil
		}
		conn.Close()
	} else {
		p.mu.Unlock()
	}
	return net.DialTimeout("tcp", p.address, dialTimeout)
}

func (p *connPool) put(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.conns) < p.maxSize {
		p.conns = append(p.conns, conn)
		return
	}
	conn.Close()
}

func (p *connPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
}

// Transport is the concrete api.ReplicationTransport implementation: a
// length-framed TCP protocol with per-peer connection pooling, ported
// from v1's wire_protocol.go NodeTransport. Each frame on the wire is:
//
//	[4-byte big-endian total length][2-byte sender-ID length][sender ID bytes][payload bytes]
//
// The sender ID is threaded through so OnReceive's handler can report
// which node.NodeInfo the payload came from without a separate handshake.
type Transport struct {
	selfID   string
	bindAddr string

	mu       sync.RWMutex
	listener net.Listener
	pools    map[string]*connPool
	// accepted tracks every inbound connection currently being served by
	// handleConn, so Stop can force-close them. Without this, a blocked
	// handleConn only unblocks after its idle read deadline (up to 30s)
	// even though Stop wants to shut down immediately — this bit us in
	// testing whenever a peer's connections were still open.
	accepted map[net.Conn]struct{}

	handlerMu sync.RWMutex
	handler   func(from api.NodeInfo, payload []byte)

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewTransport creates a transport identified by selfID, listening on
// bindAddr once Start is called (":0" picks a free port — call Addr()
// after Start to learn the actual bound address).
func NewTransport(selfID, bindAddr string) *Transport {
	return &Transport{
		selfID:   selfID,
		bindAddr: bindAddr,
		pools:    make(map[string]*connPool),
		accepted: make(map[net.Conn]struct{}),
	}
}

// Start begins listening for inbound connections.
func (t *Transport) Start() error {
	ln, err := net.Listen("tcp", t.bindAddr)
	if err != nil {
		return fmt.Errorf("replication: transport listen on %s: %w", t.bindAddr, err)
	}
	t.mu.Lock()
	t.listener = ln
	t.mu.Unlock()

	t.ctx, t.cancel = context.WithCancel(context.Background())
	t.wg.Add(1)
	go t.acceptLoop()
	return nil
}

// Addr returns the actual bound listener address (useful when bindAddr
// was ":0"). Empty if Start hasn't been called.
func (t *Transport) Addr() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.listener == nil {
		return ""
	}
	return t.listener.Addr().String()
}

// Stop closes the listener, cancels the accept loop, force-closes every
// in-flight accepted connection (so handleConn goroutines return
// immediately instead of waiting out their idle read deadline), and
// closes all pooled outbound connections.
func (t *Transport) Stop() error {
	if t.cancel != nil {
		t.cancel()
	}
	t.mu.Lock()
	if t.listener != nil {
		t.listener.Close()
	}
	for conn := range t.accepted {
		conn.Close()
	}
	t.mu.Unlock()

	t.wg.Wait()

	t.mu.Lock()
	for _, p := range t.pools {
		p.close()
	}
	t.pools = make(map[string]*connPool)
	t.mu.Unlock()
	return nil
}

func (t *Transport) getPool(address string) *connPool {
	t.mu.RLock()
	p, ok := t.pools[address]
	t.mu.RUnlock()
	if ok {
		return p
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok = t.pools[address]; ok {
		return p
	}
	p = newConnPool(address, poolSizePerAdr)
	t.pools[address] = p
	return p
}

// Send implements api.ReplicationTransport.
func (t *Transport) Send(ctx context.Context, target api.NodeInfo, payload []byte) error {
	pool := t.getPool(target.Address)
	conn, err := pool.get()
	if err != nil {
		return fmt.Errorf("replication: connect to %s: %w", target.Address, err)
	}

	deadline := time.Now().Add(dialTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		conn.Close()
		return err
	}

	if err := writeFrame(conn, t.selfID, payload); err != nil {
		conn.Close()
		return fmt.Errorf("replication: write to %s: %w", target.Address, err)
	}

	_ = conn.SetDeadline(time.Time{})
	pool.put(conn)
	return nil
}

// OnReceive registers the single handler invoked for every inbound frame.
// Re-registering replaces the previous handler.
func (t *Transport) OnReceive(handler func(from api.NodeInfo, payload []byte)) {
	t.handlerMu.Lock()
	t.handler = handler
	t.handlerMu.Unlock()
}

func (t *Transport) acceptLoop() {
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
		go t.handleConn(conn)
	}
}

func (t *Transport) handleConn(conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	t.mu.Lock()
	t.accepted[conn] = struct{}{}
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		delete(t.accepted, conn)
		t.mu.Unlock()
	}()

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}
		if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return
		}
		senderID, payload, err := readFrame(conn)
		if err != nil {
			return
		}

		t.handlerMu.RLock()
		h := t.handler
		t.handlerMu.RUnlock()
		if h != nil {
			h(api.NodeInfo{ID: senderID, Address: conn.RemoteAddr().String()}, payload)
		}
	}
}

func writeFrame(w io.Writer, senderID string, payload []byte) error {
	idBytes := []byte(senderID)
	if len(idBytes) > 65535 {
		return fmt.Errorf("replication: sender id too long")
	}
	total := 2 + len(idBytes) + len(payload)
	if total > maxFrameLen {
		return fmt.Errorf("replication: frame too large: %d bytes", total)
	}

	header := make([]byte, 4+2)
	binary.BigEndian.PutUint32(header[0:4], uint32(total))
	binary.BigEndian.PutUint16(header[4:6], uint16(len(idBytes)))

	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(idBytes); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func readFrame(r io.Reader) (senderID string, payload []byte, err error) {
	lenBuf := make([]byte, 4)
	if _, err = io.ReadFull(r, lenBuf); err != nil {
		return "", nil, err
	}
	total := binary.BigEndian.Uint32(lenBuf)
	if total > maxFrameLen || total < 2 {
		return "", nil, fmt.Errorf("replication: invalid frame length %d", total)
	}

	body := make([]byte, total)
	if _, err = io.ReadFull(r, body); err != nil {
		return "", nil, err
	}
	idLen := binary.BigEndian.Uint16(body[0:2])
	if int(idLen) > len(body)-2 {
		return "", nil, fmt.Errorf("replication: invalid sender id length %d", idLen)
	}
	senderID = string(body[2 : 2+idLen])
	payload = body[2+idLen:]
	return senderID, payload, nil
}

var _ api.ReplicationTransport = (*Transport)(nil)
