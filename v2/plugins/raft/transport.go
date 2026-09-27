package raft

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Wire framing, request:  [1-byte kind][4-byte BE length][JSON payload]
//
//	response: [1-byte ok(1)/err(0)][4-byte BE length][JSON payload or error string]
//
// One request per connection (dial, write request, read response, close)
// — simpler and easier to reason about correctly than a pooled/persistent
// connection given Raft's request/response RPC shape and the heartbeat
// intervals involved (tens of milliseconds), at the cost of a fresh
// TCP handshake per RPC. Correct-first, matching this plugin's overall
// priority given the directive.
const (
	kindRequestVote   byte = 1
	kindAppendEntries byte = 2

	maxRPCFrame = 16 * 1024 * 1024
)

func writeFrame(w io.Writer, ok bool, body []byte) error {
	header := make([]byte, 5)
	if ok {
		header[0] = 1
	}
	binary.BigEndian.PutUint32(header[1:5], uint32(len(body)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	_, err := w.Write(body)
	return err
}

func readFrame(r io.Reader) (ok bool, body []byte, err error) {
	header := make([]byte, 5)
	if _, err = io.ReadFull(r, header); err != nil {
		return false, nil, err
	}
	ok = header[0] == 1
	n := binary.BigEndian.Uint32(header[1:5])
	if n > maxRPCFrame {
		return false, nil, fmt.Errorf("raft: frame too large: %d", n)
	}
	body = make([]byte, n)
	if n > 0 {
		if _, err = io.ReadFull(r, body); err != nil {
			return false, nil, err
		}
	}
	return ok, body, nil
}

// rpcHandler dispatches one decoded request to the right Raft method,
// returning the response to encode (or an error to report to the caller).
type rpcHandler func(kind byte, body []byte) (resp any, err error)

type rpcServer struct {
	ln      net.Listener
	handler rpcHandler

	mu       sync.Mutex
	accepted map[net.Conn]struct{}
	closing  bool
	wg       sync.WaitGroup
}

func newRPCServer(addr string, handler rpcHandler) (*rpcServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &rpcServer{ln: ln, handler: handler, accepted: make(map[net.Conn]struct{})}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

func (s *rpcServer) Addr() string { return s.ln.Addr().String() }

func (s *rpcServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			conn.Close()
			return
		}
		s.accepted[conn] = struct{}{}
		s.mu.Unlock()

		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *rpcServer) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		delete(s.accepted, conn)
		s.mu.Unlock()
		conn.Close()
	}()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	kindBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, kindBuf); err != nil {
		return
	}
	_, body, err := readFrame(conn)
	if err != nil {
		return
	}

	resp, herr := s.handler(kindBuf[0], body)
	if herr != nil {
		_ = writeFrame(conn, false, []byte(herr.Error()))
		return
	}
	respBody, err := json.Marshal(resp)
	if err != nil {
		_ = writeFrame(conn, false, []byte(err.Error()))
		return
	}
	_ = writeFrame(conn, true, respBody)
}

func (s *rpcServer) Stop() {
	s.mu.Lock()
	s.closing = true
	s.ln.Close()
	for c := range s.accepted {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// rpcCall dials addr fresh, sends one (kind, req) frame, and decodes the
// response into resp. timeout bounds the whole round trip.
func rpcCall(addr string, kind byte, req any, resp any, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reqBody, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if _, err := conn.Write([]byte{kind}); err != nil {
		return err
	}
	if err := writeFrame(conn, true, reqBody); err != nil {
		return err
	}

	ok, body, err := readFrame(conn)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New(string(body))
	}
	if resp != nil {
		return json.Unmarshal(body, resp)
	}
	return nil
}
