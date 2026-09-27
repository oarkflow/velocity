package resp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
)

func bootRespPlugin(t *testing.T, cfg map[string]any) (*Plugin, func()) {
	t.Helper()
	if cfg == nil {
		cfg = map[string]any{}
	}
	if _, ok := cfg["addr"]; !ok {
		cfg["addr"] = "127.0.0.1:0"
	}
	k := kernel.New(kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "kv", Enabled: true},
		{Name: "resp", Enabled: true, Config: cfg},
	}})
	kv := newMemKV()
	fakeKVPlugin := &fakeServicePlugin{name: "kv", svc: kv}
	respPlugin := NewPlugin("kv")
	if err := k.Boot(context.Background(), []api.Plugin{fakeKVPlugin, respPlugin}, map[string]bool{"kv": true, "resp": true}); err != nil {
		t.Fatalf("boot: %v", err)
	}
	cleanup := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = k.Shutdown(shutdownCtx)
	}
	return respPlugin, cleanup
}

func rlSendCommand(t *testing.T, conn net.Conn, raw string) string {
	t.Helper()
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(buf[:n])
}

func TestRateLimit_DisabledByDefault(t *testing.T) {
	p, cleanup := bootRespPlugin(t, nil)
	defer cleanup()
	conn, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// Fire a burst of PINGs — with no rate limit configured, none should
	// ever get the rate-limit error.
	for i := 0; i < 20; i++ {
		reply := rlSendCommand(t, conn, "*1\r\n$4\r\nPING\r\n")
		if reply != "+PONG\r\n" {
			t.Fatalf("PING #%d unexpectedly not PONG: %q", i, reply)
		}
	}
}

func TestRateLimit_ExceedingOpsPerSecGetsErrorReplyConnectionStaysOpen(t *testing.T) {
	p, cleanup := bootRespPlugin(t, map[string]any{
		"rate_limit_ops_per_sec": 2,
		"rate_limit_burst":       2,
	})
	defer cleanup()
	conn, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Burst of 2: first two PINGs succeed.
	for i := 0; i < 2; i++ {
		reply := rlSendCommand(t, conn, "*1\r\n$4\r\nPING\r\n")
		if reply != "+PONG\r\n" {
			t.Fatalf("PING #%d within burst: got %q, want PONG", i, reply)
		}
	}

	// Third, immediate PING should be rate-limited — a RESP error reply,
	// not a closed connection.
	reply := rlSendCommand(t, conn, "*1\r\n$4\r\nPING\r\n")
	if len(reply) == 0 || reply[0] != '-' {
		t.Fatalf("expected a RESP error reply when rate-limited, got %q", reply)
	}

	// The connection must still be usable afterward — send another PING
	// right away, still rate-limited (tokens haven't refilled), then wait
	// for the window to refill and confirm normal service resumes.
	reply2 := rlSendCommand(t, conn, "*1\r\n$4\r\nPING\r\n")
	if len(reply2) == 0 || reply2[0] != '-' {
		t.Fatalf("expected still-rate-limited on connection, got %q", reply2)
	}

	time.Sleep(1100 * time.Millisecond)
	reply3 := rlSendCommand(t, conn, "*1\r\n$4\r\nPING\r\n")
	if reply3 != "+PONG\r\n" {
		t.Fatalf("after refill window: got %q, want PONG", reply3)
	}
}

func TestMaxConnections_ExcessConnectionsRefusedCleanly(t *testing.T) {
	p, cleanup := bootRespPlugin(t, map[string]any{"max_connections": 1})
	defer cleanup()

	conn1, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer conn1.Close()
	// Confirm the first connection is genuinely usable.
	if reply := rlSendCommand(t, conn1, "*1\r\n$4\r\nPING\r\n"); reply != "+PONG\r\n" {
		t.Fatalf("conn1 PING: got %q, want PONG", reply)
	}

	// A second, over-the-cap connection must be refused cleanly (closed),
	// not hung — a read on it should return EOF/error promptly, not time
	// out waiting for a reply that will never come.
	conn2, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer conn2.Close()
	conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	_, readErr := conn2.Read(buf)
	if readErr == nil {
		t.Fatalf("expected the over-cap connection to be closed/refused, got a successful read")
	}

	// Freeing the first connection's slot must allow a new connection to
	// succeed.
	conn1.Close()
	// Give acceptLoop a moment to process the close via the accepted-map
	// cleanup in handleConn's deferred cleanup.
	var conn3 net.Conn
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn3, err = net.Dial("tcp", p.Addr())
		if err == nil {
			reply := rlSendCommand(t, conn3, "*1\r\n$4\r\nPING\r\n")
			if reply == "+PONG\r\n" {
				conn3.Close()
				return // success
			}
			conn3.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("a new connection never succeeded after freeing the capped slot")
}
