package replication

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

func TestTransport_SendReceive(t *testing.T) {
	tA := NewTransport("A", "127.0.0.1:0")
	tB := NewTransport("B", "127.0.0.1:0")

	if err := tA.Start(); err != nil {
		t.Fatalf("start A: %v", err)
	}
	defer tA.Stop()
	if err := tB.Start(); err != nil {
		t.Fatalf("start B: %v", err)
	}
	defer tB.Stop()

	var (
		mu       sync.Mutex
		gotFrom  api.NodeInfo
		gotBytes []byte
	)
	received := make(chan struct{})

	tB.OnReceive(func(from api.NodeInfo, payload []byte) {
		mu.Lock()
		gotFrom = from
		gotBytes = append([]byte(nil), payload...)
		mu.Unlock()
		close(received)
	})

	target := api.NodeInfo{ID: "B", Address: tB.Addr()}
	payload := []byte("hello from A")

	if err := tA.Send(context.Background(), target, payload); err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for B to receive the frame")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotFrom.ID != "A" {
		t.Fatalf("expected sender ID 'A', got %q", gotFrom.ID)
	}
	if string(gotBytes) != string(payload) {
		t.Fatalf("payload mismatch: got %q want %q", gotBytes, payload)
	}
}
