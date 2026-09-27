package replication

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// wireMembership hooks Transport.OnReceive to decode the shared envelope
// and dispatch control frames to m, mirroring what Plugin.Init does for a
// full boot. Test-only glue since these tests exercise Membership without
// going through Plugin.
func wireMembership(t *Transport, m *Membership) {
	t.OnReceive(func(from api.NodeInfo, payload []byte) {
		var env frameEnvelope
		if err := json.Unmarshal(payload, &env); err != nil {
			return
		}
		if env.Kind == "control" && env.Control != nil {
			m.HandleControl(from, *env.Control)
		}
	})
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("condition not met within %s", timeout)
	}
}

func TestMembership_JoinAndLeave(t *testing.T) {
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

	mA := NewMembership(api.NodeInfo{ID: "A", Address: tA.Addr()}, tA, 50*time.Millisecond, 5*time.Second)
	mB := NewMembership(api.NodeInfo{ID: "B", Address: tB.Addr()}, tB, 50*time.Millisecond, 5*time.Second)
	wireMembership(tA, mA)
	wireMembership(tB, mB)

	mA.Start()
	defer mA.Stop()
	mB.Start()
	defer mB.Stop()

	// B joins A's address.
	if err := mB.Join(context.Background(), tA.Addr()); err != nil {
		t.Fatalf("join: %v", err)
	}

	waitFor(t, 2*time.Second, func() bool { return len(mA.Members()) == 2 })
	waitFor(t, 2*time.Second, func() bool { return len(mB.Members()) == 2 })

	ids := map[string]bool{}
	for _, n := range mA.Members() {
		ids[n.ID] = true
	}
	if !ids["A"] || !ids["B"] {
		t.Fatalf("expected A to know about both A and B, got %v", mA.Members())
	}

	// B leaves; A should observe the departure.
	if err := mB.Leave(context.Background()); err != nil {
		t.Fatalf("leave: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return len(mA.Members()) == 1 })

	remaining := mA.Members()
	if len(remaining) != 1 || remaining[0].ID != "A" {
		t.Fatalf("expected only A to remain after B left, got %v", remaining)
	}
}

func TestMembership_NodeForKeyUsesRing(t *testing.T) {
	tA := NewTransport("A", "127.0.0.1:0")
	if err := tA.Start(); err != nil {
		t.Fatalf("start A: %v", err)
	}
	defer tA.Stop()

	mA := NewMembership(api.NodeInfo{ID: "A", Address: tA.Addr()}, tA, time.Second, time.Second)
	owner := mA.NodeForKey([]byte("some-key"))
	if owner.ID != "A" {
		t.Fatalf("expected sole member A to own every key, got %q", owner.ID)
	}
}
