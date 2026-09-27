package kv

import (
	"context"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// simpleBus is a minimal in-test api.EventBus (synchronous, no filtering
// beyond topic — good enough to exercise Watch's own prefix filtering).
type simpleBus struct {
	handlers map[string][]api.Handler
}

func newSimpleBus() *simpleBus { return &simpleBus{handlers: map[string][]api.Handler{}} }

func (b *simpleBus) Publish(ctx context.Context, ev api.Event) {
	for _, h := range b.handlers[ev.Topic] {
		h(ctx, ev)
	}
}
func (b *simpleBus) Subscribe(topic string, h api.Handler) api.Subscription {
	idx := len(b.handlers[topic])
	b.handlers[topic] = append(b.handlers[topic], h)
	return &busSub{bus: b, topic: topic, idx: idx}
}

type busSub struct {
	bus   *simpleBus
	topic string
	idx   int
}

func (s *busSub) Unsubscribe() {
	// Replace with a no-op handler rather than mutating the slice under
	// concurrent iteration in Publish — sufficient for this test's needs.
	s.bus.handlers[s.topic][s.idx] = func(ctx context.Context, ev api.Event) {}
}

func TestWatchDeliversMatchingPrefixOnly(t *testing.T) {
	bus := newSimpleBus()
	p := &Plugin{storage: newMemBackend(), events: bus}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, handle, err := p.Watch(ctx, "foo/")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	defer handle.Close()

	if err := p.Put(ctx, "foo/a", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := p.Put(ctx, "bar/b", []byte("2")); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(ctx, "foo/a"); err != nil {
		t.Fatal(err)
	}

	var got []api.ChangeEvent
	timeout := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case ev := <-ch:
			got = append(got, ev)
		case <-timeout:
			t.Fatalf("timed out waiting for change events, got %d so far: %+v", len(got), got)
		}
	}

	if got[0].Key != "foo/a" || got[0].Deleted {
		t.Fatalf("expected first event to be foo/a put, got %+v", got[0])
	}
	if got[1].Key != "foo/a" || !got[1].Deleted {
		t.Fatalf("expected second event to be foo/a delete, got %+v", got[1])
	}

	select {
	case ev := <-ch:
		t.Fatalf("expected no event for non-matching prefix bar/b, got %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestWatchCloseStopsDeliveryAndDoesNotLeak(t *testing.T) {
	bus := newSimpleBus()
	p := &Plugin{storage: newMemBackend(), events: bus}
	ctx := context.Background()

	const n = 20
	var handles []api.WatchHandle
	for i := 0; i < n; i++ {
		_, h, err := p.Watch(ctx, "")
		if err != nil {
			t.Fatalf("Watch #%d: %v", i, err)
		}
		handles = append(handles, h)
	}

	if got := p.ActiveWatches(); got != n {
		t.Fatalf("expected %d active watches, got %d", n, got)
	}

	for _, h := range handles {
		h.Close()
	}

	deadline := time.Now().Add(time.Second)
	for p.ActiveWatches() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := p.ActiveWatches(); got != 0 {
		t.Fatalf("expected 0 active watches after closing all, got %d (goroutine/subscription leak)", got)
	}

	// A publish after everything is closed must not panic or block,
	// confirming the channels are truly detached.
	p.Put(ctx, "x", []byte("y"))
}

func TestWatchAutoClosesOnContextCancel(t *testing.T) {
	bus := newSimpleBus()
	p := &Plugin{storage: newMemBackend(), events: bus}
	ctx, cancel := context.WithCancel(context.Background())

	ch, _, err := p.Watch(ctx, "")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	cancel()

	deadline := time.Now().Add(time.Second)
	for p.ActiveWatches() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := p.ActiveWatches(); got != 0 {
		t.Fatalf("expected watch to auto-close on context cancel, activeWatches=%d", got)
	}

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("expected channel to be closed after context cancel")
		}
	case <-time.After(time.Second):
		t.Fatalf("channel was not closed after context cancel")
	}
}
