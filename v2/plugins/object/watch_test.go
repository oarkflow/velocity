package object

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// simpleBus is a minimal in-test api.EventBus, mirroring plugins/kv's
// equivalent test helper (kept package-local rather than shared, so
// object stays independently testable).
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
	s.bus.handlers[s.topic][s.idx] = func(ctx context.Context, ev api.Event) {}
}

func TestObjectWatchDeliversMatchingPrefixOnly(t *testing.T) {
	bus := newSimpleBus()
	p := newTestPlugin()
	p.events = bus
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := p.CreateBucket(ctx, "b1"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if err := p.CreateBucket(ctx, "b2"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	ch, handle, err := p.Watch(ctx, "b1/")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	defer handle.Close()

	if _, err := p.PutObject(ctx, "b1", "k1", strings.NewReader("hello"), api.ObjectMeta{}); err != nil {
		t.Fatalf("PutObject b1: %v", err)
	}
	if _, err := p.PutObject(ctx, "b2", "k2", strings.NewReader("world"), api.ObjectMeta{}); err != nil {
		t.Fatalf("PutObject b2: %v", err)
	}

	select {
	case ev := <-ch:
		if ev.Key != "b1/k1" || ev.Deleted {
			t.Fatalf("expected put event for b1/k1, got %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for matching event")
	}

	select {
	case ev := <-ch:
		t.Fatalf("expected no event for non-matching bucket b2, got %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestObjectWatchCloseStopsDelivery(t *testing.T) {
	bus := newSimpleBus()
	p := newTestPlugin()
	p.events = bus
	ctx := context.Background()

	if err := p.CreateBucket(ctx, "b1"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	ch, handle, err := p.Watch(ctx, "")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	handle.Close()

	if _, err := p.PutObject(ctx, "b1", "k1", strings.NewReader("hello"), api.ObjectMeta{}); err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("expected channel closed/no delivery after Close, got an open-channel event")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("channel neither closed nor delivered — Close should close it promptly")
	}
}
