package notifications

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// memBackend is a minimal in-test api.StorageBackend stub.
type memBackend struct {
	data map[string][]byte
}

func newMemBackend() *memBackend { return &memBackend{data: map[string][]byte{}} }

func (m *memBackend) Get(ctx context.Context, key []byte) ([]byte, bool, error) {
	v, ok := m.data[string(key)]
	return v, ok, nil
}
func (m *memBackend) Put(ctx context.Context, e api.Entry) error {
	m.data[string(e.Key)] = e.Value
	return nil
}
func (m *memBackend) Delete(ctx context.Context, key []byte) error {
	delete(m.data, string(key))
	return nil
}
func (m *memBackend) Batch(ctx context.Context, ops []api.BatchOp) error {
	for _, op := range ops {
		if op.Delete {
			delete(m.data, string(op.Entry.Key))
		} else {
			m.data[string(op.Entry.Key)] = op.Entry.Value
		}
	}
	return nil
}
func (m *memBackend) Scan(ctx context.Context, prefix []byte) (api.Iterator, error) {
	return nil, nil
}
func (m *memBackend) Snapshot(ctx context.Context) (api.Snapshot, error) { return nil, nil }
func (m *memBackend) Close() error                                       { return nil }

// simpleBus is a minimal in-test api.EventBus.
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
	b.handlers[topic] = append(b.handlers[topic], h)
	return noopSub{}
}

type noopSub struct{}

func (noopSub) Unsubscribe() {}

type nopLogger struct{}

func (nopLogger) Debug(string, ...any) {}
func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

func newTestPlugin(t *testing.T, bus *simpleBus) *Plugin {
	t.Helper()
	p := NewPlugin("")
	p.storage = newMemBackend()
	p.events = bus
	p.log = nopLogger{}
	p.queue = make(chan delivery, 64)

	for _, topic := range []string{api.TopicKVPut, api.TopicKVDelete, api.TopicObjectPut, api.TopicObjectDelete} {
		bus.Subscribe(topic, p.onEvent)
	}
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { p.Stop(context.Background()) })
	return p
}

func TestWebhookDeliveredOnMatchingTopic(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	bus := newSimpleBus()
	p := newTestPlugin(t, bus)

	if err := p.AddRule(context.Background(), api.NotificationRule{ID: "r1", Topic: api.TopicKVPut, WebhookURL: srv.URL, Enabled: true}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	bus.Publish(context.Background(), api.Event{Topic: api.TopicKVPut, Source: "kv", Payload: map[string]any{"key": "foo"}})

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&hits) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected exactly 1 webhook hit, got %d", hits)
	}

	delivered, failed := p.Stats()
	if delivered != 1 || failed != 0 {
		t.Fatalf("expected delivered=1 failed=0, got delivered=%d failed=%d", delivered, failed)
	}
}

func TestWebhookNotFiredForNonMatchingTopic(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	bus := newSimpleBus()
	p := newTestPlugin(t, bus)

	if err := p.AddRule(context.Background(), api.NotificationRule{ID: "r1", Topic: api.TopicObjectPut, WebhookURL: srv.URL, Enabled: true}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	bus.Publish(context.Background(), api.Event{Topic: api.TopicKVPut, Source: "kv", Payload: map[string]any{"key": "foo"}})
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("expected 0 webhook hits for non-matching topic, got %d", hits)
	}
}

func TestWebhookRetryThenSucceed(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	bus := newSimpleBus()
	p := newTestPlugin(t, bus)
	p.maxRetry = 3

	if err := p.AddRule(context.Background(), api.NotificationRule{ID: "r1", Topic: api.TopicKVPut, WebhookURL: srv.URL, Enabled: true}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	bus.Publish(context.Background(), api.Event{Topic: api.TopicKVPut, Source: "kv", Payload: map[string]any{"key": "foo"}})

	deadline := time.Now().Add(3 * time.Second)
	for {
		delivered, _ := p.Stats()
		if delivered == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("webhook never succeeded after retry, attempts=%d", atomic.LoadInt32(&attempts))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if atomic.LoadInt32(&attempts) < 2 {
		t.Fatalf("expected at least 2 attempts (1 failure + 1 success), got %d", attempts)
	}
}

func TestListRulesPersistence(t *testing.T) {
	bus := newSimpleBus()
	p := newTestPlugin(t, bus)

	if err := p.AddRule(context.Background(), api.NotificationRule{ID: "a", Topic: api.TopicKVPut, WebhookURL: "http://x", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := p.AddRule(context.Background(), api.NotificationRule{ID: "b", Topic: api.TopicObjectDelete, WebhookURL: "http://y", Enabled: false}); err != nil {
		t.Fatal(err)
	}

	rules, err := p.ListRules(context.Background())
	if err != nil || len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d (err=%v)", len(rules), err)
	}

	if err := p.RemoveRule(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	rules, _ = p.ListRules(context.Background())
	if len(rules) != 1 || rules[0].ID != "b" {
		t.Fatalf("expected only rule 'b' left, got %+v", rules)
	}

	// Reload from storage into a fresh in-memory rule map to confirm
	// persistence round-trips.
	p2 := NewPlugin("")
	p2.storage = p.storage
	if err := p2.loadRules(context.Background()); err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	if len(p2.rules) != 1 || p2.rules["b"].WebhookURL != "http://y" {
		t.Fatalf("persisted rules did not round-trip: %+v", p2.rules)
	}
}
