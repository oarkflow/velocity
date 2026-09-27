package kernel

import (
	"context"
	"sync"

	"github.com/oarkflow/velocity/v2/api"
)

// eventBus is the default api.EventBus implementation. Publish is
// synchronous and calls each subscribed handler in turn, with panic
// recovery per handler so one misbehaving observer plugin cannot take
// down the publisher or other observers.
type eventBus struct {
	mu       sync.RWMutex
	handlers map[string]map[uint64]api.Handler
	nextID   uint64
	log      api.Logger
}

func newEventBus(log api.Logger) *eventBus {
	return &eventBus{handlers: make(map[string]map[uint64]api.Handler), log: log}
}

type subscription struct {
	bus   *eventBus
	topic string
	id    uint64
}

func (s *subscription) Unsubscribe() {
	s.bus.mu.Lock()
	defer s.bus.mu.Unlock()
	delete(s.bus.handlers[s.topic], s.id)
}

func (b *eventBus) Subscribe(topic string, h api.Handler) api.Subscription {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.handlers[topic] == nil {
		b.handlers[topic] = make(map[uint64]api.Handler)
	}
	b.nextID++
	id := b.nextID
	b.handlers[topic][id] = h
	return &subscription{bus: b, topic: topic, id: id}
}

func (b *eventBus) Publish(ctx context.Context, ev api.Event) {
	b.mu.RLock()
	topicHandlers := b.handlers[ev.Topic]
	handlers := make([]api.Handler, 0, len(topicHandlers))
	for _, h := range topicHandlers {
		handlers = append(handlers, h)
	}
	b.mu.RUnlock()

	for _, h := range handlers {
		b.invoke(ctx, ev, h)
	}
}

func (b *eventBus) invoke(ctx context.Context, ev api.Event, h api.Handler) {
	defer func() {
		if r := recover(); r != nil && b.log != nil {
			b.log.Error("event handler panicked", "topic", ev.Topic, "source", ev.Source, "recover", r)
		}
	}()
	h(ctx, ev)
}

var _ api.EventBus = (*eventBus)(nil)
