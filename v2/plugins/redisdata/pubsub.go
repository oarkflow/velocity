package redisdata

import (
	"context"

	"github.com/oarkflow/velocity/v2/api"
)

// PubSub is purely in-memory — never persisted via StorageBackend — since
// real Redis PUBLISH/SUBSCRIBE has no persistence or delivery history
// either: a Subscribe call only ever sees messages Published after it
// starts, and a channel with zero subscribers silently drops the message
// (Publish still succeeds, reporting 0 subscribers reached).
//
// Each subscriber gets its own buffered channel; Publish sends
// non-blockingly (select+default) so one slow or stuck subscriber can
// never block delivery to other subscribers or block the publisher
// itself — a message a full subscriber can't accept in time is dropped
// for that subscriber only, logged at Warn, matching real message-bus
// backpressure-drop semantics rather than Redis's own (Redis instead
// disconnects a slow-consumer client; dropping is the simpler, still
// bounded-memory choice for this in-process implementation, documented
// here as a deliberate behavioral difference).
const pubsubBufferSize = 64

func (p *Plugin) Publish(ctx context.Context, channel string, payload []byte) (int64, error) {
	p.psMu.Lock()
	subs := p.psSubs[channel]
	// Snapshot the channel list under the lock, then send outside it, so a
	// slow subscriber's full buffer (handled via select+default below)
	// never holds psMu and blocks concurrent Subscribe/Publish/unsubscribe
	// calls on other channels.
	chans := make([]chan api.PubSubMessage, 0, len(subs))
	for _, ch := range subs {
		chans = append(chans, ch)
	}
	p.psMu.Unlock()

	msg := api.PubSubMessage{Channel: channel, Payload: payload}
	var delivered int64
	for _, ch := range chans {
		select {
		case ch <- msg:
			delivered++
		default:
			if p.log != nil {
				p.log.Warn("redisdata: pubsub subscriber buffer full, dropping message", "channel", channel)
			}
		}
	}
	return delivered, nil
}

func (p *Plugin) Subscribe(ctx context.Context, channel string) (<-chan api.PubSubMessage, func(), error) {
	ch := make(chan api.PubSubMessage, pubsubBufferSize)

	p.psMu.Lock()
	if p.psSubs[channel] == nil {
		p.psSubs[channel] = make(map[uint64]chan api.PubSubMessage)
	}
	p.psNextID++
	id := p.psNextID
	p.psSubs[channel][id] = ch
	p.psMu.Unlock()

	var closed bool
	unsubscribe := func() {
		p.psMu.Lock()
		defer p.psMu.Unlock()
		if closed {
			return
		}
		closed = true
		delete(p.psSubs[channel], id)
		if len(p.psSubs[channel]) == 0 {
			delete(p.psSubs, channel)
		}
		close(ch)
	}

	return ch, unsubscribe, nil
}

// ActiveSubscriptions reports the total number of currently-open
// Subscribe calls across all channels. Exported for tests only, to
// assert Subscribe/unsubscribe doesn't leak.
func (p *Plugin) ActiveSubscriptions() int {
	p.psMu.Lock()
	defer p.psMu.Unlock()
	n := 0
	for _, subs := range p.psSubs {
		n += len(subs)
	}
	return n
}
