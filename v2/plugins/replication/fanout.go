package replication

import (
	"context"
	"encoding/json"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// fanoutQueueSize bounds the best-effort replication queue; once full,
// new events are dropped (logged) rather than blocking the publisher,
// matching the eventually-consistent, best-effort framing in doc.go.
const fanoutQueueSize = 1024

// replicaMsg wraps an observed mutation event for the wire.
type replicaMsg struct {
	Topic   string `json:"topic"`
	Payload []byte `json:"payload"`
}

// fanout subscribes to kv/object mutation events on the kernel event bus
// and asynchronously replicates them to every other known cluster member
// via Transport, exactly like plugins/compliance observes those same
// events for audit purposes — neither kv nor object plugins import or
// know about this fanout.
type fanout struct {
	membership *Membership
	transport  *Transport
	log        api.Logger

	queue chan replicaMsg
	done  chan struct{}
}

func newFanout(mem *Membership, t *Transport, log api.Logger) *fanout {
	return &fanout{
		membership: mem,
		transport:  t,
		log:        log,
		queue:      make(chan replicaMsg, fanoutQueueSize),
		done:       make(chan struct{}),
	}
}

func (f *fanout) subscribe(bus api.EventBus) {
	topics := []string{
		api.TopicKVPut, api.TopicKVDelete,
		api.TopicObjectPut, api.TopicObjectDelete,
	}
	for _, topic := range topics {
		t := topic
		bus.Subscribe(t, func(ctx context.Context, ev api.Event) {
			payload, err := json.Marshal(ev.Payload)
			if err != nil {
				return
			}
			select {
			case f.queue <- replicaMsg{Topic: t, Payload: payload}:
			default:
				if f.log != nil {
					f.log.Warn("replication: fanout queue full, dropping event", "topic", t)
				}
			}
		})
	}
}

func (f *fanout) start() {
	go f.loop()
}

func (f *fanout) stop() {
	close(f.done)
}

func (f *fanout) loop() {
	for {
		select {
		case <-f.done:
			return
		case msg := <-f.queue:
			f.replicate(msg)
		}
	}
}

func (f *fanout) replicate(msg replicaMsg) {
	data, err := json.Marshal(frameEnvelope{Kind: "replica", Replica: &msg})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, n := range f.membership.Members() {
		if n.ID == f.membership.self.ID {
			continue
		}
		if err := f.transport.Send(ctx, n, data); err != nil && f.log != nil {
			f.log.Warn("replication: fanout send failed", "target", n.ID, "err", err)
		}
	}
}

// HandleReplica processes one already-decoded replicaMsg received from a
// peer. Called by Plugin's central dispatcher after it decodes the
// frameEnvelope and routes Kind=="replica" frames here.
//
// This pass intentionally stops at "received and logged": actually
// applying a replicated kv.put/object.put to the local storage backend
// would require this plugin to depend on the kv/object plugins' service
// interfaces, which would break the one-way observer relationship
// (kv/object never know replication exists) that the rest of this plugin
// preserves. A future pass can add an optional local-apply path via a
// constructor-injected callback if that's wanted.
func (f *fanout) HandleReplica(from api.NodeInfo, msg replicaMsg) {
	if f.log != nil {
		f.log.Debug("replication: received replicated event", "from", from.ID, "topic", msg.Topic)
	}
}
