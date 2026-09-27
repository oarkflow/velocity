package api

import "context"

// Event is a single message flowing through the kernel's bus. Topic is a
// dot-namespaced string (see the Topic* constants below for the well-known
// ones); Payload is left as `any` so each topic can carry its own shape —
// consumers know what to expect for the topics they subscribe to.
type Event struct {
	Topic   string
	Source  string // plugin Name() that published the event
	Payload any
}

// Handler processes one Event. Handlers must not block indefinitely —
// Publish is synchronous and calls every subscribed handler in turn, so a
// slow handler delays every other subscriber and the publisher itself.
// Long-running work triggered by an event should be handed off to a
// goroutine or queue inside the handler.
type Handler func(ctx context.Context, ev Event)

// Subscription is returned by EventBus.Subscribe and lets a plugin stop
// receiving events, typically during Stop.
type Subscription interface {
	Unsubscribe()
}

// EventBus is the kernel's cross-cutting pub/sub mechanism. It is what
// makes this a true microkernel rather than a relabeled monolith:
// compliance, replication, and notification plugins observe what KV/
// object/secret plugins do by subscribing to events, without those
// plugins ever importing or calling them directly. Adding or removing an
// observer plugin never requires changing the plugin being observed.
type EventBus interface {
	Publish(ctx context.Context, ev Event)
	Subscribe(topic string, h Handler) Subscription
}

// Well-known event topics. Plugins are free to publish additional
// project-specific topics, but should reuse these where the concept
// matches so cross-cutting plugins (compliance, replication, metrics,
// notifications) can subscribe once and observe every producer.
const (
	TopicKVPut        = "kv.put"
	TopicKVDelete     = "kv.delete"
	TopicObjectPut    = "object.put"
	TopicObjectDelete = "object.delete"
	TopicSecretSet    = "secret.set"
	TopicSecretRotate = "secret.rotate"
	TopicSecretAccess = "secret.access"
	TopicAuthLogin    = "auth.login"
	TopicAuthDenied   = "auth.denied"
	TopicClusterJoin  = "cluster.join"
	TopicClusterLeave = "cluster.leave"
)
