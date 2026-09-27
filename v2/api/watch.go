package api

import "context"

// ChangeEvent is one externally-observable mutation, delivered by a
// Watchable's Watch channel. It is a filtered, public-facing projection
// of the internal Event/EventBus mechanism (see events.go) — Watchable
// implementations build ChangeEvents from the same TopicKVPut/
// TopicKVDelete/TopicObjectPut/TopicObjectDelete events they already
// publish internally, so adding an external watch never requires a
// second write path.
type ChangeEvent struct {
	Topic   string // e.g. TopicKVPut, TopicObjectDelete
	Key     string // KV key, or "bucket/key" for object events
	Value   []byte // best-effort; may be nil (e.g. for deletes, or where the source only publishes size/metadata)
	Deleted bool
}

// WatchHandle stops a single Watch subscription. Close is idempotent and
// must not block; it closes the channel returned alongside it and
// releases the underlying event-bus subscription.
type WatchHandle interface {
	Close()
}

// Watchable is an optional capability a service (typically the kv or
// object plugin's concrete type) may implement in addition to its
// primary interface (KVService/ObjectService). Consumers — the web
// plugin's SSE route, in particular — look up a service by its normal
// fixed name (e.g. "kv") and type-assert it to Watchable to check
// support, rather than this being a separate registered service.
//
// Watch delivers every ChangeEvent whose Key has the given prefix
// (empty prefix matches everything) until the context is cancelled or
// the returned WatchHandle is closed, whichever comes first. The channel
// is closed exactly once, after which no further sends occur.
type Watchable interface {
	Watch(ctx context.Context, prefix string) (<-chan ChangeEvent, WatchHandle, error)
}
