package api

import "context"

// ListService is a Redis-list-compatible ordered collection, backing
// LPUSH/RPUSH/LPOP/RPOP/LRANGE/LLEN. Service name: "list".
type ListService interface {
	LPush(ctx context.Context, key string, values ...[]byte) (length int64, err error)
	RPush(ctx context.Context, key string, values ...[]byte) (length int64, err error)
	LPop(ctx context.Context, key string) (value []byte, ok bool, err error)
	RPop(ctx context.Context, key string) (value []byte, ok bool, err error)
	// LRange returns elements from start to stop inclusive, Redis-style
	// (0-based, negative indices count from the end; -1 means "last
	// element"). Implementations must support negative indices.
	LRange(ctx context.Context, key string, start, stop int64) ([][]byte, error)
	LLen(ctx context.Context, key string) (int64, error)
}

// SetService is a Redis-set-compatible unordered unique collection.
// Service name: "set".
type SetService interface {
	SAdd(ctx context.Context, key string, members ...[]byte) (added int64, err error)
	SRem(ctx context.Context, key string, members ...[]byte) (removed int64, err error)
	SMembers(ctx context.Context, key string) ([][]byte, error)
	SIsMember(ctx context.Context, key string, member []byte) (bool, error)
	SCard(ctx context.Context, key string) (int64, error)
}

// HashService is a Redis-hash-compatible field/value map nested under one
// key. Service name: "hash".
type HashService interface {
	HSet(ctx context.Context, key, field string, value []byte) error
	HGet(ctx context.Context, key, field string) (value []byte, ok bool, err error)
	HDel(ctx context.Context, key, field string) error
	HGetAll(ctx context.Context, key string) (map[string][]byte, error)
	HLen(ctx context.Context, key string) (int64, error)
}

// SortedSetService is a Redis-zset-compatible score-ordered unique
// collection. Service name: "zset".
type SortedSetService interface {
	ZAdd(ctx context.Context, key string, score float64, member []byte) error
	// ZRange returns members ordered by ascending score, start to stop
	// inclusive, Redis-style (0-based, negative indices count from the
	// end).
	ZRange(ctx context.Context, key string, start, stop int64) ([][]byte, error)
	ZScore(ctx context.Context, key string, member []byte) (score float64, ok bool, err error)
	ZRem(ctx context.Context, key string, member []byte) error
	ZCard(ctx context.Context, key string) (int64, error)
}

// PubSubMessage is one message delivered to a Subscribe channel.
type PubSubMessage struct {
	Channel string
	Payload []byte
}

// PubSubService is Redis-PUBLISH/SUBSCRIBE-compatible fire-and-forget
// messaging: Publish delivers only to currently-subscribed listeners, and
// carries no history — a Subscribe call made after a Publish never sees
// it. Service name: "pubsub".
type PubSubService interface {
	Publish(ctx context.Context, channel string, payload []byte) (subscribers int64, err error)
	// Subscribe returns a channel of messages for the given channel name
	// and an unsubscribe function the caller must call to stop delivery
	// and release resources (mirroring api.Watchable's WatchHandle
	// pattern already used elsewhere in this codebase).
	Subscribe(ctx context.Context, channel string) (<-chan PubSubMessage, func(), error)
}
