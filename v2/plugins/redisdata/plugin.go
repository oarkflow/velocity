// Package redisdata implements a single Velocity v2 plugin providing five
// Redis-compatible data-structure services (List, Set, Hash, SortedSet,
// PubSub) atop whatever api.StorageBackend is registered under "storage".
// One concrete Plugin type implements all five api interfaces and
// registers itself under all five service names ("list", "set", "hash",
// "zset", "pubsub") — Redis itself treats these as one shared keyspace,
// and the interfaces are small enough that splitting them into five
// separate plugin types would add indirection without benefit.
//
// On-disk design (see list.go/set.go/hash.go/zset.go doc comments for the
// full rationale per structure):
//   - List: head/tail sequence counters + per-index element entries, so
//     LPush/RPush/LPop/RPop are O(1) storage operations (no whole-list
//     rewrite) and LRange(start, stop) is O(range size), not O(list size).
//   - Set/Hash: direct per-member/per-field entries, so membership tests
//     and field lookups are O(1) point reads.
//   - SortedSet: a score-ordered index (byte-sortable float encoding) for
//     ZRange, plus a separate member->score lookup index for O(1)
//     ZScore/ZRem — ZRange itself is O(cardinality) since it collects the
//     whole ordered set before applying Redis-style start/stop indexing
//     (documented limitation, not a hidden cost).
//   - PubSub: purely in-memory, matching Redis's own lack of persistence
//     or delivery history for pub/sub.
package redisdata

import (
	"context"
	"sync"

	"github.com/oarkflow/velocity/v2/api"
)

// Plugin implements api.Plugin plus api.ListService, api.SetService,
// api.HashService, api.SortedSetService, and api.PubSubService.
type Plugin struct {
	storageDep string

	storage api.StorageBackend
	log     api.Logger

	// listMu serializes List mutations (LPush/RPush/LPop/RPop) per-plugin
	// (not per-key) — correctness over concurrency granularity, matching
	// the coarse-lock precedent already established by plugins/kv's Incr.
	listMu sync.Mutex

	// zsetMu serializes ZAdd/ZRem, which each need an atomic
	// read-old-score-then-write-new-entries sequence to avoid leaving a
	// stale byscore-ordered entry under concurrent access to the same
	// member.
	zsetMu sync.Mutex

	// pubsub state: channel name -> subscriber id -> delivery channel.
	psMu     sync.Mutex
	psSubs   map[string]map[uint64]chan api.PubSubMessage
	psNextID uint64
}

// NewPlugin constructs the plugin. storageDep names the plugin whose
// Dependencies()-graph position this one boots after (default
// "storage-lsm" when empty) — NOT the service-lookup name, which is
// always the fixed "storage".
func NewPlugin(storageDep string) *Plugin {
	if storageDep == "" {
		storageDep = "storage-lsm"
	}
	return &Plugin{
		storageDep: storageDep,
		psSubs:     make(map[string]map[uint64]chan api.PubSubMessage),
	}
}

func (p *Plugin) Name() string           { return "redisdata" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return []string{p.storageDep} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.storage = k.Registry().MustLookup("storage").(api.StorageBackend)
	p.log = k.Logger()

	if err := k.Registry().Provide("list", api.ListService(p)); err != nil {
		return err
	}
	if err := k.Registry().Provide("set", api.SetService(p)); err != nil {
		return err
	}
	if err := k.Registry().Provide("hash", api.HashService(p)); err != nil {
		return err
	}
	if err := k.Registry().Provide("zset", api.SortedSetService(p)); err != nil {
		return err
	}
	if err := k.Registry().Provide("pubsub", api.PubSubService(p)); err != nil {
		return err
	}
	return nil
}

func (p *Plugin) Start(ctx context.Context) error { return nil }
func (p *Plugin) Stop(ctx context.Context) error  { return nil }

func (p *Plugin) Health() api.Health {
	return api.Health{Status: "ok"}
}

var (
	_ api.Plugin           = (*Plugin)(nil)
	_ api.ListService      = (*Plugin)(nil)
	_ api.SetService       = (*Plugin)(nil)
	_ api.HashService      = (*Plugin)(nil)
	_ api.SortedSetService = (*Plugin)(nil)
	_ api.PubSubService    = (*Plugin)(nil)
)
