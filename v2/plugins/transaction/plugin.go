// Package transaction implements Velocity v2's cross-plugin atomic write
// coordinator: api.TxCoordinator, backing a real api.CrossTx built atop
// whatever a participating plugin's own StorageBackend.Batch already
// provides. See api.CrossTx's doc comment for the honest scope: this is
// NOT a generic multi-backend two-phase-commit protocol, only a single
// real Batch call combining ops from every participant that shares one
// StorageBackend instance.
package transaction

import (
	"context"
	"fmt"
	"sync"

	"github.com/oarkflow/velocity/v2/api"
)

// ServiceName is the fixed Registry name this plugin provides its
// api.TxCoordinator under.
const ServiceName = "transaction"

// Plugin implements api.Plugin and api.TxCoordinator. It has no storage
// dependency of its own — Begin doesn't need one, since the reference
// backend for a given CrossTx is established by whichever participant
// Stages first, not by this plugin.
type Plugin struct {
	log api.Logger
}

func NewPlugin() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string           { return ServiceName }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return nil }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.log = k.Logger()
	return k.Registry().Provide(ServiceName, api.TxCoordinator(p))
}

func (p *Plugin) Start(ctx context.Context) error { return nil }
func (p *Plugin) Stop(ctx context.Context) error  { return nil }
func (p *Plugin) Health() api.Health              { return api.Health{Status: "ok"} }

func (p *Plugin) Begin(ctx context.Context) (api.CrossTx, error) {
	return &crossTx{}, nil
}

var _ api.Plugin = (*Plugin)(nil)
var _ api.TxCoordinator = (*Plugin)(nil)

// crossTx is the default api.CrossTx implementation.
type crossTx struct {
	mu      sync.Mutex
	backend api.StorageBackend // established by the first Stage call
	ops     []api.BatchOp
	done    bool // Commit or Rollback already called — further use is refused
}

func (tx *crossTx) Stage(backend api.StorageBackend, ops []api.BatchOp) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if tx.done {
		return fmt.Errorf("transaction: Stage called after Commit/Rollback")
	}
	if backend == nil {
		return fmt.Errorf("transaction: Stage requires a non-nil backend")
	}
	if tx.backend == nil {
		tx.backend = backend
	} else if tx.backend != backend {
		// Go interface equality: true only if both the dynamic TYPE and
		// the dynamic VALUE (e.g. the same underlying *Engine pointer)
		// match — this is exactly "is this genuinely the same backend
		// instance," not merely "the same backend type." A tenant-scoped
		// StorageBackend decorator (see plugins/kv/tenantstorage.go) is a
		// DIFFERENT interface value than the raw shared backend even
		// though it wraps it, so a tenant-scoped participant correctly
		// fails this check rather than being silently combined with a
		// non-tenant-scoped one into a fake-atomic operation.
		return fmt.Errorf("transaction: Stage called with a different StorageBackend instance than this transaction's first Stage call — cross-plugin atomicity only works when every participant shares one StorageBackend instance")
	}
	tx.ops = append(tx.ops, ops...)
	return nil
}

func (tx *crossTx) Commit(ctx context.Context) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if tx.done {
		return fmt.Errorf("transaction: Commit called after Commit/Rollback")
	}
	tx.done = true
	if tx.backend == nil || len(tx.ops) == 0 {
		return nil // nothing staged — a no-op commit is not an error
	}
	return tx.backend.Batch(ctx, tx.ops)
}

func (tx *crossTx) Rollback() {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.done = true
	tx.ops = nil
}

var _ api.CrossTx = (*crossTx)(nil)
