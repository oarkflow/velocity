package api

import "context"

// CrossTx collects writes staged by multiple participating plugins and
// applies them atomically, in one real StorageBackend.Batch call, on
// Commit. This is deliberately NOT a generic multi-service two-phase-
// commit protocol — that would be a much larger, riskier undertaking.
// The honest scope: cross-plugin atomicity is real and achievable when
// every participant resolves to the SAME StorageBackend instance (the
// common case — kv/object/sql/secret/etc all resolve to one "storage"
// service unless a manifest deliberately splits them, or a tenant-scoped
// context wraps it in a per-tenant decorator — see Stage). A participant
// backed by a DIFFERENT instance is refused at Stage time, never silently
// combined into a fake-atomic operation.
type CrossTx interface {
	// Stage queues ops to be applied atomically on Commit, tagged with
	// the exact StorageBackend instance they're meant for. The first
	// Stage call on a given CrossTx establishes that transaction's
	// reference backend (via Go interface equality — the concrete
	// pointer must match, not just the type); every subsequent Stage call
	// passing a DIFFERENT backend instance is refused with a clear error,
	// rather than being applied non-atomically or silently dropped.
	Stage(backend StorageBackend, ops []BatchOp) error

	// Commit applies every staged op, across every Stage call, in ONE
	// StorageBackend.Batch call against the transaction's reference
	// backend. If that Batch call fails, NONE of the staged ops take
	// effect — Commit does not partially apply what was staged.
	Commit(ctx context.Context) error

	// Rollback discards everything staged without applying any of it.
	// Equivalent to simply never calling Commit, provided as an explicit,
	// self-documenting call for callers that want to state their intent.
	Rollback()
}

// TxCoordinator is the service a plugin looks up (service name
// "transaction") to begin a CrossTx.
type TxCoordinator interface {
	Begin(ctx context.Context) (CrossTx, error)
}
