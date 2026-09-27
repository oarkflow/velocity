package kv

import (
	"context"

	"github.com/oarkflow/velocity/v2/api"
)

// PutStaged stages a Put as part of a cross-plugin api.CrossTx (see
// plugins/transaction) instead of applying it immediately: the value is
// sealed exactly as Put would seal it, then queued via tx.Stage against
// this plugin's own StorageBackend instance (p.storageFor(ctx), the SAME
// choke point Put/Get already route through — so a tenant-scoped context
// stages against the tenant-scoped decorator, which correctly won't match
// a non-tenant-scoped participant's backend, per CrossTx.Stage's
// documented refusal). The write only actually happens when the caller
// later calls tx.Commit.
//
// This is purely additive: Put/PutWithTTL/Get/etc are completely
// unchanged, and a caller that never touches CrossTx never touches this
// method at all.
func (p *Plugin) PutStaged(ctx context.Context, tx api.CrossTx, key string, value []byte) error {
	if key == "" {
		return ErrEmptyKey
	}
	sealed, err := p.seal(ctx, key, value)
	if err != nil {
		return err
	}
	return tx.Stage(p.storageFor(ctx), []api.BatchOp{
		{Entry: api.Entry{Key: []byte(key), Value: sealed}},
	})
}
