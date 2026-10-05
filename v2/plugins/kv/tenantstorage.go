package kv

import (
	"context"

	"github.com/oarkflow/velocity/v2/api"
)

// tenantScope wraps an api.StorageBackend, transparently prefixing every
// key with "tenant/<id>/" and stripping that prefix back off on read, so
// two different tenants' identical logical keys never collide in the
// underlying backend. Safe by construction: api.ValidTenantID (enforced
// by api.WithTenant/TenantFromContext before this type is ever
// constructed) forbids "/" inside id, so the byte immediately after a
// valid id's prefix must be "/" — one tenant's prefix can therefore never
// be a true byte-prefix of another's, regardless of either tenant's ID or
// key content.
type tenantScope struct {
	backend api.StorageBackend
	prefix  []byte
}

func scopedForTenant(backend api.StorageBackend, tenantID string) api.StorageBackend {
	return &tenantScope{backend: backend, prefix: []byte("tenant/" + tenantID + "/")}
}

func (t *tenantScope) scopeKey(key []byte) []byte {
	out := make([]byte, 0, len(t.prefix)+len(key))
	out = append(out, t.prefix...)
	out = append(out, key...)
	return out
}

func (t *tenantScope) Get(ctx context.Context, key []byte) ([]byte, bool, error) {
	return t.backend.Get(ctx, t.scopeKey(key))
}

func (t *tenantScope) Put(ctx context.Context, e api.Entry) error {
	e.Key = t.scopeKey(e.Key)
	return t.backend.Put(ctx, e)
}

func (t *tenantScope) Delete(ctx context.Context, key []byte) error {
	return t.backend.Delete(ctx, t.scopeKey(key))
}

func (t *tenantScope) Batch(ctx context.Context, ops []api.BatchOp) error {
	scoped := make([]api.BatchOp, len(ops))
	for i, op := range ops {
		op.Entry.Key = t.scopeKey(op.Entry.Key)
		scoped[i] = op
	}
	return t.backend.Batch(ctx, scoped)
}

func (t *tenantScope) Scan(ctx context.Context, prefix []byte) (api.Iterator, error) {
	it, err := t.backend.Scan(ctx, t.scopeKey(prefix))
	if err != nil {
		return nil, err
	}
	return &tenantIterator{it: it, stripLen: len(t.prefix)}, nil
}

// ScanFrom forwards api.RangedScanner so a tenant-scoped paginated walk keeps
// the O(n) resume behavior: both the prefix and the start key are scoped
// identically, and tenantIterator strips the prefix back off for the caller.
// Deliberately NOT declared when the wrapped backend isn't a RangedScanner —
// the type assertion in kv.Scan then falls back to skipping forward.
func (t *tenantScope) ScanFrom(ctx context.Context, prefix, startKey []byte, maxKeys int) (api.Iterator, error) {
	rs, ok := t.backend.(api.RangedScanner)
	if !ok {
		return nil, api.ErrRangeUnsupported
	}
	it, err := rs.ScanFrom(ctx, t.scopeKey(prefix), t.scopeKey(startKey), maxKeys)
	if err != nil {
		return nil, err
	}
	return &tenantIterator{it: it, stripLen: len(t.prefix)}, nil
}

func (t *tenantScope) Snapshot(ctx context.Context) (api.Snapshot, error) {
	snap, err := t.backend.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	return &tenantSnapshot{snap: snap, prefix: t.prefix}, nil
}

// Close is a no-op: tenantScope never owns the underlying backend (many
// tenants, and the no-tenant path, all share one real StorageBackend
// instance owned by whichever storage-* plugin provided it) — only that
// plugin's own Stop() may actually close it.
func (t *tenantScope) Close() error { return nil }

var _ api.StorageBackend = (*tenantScope)(nil)

type tenantIterator struct {
	it       api.Iterator
	stripLen int
}

func (i *tenantIterator) Next() bool    { return i.it.Next() }
func (i *tenantIterator) Key() []byte   { return i.it.Key()[i.stripLen:] }
func (i *tenantIterator) Value() []byte { return i.it.Value() }
func (i *tenantIterator) Err() error    { return i.it.Err() }
func (i *tenantIterator) Close() error  { return i.it.Close() }

var _ api.Iterator = (*tenantIterator)(nil)

type tenantSnapshot struct {
	snap   api.Snapshot
	prefix []byte
}

func (s *tenantSnapshot) Get(key []byte) ([]byte, bool, error) {
	scoped := make([]byte, 0, len(s.prefix)+len(key))
	scoped = append(scoped, s.prefix...)
	scoped = append(scoped, key...)
	return s.snap.Get(scoped)
}

func (s *tenantSnapshot) Release() { s.snap.Release() }

var _ api.Snapshot = (*tenantSnapshot)(nil)

// storageFor returns the StorageBackend this call should use: tenant-
// scoped if ctx carries a (necessarily valid — see api.WithTenant) tenant
// ID, the shared/global backend otherwise. This is the single choke point
// every exported method routes storage access through, so tenant
// isolation can't be accidentally bypassed by a call site that forgot to
// check.
func (p *Plugin) storageFor(ctx context.Context) api.StorageBackend {
	if id, ok := api.TenantFromContext(ctx); ok {
		return scopedForTenant(p.storage, id)
	}
	return p.storage
}
