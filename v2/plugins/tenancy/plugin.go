// Package tenancy implements Velocity v2's "tenancy" plugin:
// api.TenantService — tenant lifecycle, quota management, and usage
// reporting. It does NOT itself enforce key isolation between tenants;
// that's done directly by plugins/kv and plugins/object (see their
// tenantstorage.go), which prefix every storage key with
// "tenant/<id>/" whenever api.TenantFromContext finds one in the
// request context, independent of whether this plugin is even enabled.
// This plugin adds the OPTIONAL layer on top: quota enforcement (kv looks
// it up, if registered) and operator-facing tenant management
// (CreateTenant/DeleteTenant/Usage/ListTenants) without needing to know
// kv/object's internal key layout — Usage/DeleteTenant work by scanning
// the SAME "tenant/<id>/" prefix on the shared storage backend that
// kv/object write under.
package tenancy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/oarkflow/velocity/v2/api"
)

const pluginName = "tenancy"

// ServiceName is the fixed Registry name this plugin provides its
// api.TenantService under.
const ServiceName = pluginName

func metaKey(id string) string { return "tenancy/meta/" + id }

// dataPrefix is the SAME prefix scheme plugins/kv and plugins/object use
// in their own tenantScope wrappers ("tenant/<id>/") — Usage/DeleteTenant
// scan this prefix directly on the shared storage backend rather than
// asking kv/object, since both already write everything a tenant owns
// under exactly this prefix regardless of which plugin wrote it.
func dataPrefix(id string) string { return "tenant/" + id + "/" }

type tenantMeta struct {
	Quota api.TenantQuota `json:"quota"`
}

// Plugin implements api.Plugin and api.TenantService.
type Plugin struct {
	storageDep string
	storage    api.StorageBackend
}

// NewPlugin constructs the tenancy plugin. storageDep names the storage
// plugin this one depends on for boot ordering (NOT the service-lookup
// name, which is always the fixed "storage"); it defaults to
// "storage-lsm" when empty.
func NewPlugin(storageDep string) *Plugin {
	if storageDep == "" {
		storageDep = "storage-lsm"
	}
	return &Plugin{storageDep: storageDep}
}

func (p *Plugin) Name() string           { return pluginName }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return []string{p.storageDep} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.storage = k.Registry().MustLookup("storage").(api.StorageBackend)
	return k.Registry().Provide(ServiceName, api.TenantService(p))
}

func (p *Plugin) Start(context.Context) error { return nil }
func (p *Plugin) Stop(context.Context) error  { return nil }
func (p *Plugin) Health() api.Health          { return api.Health{Status: "ok"} }

func (p *Plugin) CreateTenant(ctx context.Context, id string, quota api.TenantQuota) error {
	if !api.ValidTenantID(id) {
		return fmt.Errorf("tenancy: invalid tenant id %q (must be non-empty and not contain '/')", id)
	}
	buf, err := json.Marshal(tenantMeta{Quota: quota})
	if err != nil {
		return err
	}
	return p.storage.Put(ctx, api.Entry{Key: []byte(metaKey(id)), Value: buf})
}

func (p *Plugin) DeleteTenant(ctx context.Context, id string) error {
	if !api.ValidTenantID(id) {
		return fmt.Errorf("tenancy: invalid tenant id %q", id)
	}

	it, err := p.storage.Scan(ctx, []byte(dataPrefix(id)))
	if err != nil {
		return err
	}
	var ops []api.BatchOp
	for it.Next() {
		k := make([]byte, len(it.Key()))
		copy(k, it.Key())
		ops = append(ops, api.BatchOp{Delete: true, Entry: api.Entry{Key: k}})
	}
	if err := it.Err(); err != nil {
		it.Close()
		return err
	}
	it.Close()

	ops = append(ops, api.BatchOp{Delete: true, Entry: api.Entry{Key: []byte(metaKey(id))}})
	return p.storage.Batch(ctx, ops)
}

func (p *Plugin) GetQuota(ctx context.Context, id string) (api.TenantQuota, bool, error) {
	buf, ok, err := p.storage.Get(ctx, []byte(metaKey(id)))
	if err != nil || !ok {
		return api.TenantQuota{}, ok, err
	}
	var m tenantMeta
	if err := json.Unmarshal(buf, &m); err != nil {
		return api.TenantQuota{}, false, fmt.Errorf("tenancy: corrupt metadata for tenant %q: %w", id, err)
	}
	return m.Quota, true, nil
}

func (p *Plugin) SetQuota(ctx context.Context, id string, quota api.TenantQuota) error {
	if !api.ValidTenantID(id) {
		return fmt.Errorf("tenancy: invalid tenant id %q", id)
	}
	buf, err := json.Marshal(tenantMeta{Quota: quota})
	if err != nil {
		return err
	}
	return p.storage.Put(ctx, api.Entry{Key: []byte(metaKey(id)), Value: buf})
}

func (p *Plugin) Usage(ctx context.Context, id string) (int64, int64, error) {
	it, err := p.storage.Scan(ctx, []byte(dataPrefix(id)))
	if err != nil {
		return 0, 0, err
	}
	defer it.Close()

	var keys, bytesTotal int64
	for it.Next() {
		keys++
		bytesTotal += int64(len(it.Value()))
	}
	return keys, bytesTotal, it.Err()
}

func (p *Plugin) ListTenants(ctx context.Context) ([]string, error) {
	it, err := p.storage.Scan(ctx, []byte("tenancy/meta/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()

	var out []string
	for it.Next() {
		id := string(it.Key())[len("tenancy/meta/"):]
		out = append(out, id)
	}
	return out, it.Err()
}

var (
	_ api.Plugin        = (*Plugin)(nil)
	_ api.TenantService = (*Plugin)(nil)
)
