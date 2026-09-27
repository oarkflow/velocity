package api

import (
	"context"
	"strings"
)

// tenantContextKey is unexported, so the ONLY way any code outside this
// package can attach a tenant ID to a context is through WithTenant below
// — this is what lets TenantFromContext guarantee every tenant ID it
// returns already passed ValidTenantID, without needing every consumer
// (kv, object, ...) to separately re-validate or handle an "invalid
// tenant in context" error case at every call site.
type tenantContextKey struct{}

// ValidTenantID reports whether id is safe to use as a tenant key-prefix
// component: non-empty and free of "/". kv/object build a per-tenant
// storage prefix as "tenant/<id>/<key>"; forbidding "/" inside id is what
// makes that boundary unambiguous — the byte immediately after a valid
// id must be "/", so one tenant's prefix can never be a true byte-prefix
// of another's, regardless of what either tenant's ID or key CONTENT is
// (including content deliberately crafted to look like "../other-tenant/
// ..." — that's just ordinary key bytes to a byte-string keyspace, not a
// filesystem path, so there is nothing to traverse).
func ValidTenantID(id string) bool {
	return id != "" && !strings.Contains(id, "/")
}

// WithTenant returns a context scoped to tenantID for any tenant-aware
// service (kv, object) looked up and used with it. If tenantID fails
// ValidTenantID, WithTenant does NOT attach it — ctx is returned
// unchanged, so a subsequent TenantFromContext(ctx) reports "no tenant"
// rather than an ambiguous or unsafe one. Callers that need to detect
// this (e.g. to reject a request with a bad tenant ID rather than
// silently falling back to the global, non-tenant-isolated keyspace)
// should call ValidTenantID themselves before calling WithTenant, or
// call TenantFromContext immediately after to confirm it took.
func WithTenant(ctx context.Context, tenantID string) context.Context {
	if !ValidTenantID(tenantID) {
		return ctx
	}
	return context.WithValue(ctx, tenantContextKey{}, tenantID)
}

// TenantFromContext returns the tenant ID attached via WithTenant, if
// any. Every ID it returns has already passed ValidTenantID.
func TenantFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(tenantContextKey{}).(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// TenantQuota bounds one tenant's resource usage. Zero means unlimited
// for that dimension.
type TenantQuota struct {
	MaxKeys  int64
	MaxBytes int64
}

// TenantService is the surface plugins/tenancy exposes: tenant
// lifecycle, quota management, and usage reporting. Service name:
// "tenancy" -> api.TenantService.
//
// TenantService itself does not enforce isolation — kv/object do that
// directly (see their own doc comments) by prefixing every storage key
// with the tenant ID found via TenantFromContext, independent of whether
// a TenantService is even registered. TenantService adds the OPTIONAL
// quota layer on top: kv looks it up (if registered) to enforce
// MaxKeys/MaxBytes on writes, and Usage/DeleteTenant/ListTenants give an
// operator a way to manage tenants without needing to know kv/object's
// internal key layout.
type TenantService interface {
	CreateTenant(ctx context.Context, id string, quota TenantQuota) error
	// DeleteTenant removes the tenant's quota record AND every key any
	// tenant-aware plugin (kv, object) stored under its prefix.
	DeleteTenant(ctx context.Context, id string) error
	GetQuota(ctx context.Context, id string) (TenantQuota, bool, error)
	SetQuota(ctx context.Context, id string, quota TenantQuota) error
	// Usage reports the tenant's current key count and total value bytes
	// across every tenant-aware plugin sharing the same storage backend.
	Usage(ctx context.Context, id string) (keys int64, bytes int64, err error)
	ListTenants(ctx context.Context) ([]string, error)
}
