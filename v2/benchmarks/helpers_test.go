// Package benchmarks holds Go benchmark tests for Velocity v2's plugins,
// run in-process against real plugin implementations (booted through the
// same kernel used in production, not hand-rolled shortcuts). See
// RESULTS.md for the last captured run.
package benchmarks

import (
	"context"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	cryptofips "github.com/oarkflow/velocity/v2/plugins/crypto-fips"
	cryptoxchacha "github.com/oarkflow/velocity/v2/plugins/crypto-xchacha"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	"github.com/oarkflow/velocity/v2/plugins/object"
	"github.com/oarkflow/velocity/v2/plugins/search"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
	storagemem "github.com/oarkflow/velocity/v2/plugins/storage-mem"
)

// bootKV boots a kernel with the given storage backend plugin name enabled
// ("storage-lsm" or "storage-mem") plus kv, and returns the live
// api.KVService and a cleanup func.
func bootKV(b *testing.B, storageName string) (api.KVService, func()) {
	b.Helper()
	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: storageName, Enabled: true, Config: map[string]any{"dir": b.TempDir()}},
		{Name: "kv", Enabled: true},
	}}
	k := kernel.New(manifest)
	all := []api.Plugin{storagelsm.New(), storagemem.New(), kv.New(storageName)}
	ctx := context.Background()
	if err := k.Boot(ctx, all, manifest.Enabled()); err != nil {
		b.Fatalf("boot: %v", err)
	}
	svc, ok := k.Registry().Lookup("kv")
	if !ok {
		b.Fatalf("kv service not registered")
	}
	return svc.(api.KVService), func() { _ = k.Shutdown(ctx) }
}

// bootObject boots storage-lsm + object.
func bootObject(b *testing.B) (api.ObjectService, func()) {
	b.Helper()
	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": b.TempDir()}},
		{Name: "object", Enabled: true},
	}}
	k := kernel.New(manifest)
	all := []api.Plugin{storagelsm.New(), object.New("storage-lsm")}
	ctx := context.Background()
	if err := k.Boot(ctx, all, manifest.Enabled()); err != nil {
		b.Fatalf("boot: %v", err)
	}
	svc, ok := k.Registry().Lookup("object")
	if !ok {
		b.Fatalf("object service not registered")
	}
	return svc.(api.ObjectService), func() { _ = k.Shutdown(ctx) }
}

// bootSearch boots storage-lsm + kv + search, returning the fulltext and
// vector services.
func bootSearch(b *testing.B) (api.SearchIndex, api.VectorIndex, func()) {
	b.Helper()
	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": b.TempDir()}},
		{Name: "kv", Enabled: true},
		{Name: "search", Enabled: true, Config: map[string]any{"vector_dimension": 12}},
	}}
	k := kernel.New(manifest)
	all := []api.Plugin{storagelsm.New(), kv.New("storage-lsm"), search.NewPlugin("kv")}
	ctx := context.Background()
	if err := k.Boot(ctx, all, manifest.Enabled()); err != nil {
		b.Fatalf("boot: %v", err)
	}
	ft, ok := k.Registry().Lookup("search.fulltext")
	if !ok {
		b.Fatalf("search.fulltext not registered")
	}
	vec, ok := k.Registry().Lookup("search.vector")
	if !ok {
		b.Fatalf("search.vector not registered")
	}
	return ft.(api.SearchIndex), vec.(api.VectorIndex), func() { _ = k.Shutdown(ctx) }
}

// bootCrypto boots the named crypto plugin ("crypto-xchacha" or
// "crypto-fips") standalone.
func bootCrypto(b *testing.B, name string) (api.CryptoProvider, func()) {
	b.Helper()
	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		// 32 raw bytes, base64-encoded — both crypto plugins require an
		// exact 32-byte key (raw/base64/hex); this is a fixed benchmark-only
		// key, never use it for anything real.
		{Name: name, Enabled: true, Config: map[string]any{"key": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}},
	}}
	k := kernel.New(manifest)
	all := []api.Plugin{cryptoxchacha.New(), cryptofips.New()}
	ctx := context.Background()
	if err := k.Boot(ctx, all, manifest.Enabled()); err != nil {
		b.Fatalf("boot: %v", err)
	}
	svc, ok := k.Registry().Lookup("crypto")
	if !ok {
		b.Fatalf("crypto service not registered")
	}
	return svc.(api.CryptoProvider), func() { _ = k.Shutdown(ctx) }
}
