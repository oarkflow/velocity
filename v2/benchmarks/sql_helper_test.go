package benchmarks

import (
	"context"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	"github.com/oarkflow/velocity/v2/plugins/sql"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

// bootSQL boots storage-lsm + kv + sql. Kept in its own file (separate
// from helpers_test.go) so the plugins/sql import can be excluded on its
// own if that package is mid-edit, without losing every other benchmark.
func bootSQL(b *testing.B) (api.SQLEngine, func()) {
	b.Helper()
	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": b.TempDir()}},
		{Name: "kv", Enabled: true},
		{Name: "sql", Enabled: true},
	}}
	k := kernel.New(manifest)
	all := []api.Plugin{storagelsm.New(), kv.New("storage-lsm"), sql.NewPlugin("kv")}
	ctx := context.Background()
	if err := k.Boot(ctx, all, manifest.Enabled()); err != nil {
		b.Fatalf("boot: %v", err)
	}
	svc, ok := k.Registry().Lookup("sql")
	if !ok {
		b.Fatalf("sql service not registered")
	}
	return svc.(api.SQLEngine), func() { _ = k.Shutdown(ctx) }
}
