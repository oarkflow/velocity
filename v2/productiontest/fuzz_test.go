package productiontest

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	sqlplugin "github.com/oarkflow/velocity/v2/plugins/sql"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
	storagemem "github.com/oarkflow/velocity/v2/plugins/storage-mem"
)

// FuzzWALRecovery feeds arbitrary byte sequences into a storage-lsm data
// directory's wal.log and confirms Open() never panics — it must always
// either replay correctly or return a clean error, treating a malformed
// file as "torn/corrupt," never crashing the process. This exercises the
// WAL record parser (readRecord/replayWAL, unexported) through its only
// reachable public boundary from outside the package.
func FuzzWALRecovery(f *testing.F) {
	// Seed corpus: empty, a single zero byte, a plausible-looking but
	// truncated header, and a real valid record (written via the normal
	// API) so the fuzzer starts from something structurally close to
	// valid input, not just noise.
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03})
	f.Add(func() []byte {
		dir, err := os.MkdirTemp("", "fuzzseed")
		if err != nil {
			return nil
		}
		defer os.RemoveAll(dir)
		eng, err := storagelsm.Open(dir, true)
		if err != nil {
			return nil
		}
		_ = eng.Put(context.Background(), api.Entry{Key: []byte("seed"), Value: []byte("value")})
		b, _ := os.ReadFile(filepath.Join(dir, "wal.log"))
		return b
	}())

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "wal.log"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("storagelsm.Open PANICKED on malformed WAL data (%d bytes): %v", len(data), r)
			}
		}()
		eng, err := storagelsm.Open(dir, true)
		if err != nil {
			return // a clean error on malformed input is the correct, expected outcome
		}
		defer eng.Close()
		// If it opened, every subsequent operation must also stay panic-free.
		_, _, _ = eng.Get(context.Background(), []byte("anything"))
	})
}

// sqlEngineForFuzz boots a minimal real kernel (storage-mem + kv) and
// returns a *sqlplugin.Engine backed by the real kv.Plugin — the same
// construction path production code uses, not a stub.
func sqlEngineForFuzz(t testing.TB) *sqlplugin.Engine {
	t.Helper()
	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-mem", Enabled: true},
		{Name: "kv", Enabled: true},
	}}
	k := kernel.New(manifest)
	plugins := []api.Plugin{storagemem.New(), kv.New("storage-mem")}
	ctx := context.Background()
	if err := k.Boot(ctx, plugins, manifest.Enabled()); err != nil {
		t.Fatalf("boot: %v", err)
	}
	kvSvc := k.Registry().MustLookup("kv").(api.KVService)
	return sqlplugin.NewEngine(kvSvc)
}

// FuzzSQLParser feeds arbitrary strings into Engine.Exec/Query and
// confirms neither ever panics on malformed SQL — always either executes
// correctly or returns a clean parse/execution error.
func FuzzSQLParser(f *testing.F) {
	f.Add("SELECT * FROM t")
	f.Add("CREATE TABLE t (id INT PRIMARY KEY, name TEXT)")
	f.Add("INSERT INTO t (id, name) VALUES (1, 'a')")
	f.Add("SELECT * FROM t WHERE id = 1 AND (")
	f.Add("'; DROP TABLE t; --")
	f.Add("")
	f.Add("SELECT")
	f.Add("SELECT * FROM t JOIN")

	engine := sqlEngineForFuzz(f)
	f.Fuzz(func(t *testing.T, query string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("SQL engine PANICKED on input %q: %v", query, r)
			}
		}()
		ctx := context.Background()
		_, _ = engine.Exec(ctx, query)
		_, _ = engine.Query(ctx, query)
	})
}
