//go:build destructive

package velocity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type destructiveManifest struct {
	Mode    string            `json:"mode"`
	Relaxed bool              `json:"relaxed"`
	Rows    map[string]string `json:"rows"`
}

func TestDestructiveChildProcess(t *testing.T) {
	if os.Getenv("VELOCITY_DESTRUCTIVE_CHILD") != "1" {
		t.Skip("helper process only")
	}
	mode := os.Getenv("VELOCITY_DESTRUCTIVE_MODE")
	path := os.Getenv("VELOCITY_DESTRUCTIVE_PATH")
	manifest := os.Getenv("VELOCITY_DESTRUCTIVE_MANIFEST")
	perfMode := os.Getenv("VELOCITY_DESTRUCTIVE_PERF")
	iterations := destructiveIterations(120)
	if raw := os.Getenv("VELOCITY_DESTRUCTIVE_ITER"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			iterations = n
		}
	}
	cfg := Config{Path: path, MasterKey: productionTestKey('x'), PerformanceMode: perfMode}
	if os.Getenv("VELOCITY_DESTRUCTIVE_DISABLE_FSYNC") == "1" {
		cfg.DisableFsync = true
	}
	if os.Getenv("VELOCITY_DESTRUCTIVE_INDEX") == "1" {
		cfg.SearchSchemas = map[string]*SearchSchema{
			"doc": {
				Fields: []SearchSchemaField{
					{Name: "kind", HashSearch: true},
					{Name: "n", ValueIndex: true},
				},
			},
		}
	}
	db, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("child open failed: %v", err)
	}
	defer db.Close()

	switch mode {
	case "strict-put", "relaxed-put":
		runDestructivePutChild(t, db, manifest, mode, mode == "relaxed-put", iterations)
	case "batch-flush":
		runDestructiveBatchFlushChild(t, db, manifest, iterations)
	case "indexed-relaxed":
		runDestructiveIndexedChild(t, db, manifest, iterations)
	default:
		t.Fatalf("unknown destructive child mode %q", mode)
	}
	select {}
}

func TestDestructiveStrictDurabilityCrashMatrix(t *testing.T) {
	for _, perfMode := range []string{"", "balanced", "aggressive"} {
		name := perfMode
		if name == "" {
			name = "default"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "strict_"+name)
			manifest := filepath.Join(path, "manifest.json")
			runAndKillDestructiveChild(t, path, manifest, map[string]string{
				"VELOCITY_DESTRUCTIVE_MODE": "strict-put",
				"VELOCITY_DESTRUCTIVE_PERF": perfMode,
			}, 40)
			verifyStrictManifest(t, path, manifest)
		})
	}
}

func TestDestructiveBatchFlushCrashRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "batch_flush")
	manifest := filepath.Join(path, "manifest.json")
	runAndKillDestructiveChild(t, path, manifest, map[string]string{
		"VELOCITY_DESTRUCTIVE_MODE": "batch-flush",
	}, 30)
	verifyStrictManifest(t, path, manifest)
	if _, err := os.Stat(filepath.Join(path, flushCheckpointName)); err == nil {
		t.Fatalf("flush checkpoint survived clean recovery")
	}
}

func TestDestructiveRelaxedDurabilityCrashMatrix(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "performance",
			env: map[string]string{
				"VELOCITY_DESTRUCTIVE_MODE":  "relaxed-put",
				"VELOCITY_DESTRUCTIVE_PERF":  "performance",
				"VELOCITY_DESTRUCTIVE_INDEX": "1",
			},
		},
		{
			name: "disable_fsync",
			env: map[string]string{
				"VELOCITY_DESTRUCTIVE_MODE":          "indexed-relaxed",
				"VELOCITY_DESTRUCTIVE_DISABLE_FSYNC": "1",
				"VELOCITY_DESTRUCTIVE_INDEX":         "1",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.name)
			manifest := filepath.Join(path, "manifest.json")
			runAndKillDestructiveChild(t, path, manifest, tc.env, 30)
			verifyRelaxedManifest(t, path, manifest, true)
		})
	}
}

func TestDestructiveCorruptionMatrix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corruption")
	key := productionTestKey('x')
	db, err := NewWithConfig(Config{Path: path, MasterKey: key})
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if err := db.Put([]byte("corrupt:key"), []byte("known-good")); err != nil {
		t.Fatalf("put failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	files, err := filepath.Glob(filepath.Join(path, "sst_*.db"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("expected SSTable")
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if len(data) < 32 {
		t.Fatalf("sstable too small")
	}
	data[len(data)-16] ^= 0xff
	if err := os.WriteFile(files[0], data, 0o600); err != nil {
		t.Fatalf("corrupt write failed: %v", err)
	}
	reopened, err := NewWithConfig(Config{Path: path, MasterKey: key})
	if err != nil {
		t.Fatalf("reopen after corruption failed: %v", err)
	}
	defer reopened.Close()
	got, err := reopened.Get([]byte("corrupt:key"))
	if err == nil && !bytes.Equal(got, []byte("known-good")) {
		t.Fatalf("returned forged corrupted value %q", got)
	}
}

func runDestructivePutChild(t *testing.T, db *DB, manifestPath, mode string, relaxed bool, iterations int) {
	t.Helper()
	m := destructiveManifest{Mode: mode, Relaxed: relaxed, Rows: make(map[string]string)}
	for i := 0; i < iterations; i++ {
		key := fmt.Sprintf("kv:%04d", i)
		value := fmt.Sprintf("value:%04d", i)
		if err := db.Put([]byte(key), []byte(value)); err != nil {
			t.Fatalf("put failed: %v", err)
		}
		m.Rows[key] = value
		writeDestructiveManifest(t, manifestPath, m)
		time.Sleep(5 * time.Millisecond)
	}
}

func runDestructiveBatchFlushChild(t *testing.T, db *DB, manifestPath string, iterations int) {
	t.Helper()
	db.memTableSize = 1024
	m := destructiveManifest{Mode: "batch-flush", Rows: make(map[string]string)}
	batchSize := 8
	for start := 0; start < iterations; start += batchSize {
		bw := db.NewBatchWriter(batchSize)
		limit := start + batchSize
		if limit > iterations {
			limit = iterations
		}
		for i := start; i < limit; i++ {
			key := fmt.Sprintf("batch:%04d", i)
			value := fmt.Sprintf("value:%04d", i)
			if err := bw.Put([]byte(key), []byte(value)); err != nil {
				t.Fatalf("batch put failed: %v", err)
			}
			m.Rows[key] = value
		}
		if err := bw.Flush(); err != nil {
			t.Fatalf("batch flush failed: %v", err)
		}
		if err := db.flushMemTable(); err != nil {
			t.Fatalf("memtable flush failed: %v", err)
		}
		writeDestructiveManifest(t, manifestPath, m)
		time.Sleep(5 * time.Millisecond)
	}
}

func runDestructiveIndexedChild(t *testing.T, db *DB, manifestPath string, iterations int) {
	t.Helper()
	m := destructiveManifest{Mode: "indexed-relaxed", Relaxed: true, Rows: make(map[string]string)}
	for i := 0; i < iterations; i++ {
		key := fmt.Sprintf("doc:%04d", i)
		value := fmt.Sprintf(`{"kind":"destructive","n":%d}`, i)
		if err := db.Put([]byte(key), []byte(value)); err != nil {
			t.Fatalf("indexed put failed: %v", err)
		}
		m.Rows[key] = value
		writeDestructiveManifest(t, manifestPath, m)
		time.Sleep(5 * time.Millisecond)
	}
}

func runAndKillDestructiveChild(t *testing.T, path, manifest string, childEnv map[string]string, minManifestRows int) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestDestructiveChildProcess$", "-test.v")
	cmd.Env = append(os.Environ(),
		"VELOCITY_DESTRUCTIVE_CHILD=1",
		"VELOCITY_DESTRUCTIVE_PATH="+path,
		"VELOCITY_DESTRUCTIVE_MANIFEST="+manifest,
		"VELOCITY_DESTRUCTIVE_ITER="+strconv.Itoa(destructiveIterations(160)),
	)
	for k, v := range childEnv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child failed: %v", err)
	}
	waitForManifestRows(t, ctx, manifest, minManifestRows)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill child failed: %v", err)
	}
	_ = cmd.Wait()
}

func verifyStrictManifest(t *testing.T, path, manifestPath string) {
	t.Helper()
	m := readDestructiveManifest(t, manifestPath)
	db, err := NewWithConfig(Config{Path: path, MasterKey: productionTestKey('x')})
	if err != nil {
		t.Fatalf("strict reopen failed: %v", err)
	}
	defer db.Close()
	for key, want := range m.Rows {
		got, err := db.Get([]byte(key))
		if err != nil {
			t.Fatalf("acknowledged key %s missing after crash: %v", key, err)
		}
		if string(got) != want {
			t.Fatalf("key %s = %q, want %q", key, got, want)
		}
	}
}

func verifyRelaxedManifest(t *testing.T, path, manifestPath string, verifyIndex bool) {
	t.Helper()
	m := readDestructiveManifest(t, manifestPath)
	db, err := NewWithConfig(Config{
		Path:      path,
		MasterKey: productionTestKey('x'),
		SearchSchemas: map[string]*SearchSchema{
			"doc": {
				Fields: []SearchSchemaField{
					{Name: "kind", HashSearch: true},
					{Name: "n", ValueIndex: true},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("relaxed reopen failed: %v", err)
	}
	defer db.Close()
	for key, want := range m.Rows {
		got, err := db.Get([]byte(key))
		if err != nil {
			continue
		}
		if string(got) != want {
			t.Fatalf("relaxed mode returned corrupted value for %s: got %q want %q", key, got, want)
		}
	}
	if verifyIndex {
		schema := &SearchSchema{Fields: []SearchSchemaField{{Name: "kind", HashSearch: true}, {Name: "n", ValueIndex: true}}}
		if err := db.RebuildIndex("doc", schema, &RebuildOptions{BatchSize: 32, NoWAL: true}); err != nil {
			t.Fatalf("index rebuild after crash failed: %v", err)
		}
		if _, err := db.Search(SearchQuery{
			Prefix: "doc",
			Filters: []SearchFilter{{
				Field:    "kind",
				Op:       "==",
				Value:    "destructive",
				HashOnly: true,
			}},
			Limit: 10,
		}); err != nil {
			t.Fatalf("search after crash/rebuild failed: %v", err)
		}
	}
}

func writeDestructiveManifest(t *testing.T, path string, m destructiveManifest) {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest failed: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir manifest dir failed: %v", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatalf("write manifest failed: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename manifest failed: %v", err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		t.Fatalf("sync manifest dir failed: %v", err)
	}
}

func readDestructiveManifest(t *testing.T, path string) destructiveManifest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest failed: %v", err)
	}
	var m destructiveManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal manifest failed: %v", err)
	}
	if len(m.Rows) == 0 {
		t.Fatalf("manifest has no acknowledged rows")
	}
	return m
}

func waitForManifestRows(t *testing.T, ctx context.Context, path string, minRows int) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for manifest rows: %v", ctx.Err())
		case <-ticker.C:
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var m destructiveManifest
			if json.Unmarshal(data, &m) == nil && len(m.Rows) >= minRows {
				return
			}
		}
	}
}

func destructiveIterations(defaultValue int) int {
	if raw := os.Getenv("VELOCITY_DESTRUCTIVE_SOAK_ITERS"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			return n
		}
	}
	return defaultValue
}
