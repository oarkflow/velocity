package kernel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oarkflow/bcl"

	"github.com/oarkflow/velocity/v2/api"
)

// stubPlugin is a minimal, instrumented api.Plugin for testing Boot/
// Reload without depending on any real plugin. Its service name (for
// Registry.Provide/Lookup) is always its own Name(), which is enough to
// exercise dependency ordering and stale-reference-avoidance in tests.
type stubPlugin struct {
	name     string
	deps     []string
	optDeps  []string
	failInit bool

	initCount, startCount, stopCount int
	lastConfig                       map[string]any
}

func (s *stubPlugin) Name() string                   { return s.name }
func (s *stubPlugin) Version() string                { return "0.0.1" }
func (s *stubPlugin) Dependencies() []string         { return s.deps }
func (s *stubPlugin) OptionalDependencies() []string { return s.optDeps }

func (s *stubPlugin) Init(ctx context.Context, k api.Kernel) error {
	s.initCount++
	s.lastConfig = k.Config().Scoped(s.name).Raw()
	if s.failInit {
		return errAssert("stub init failure")
	}
	if err := k.Registry().Provide(s.name, s); err != nil {
		return err
	}
	for _, d := range s.deps {
		k.Registry().MustLookup(d) // proves the dependency booted first
	}
	return nil
}

func (s *stubPlugin) Start(ctx context.Context) error { s.startCount++; return nil }
func (s *stubPlugin) Stop(ctx context.Context) error  { s.stopCount++; return nil }
func (s *stubPlugin) Health() api.Health              { return api.Health{Status: "ok"} }

var _ api.Plugin = (*stubPlugin)(nil)
var _ api.PluginWithOptionalDependencies = (*stubPlugin)(nil)

type errAssert string

func (e errAssert) Error() string { return string(e) }

func manifestFor(specs ...PluginSpec) Manifest { return Manifest{Plugins: specs} }

func spec(name string, enabled bool, cfg map[string]any) PluginSpec {
	return PluginSpec{Name: name, Enabled: enabled, Config: cfg}
}

// 1. Reload enabling one MORE plugin: the new one boots, previously
// running ones are untouched (InitCount unchanged).
func TestReload_AddsNewPluginWithoutTouchingExisting(t *testing.T) {
	a := &stubPlugin{name: "a"}
	b := &stubPlugin{name: "b"}
	all := []api.Plugin{a, b}

	k := New(manifestFor(spec("a", true, nil)))
	if err := k.Boot(context.Background(), all, k.Manifest().Enabled()); err != nil {
		t.Fatalf("Boot: %v", err)
	}
	if a.initCount != 1 || a.startCount != 1 {
		t.Fatalf("a not booted correctly: init=%d start=%d", a.initCount, a.startCount)
	}

	newManifest := manifestFor(spec("a", true, nil), spec("b", true, nil))
	if err := k.Reload(context.Background(), newManifest, all); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if b.initCount != 1 || b.startCount != 1 {
		t.Fatalf("b not started by reload: init=%d start=%d", b.initCount, b.startCount)
	}
	if a.initCount != 1 || a.startCount != 1 {
		t.Fatalf("a was touched by reload (should be untouched): init=%d start=%d", a.initCount, a.startCount)
	}
}

// 2. Reload disabling a previously-enabled plugin: it's Stopped and no
// longer in the registry/health report.
func TestReload_RemovesDisabledPlugin(t *testing.T) {
	a := &stubPlugin{name: "a"}
	b := &stubPlugin{name: "b"}
	all := []api.Plugin{a, b}

	k := New(manifestFor(spec("a", true, nil), spec("b", true, nil)))
	if err := k.Boot(context.Background(), all, k.Manifest().Enabled()); err != nil {
		t.Fatalf("Boot: %v", err)
	}

	newManifest := manifestFor(spec("a", true, nil), spec("b", false, nil))
	if err := k.Reload(context.Background(), newManifest, all); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if b.stopCount != 1 {
		t.Fatalf("b.Stop not called: stopCount=%d", b.stopCount)
	}
	if _, ok := k.Health()["b"]; ok {
		t.Fatalf("b still present in Health() after removal")
	}
	if _, ok := k.reg.Lookup("b"); ok {
		t.Fatalf("b's service still registered after removal")
	}
}

// 3. Reload with a malformed manifest (simulated here as an invalid
// dependency graph, since Reload itself takes an already-parsed
// Manifest — the JSON-parse-failure case is covered separately against
// LoadManifestBCL) keeps the OLD configuration untouched.
func TestReload_InvalidManifestKeepsOldConfigRunning(t *testing.T) {
	a := &stubPlugin{name: "a"}
	b := &stubPlugin{name: "b", deps: []string{"missing"}}
	all := []api.Plugin{a, b}

	k := New(manifestFor(spec("a", true, nil)))
	if err := k.Boot(context.Background(), all, k.Manifest().Enabled()); err != nil {
		t.Fatalf("Boot: %v", err)
	}

	badManifest := manifestFor(spec("a", true, nil), spec("b", true, nil)) // b depends on "missing", never enabled
	err := k.Reload(context.Background(), badManifest, all)
	if err == nil {
		t.Fatalf("expected Reload to refuse an invalid manifest")
	}
	if len(k.plugins) != 1 || k.plugins[0].Name() != "a" {
		t.Fatalf("old configuration was not preserved after refused reload: %v", k.plugins)
	}
	if b.initCount != 0 {
		t.Fatalf("b should never have been Init'd: initCount=%d", b.initCount)
	}
}

// 3b. LoadManifestBCL itself on malformed BCL returns a clear error and
// never crashes — the file-watch loop relies on this to skip a bad edit.
func TestLoadManifestBCL_MalformedIsCleanError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.bcl")
	if err := os.WriteFile(path, []byte("plugin \"a\" { enabled true config { "), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifestBCL(path); err == nil {
		t.Fatalf("expected an error for malformed BCL")
	}
}

// 4. Reload changing a LEAF plugin's config (nothing depends on it) is
// cleanly Stop+Init+Start'd with the new config; nothing else is touched.
func TestReload_LeafConfigChangeCyclesOnlyThatPlugin(t *testing.T) {
	a := &stubPlugin{name: "a"}
	leaf := &stubPlugin{name: "leaf"}
	all := []api.Plugin{a, leaf}

	k := New(manifestFor(spec("a", true, nil), spec("leaf", true, map[string]any{"x": "1"})))
	if err := k.Boot(context.Background(), all, k.Manifest().Enabled()); err != nil {
		t.Fatalf("Boot: %v", err)
	}

	newManifest := manifestFor(spec("a", true, nil), spec("leaf", true, map[string]any{"x": "2"}))
	if err := k.Reload(context.Background(), newManifest, all); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if leaf.initCount != 2 || leaf.startCount != 2 || leaf.stopCount != 1 {
		t.Fatalf("leaf not cycled correctly: init=%d start=%d stop=%d", leaf.initCount, leaf.startCount, leaf.stopCount)
	}
	if leaf.lastConfig["x"] != "2" {
		t.Fatalf("leaf did not see new config: %v", leaf.lastConfig)
	}
	if a.initCount != 1 || a.stopCount != 0 {
		t.Fatalf("unrelated plugin 'a' was touched: init=%d stop=%d", a.initCount, a.stopCount)
	}
}

// 5. Reload changing a config that OTHER running plugins depend on
// cycles every transitive dependent too (never leaves one holding a
// stale service handle).
func TestReload_ConfigChangeCyclesDependents(t *testing.T) {
	base := &stubPlugin{name: "base"}
	mid := &stubPlugin{name: "mid", deps: []string{"base"}}
	top := &stubPlugin{name: "top", deps: []string{"mid"}}
	all := []api.Plugin{base, mid, top}

	initial := manifestFor(
		spec("base", true, map[string]any{"v": "1"}),
		spec("mid", true, nil),
		spec("top", true, nil),
	)
	k := New(initial)
	if err := k.Boot(context.Background(), all, k.Manifest().Enabled()); err != nil {
		t.Fatalf("Boot: %v", err)
	}

	changed := manifestFor(
		spec("base", true, map[string]any{"v": "2"}),
		spec("mid", true, nil),
		spec("top", true, nil),
	)
	if err := k.Reload(context.Background(), changed, all); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	for _, p := range []*stubPlugin{base, mid, top} {
		if p.initCount != 2 || p.stopCount != 1 {
			t.Fatalf("%s not cycled as a dependent: init=%d stop=%d", p.name, p.initCount, p.stopCount)
		}
	}
	// "mid" looking up "base" in its second Init proves it got a FRESH
	// handle, not a stale pre-cycle one (MustLookup would panic on a
	// dangling entry left over from before removeAll ran).
}

// 6. Real file-mtime-based polling: an on-disk manifest edit triggers a
// real reload within a bounded time (exercises Watch, the polling loop
// added for cmd/velocityd's -watch-manifest flag).
func TestWatchManifest_DetectsRealFileEditAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.bcl")

	write := func(m Manifest) {
		b, err := bcl.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	a := &stubPlugin{name: "a"}
	b := &stubPlugin{name: "b"}
	all := []api.Plugin{a, b}

	write(manifestFor(spec("a", true, nil)))
	m0, err := LoadManifestBCL(path)
	if err != nil {
		t.Fatal(err)
	}
	k := New(m0)
	if err := k.Boot(context.Background(), all, k.Manifest().Enabled()); err != nil {
		t.Fatalf("Boot: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reloaded := make(chan error, 1)
	go WatchManifest(ctx, path, 20*time.Millisecond, func(newManifest Manifest) error {
		err := k.Reload(context.Background(), newManifest, all)
		select {
		case reloaded <- err:
		default:
		}
		return err
	})

	time.Sleep(30 * time.Millisecond) // ensure the watcher's first stat happens before the edit
	write(manifestFor(spec("a", true, nil), spec("b", true, nil)))

	select {
	case err := <-reloaded:
		if err != nil {
			t.Fatalf("reload callback returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for file-watch reload")
	}
	if b.initCount != 1 {
		t.Fatalf("b was not booted by the file-triggered reload: initCount=%d", b.initCount)
	}
}
