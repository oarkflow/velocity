// Command lock_and_extractor demonstrates two independent, stateless-ish
// Velocity v2 plugins in one program: the TTL-based distributed lock
// (plugins/lock) and the content extractor (plugins/extractor).
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/extractor"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	"github.com/oarkflow/velocity/v2/plugins/lock"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
}

func main() {
	dir, err := os.MkdirTemp("", "velocity-lock-extractor-*")
	must(err)
	defer os.RemoveAll(dir)

	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir, "always_sync": true}},
		{Name: "kv", Enabled: true},
		{Name: "lock", Enabled: true},
		{Name: "extractor", Enabled: true},
	}}

	k := kernel.New(manifest)
	all := []api.Plugin{
		storagelsm.New(),
		kv.New("storage-lsm"),
		lock.NewPlugin("kv"),
		extractor.NewPlugin(),
	}

	ctx := context.Background()
	must(k.Boot(ctx, all, manifest.Enabled()))
	fmt.Println("=== booted storage-lsm + kv + lock + extractor ===")
	defer func() { must(k.Shutdown(ctx)) }()

	demoLock(ctx, k)
	demoExtractor(ctx, k)
}

func demoLock(ctx context.Context, k *kernel.Kernel) {
	lockSvc := k.Registry().MustLookup("lock").(api.LockService)

	fmt.Println("\n--- lock demo ---")

	fmt.Println("=== Acquire(\"job:report-gen\", 5s) ===")
	handle, err := lockSvc.Acquire(ctx, "job:report-gen", 5*time.Second)
	must(err)
	fmt.Println("acquired OK")

	fmt.Println("\n=== second Acquire on the SAME key while held ===")
	_, err = lockSvc.Acquire(ctx, "job:report-gen", 5*time.Second)
	if err == nil {
		fmt.Fprintln(os.Stderr, "FATAL: expected second Acquire to fail while lock is held")
		os.Exit(1)
	}
	fmt.Printf("correctly rejected: %v\n", err)

	fmt.Println("\n=== Release, then re-Acquire ===")
	must(handle.Release(ctx))
	handle2, err := lockSvc.Acquire(ctx, "job:report-gen", 2*time.Second)
	must(err)
	fmt.Println("re-acquired OK after release")

	fmt.Println("\n=== letting a 2s lock naturally expire (waiting ~2.3s) ===")
	time.Sleep(2300 * time.Millisecond)
	locked, err := lockSvc.IsLocked(ctx, "job:report-gen")
	must(err)
	fmt.Printf("IsLocked after TTL expiry: %v (expect false)\n", locked)
	if locked {
		fmt.Fprintln(os.Stderr, "FATAL: lock should have expired")
		os.Exit(1)
	}

	handle3, err := lockSvc.Acquire(ctx, "job:report-gen", 2*time.Second)
	must(err)
	fmt.Println("fresh Acquire after expiry succeeded without an explicit Release")
	must(handle3.Release(ctx))
	_ = handle2 // already implicitly released by TTL expiry above
}

func demoExtractor(ctx context.Context, k *kernel.Kernel) {
	extSvc := k.Registry().MustLookup("extractor").(api.ExtractorService)

	fmt.Println("\n--- extractor demo ---")

	types, err := extSvc.SupportedTypes(ctx)
	must(err)
	fmt.Printf("=== SupportedTypes: %v ===\n", types)

	samples := []struct {
		name        string
		contentType string
		body        string
	}{
		{"plain text", "text/plain", "Hello, this is a plain text sample.\nSecond line."},
		{"JSON", "application/json", `{"order_id": 1001, "status": "shipped", "total": 42.50}`},
		{"HTML", "text/html", `<html><head><script>alert('x')</script></head><body><h1>Title</h1><p>Body text.</p></body></html>`},
		{"CSV", "text/csv", "name,age,city\nalice,30,NYC\nbob,25,LA\ncarol,35,SF"},
	}

	for _, s := range samples {
		fmt.Printf("\n=== Extract(%q) ===\n", s.name)
		result, err := extSvc.Extract(ctx, s.contentType, strings.NewReader(s.body))
		must(err)
		fmt.Printf("Text: %q\n", truncate(result.Text, 200))
		fmt.Printf("Metadata: %v\n", result.Metadata)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
