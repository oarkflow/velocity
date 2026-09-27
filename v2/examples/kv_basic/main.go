// Command kv_basic demonstrates Velocity v2's key-value surface
// (api.KVService) by booting the microkernel directly in-process — the
// way an application embedding Velocity would — rather than through the
// CLI or a running server.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "velocity-kv-basic-*")
	must(err)
	defer os.RemoveAll(dir)

	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
		{Name: "kv", Enabled: true},
	}}

	k := kernel.New(manifest)
	must(k.Boot(ctx, []api.Plugin{storagelsm.New(), kv.New("storage-lsm")}, manifest.Enabled()))
	defer k.Shutdown(ctx)

	svc := k.Registry().MustLookup("kv").(api.KVService)

	fmt.Println("=== Put/Get ===")
	must(svc.Put(ctx, "greeting", []byte("hello, velocity")))
	val, ok, err := svc.Get(ctx, "greeting")
	must(err)
	fmt.Printf("Get(greeting) = %q, found=%v\n", val, ok)

	fmt.Println("\n=== PutWithTTL, then expiry ===")
	must(svc.PutWithTTL(ctx, "session", []byte("temporary"), 150*time.Millisecond))
	val, ok, err = svc.Get(ctx, "session")
	must(err)
	fmt.Printf("immediately after Put: found=%v, value=%q\n", ok, val)
	time.Sleep(250 * time.Millisecond)
	_, ok, err = svc.Get(ctx, "session")
	must(err)
	fmt.Printf("after TTL elapses:      found=%v (expired)\n", ok)

	fmt.Println("\n=== Exists ===")
	exists, err := svc.Exists(ctx, "greeting")
	must(err)
	fmt.Printf("Exists(greeting) = %v\n", exists)

	fmt.Println("\n=== Incr ===")
	for range 3 {
		n, err := svc.Incr(ctx, "hits", 1)
		must(err)
		fmt.Printf("hits = %d\n", n)
	}

	fmt.Println("\n=== Delete ===")
	must(svc.Delete(ctx, "greeting"))
	_, ok, err = svc.Get(ctx, "greeting")
	must(err)
	fmt.Printf("Get(greeting) after Delete: found=%v\n", ok)

	fmt.Println("\n=== Keys (glob) ===")
	for i := range 5 {
		must(svc.Put(ctx, fmt.Sprintf("user:%d", i), []byte("data")))
	}
	keys, err := svc.Keys(ctx, "user:*")
	must(err)
	sort.Strings(keys)
	fmt.Printf("Keys(user:*) = %v\n", keys)

	fmt.Println("\n=== Scan (paginated) ===")
	for i := range 10 {
		must(svc.Put(ctx, fmt.Sprintf("page:%02d", i), []byte(fmt.Sprintf("v%d", i))))
	}
	cursor := ""
	page := 1
	for {
		items, next, err := svc.Scan(ctx, "page:", 3, cursor)
		must(err)
		keys := make([]string, 0, len(items))
		for k := range items {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Printf("page %d: %v (nextCursor=%q)\n", page, keys, next)
		if next == "" {
			break
		}
		cursor = next
		page++
	}

	fmt.Println("\ndone.")
}
