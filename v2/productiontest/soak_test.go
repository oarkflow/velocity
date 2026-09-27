package productiontest

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	"github.com/oarkflow/velocity/v2/plugins/object"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

// TestSoak_SustainedMixedWorkload runs a real, sustained, concurrent
// mixed KV+object workload for a bounded duration, then verifies final
// data consistency against what the workload generator tracked, and
// checks for goroutine leaks after a clean shutdown. Kept well under a
// minute so it's reasonable to run as part of normal CI, not just a
// manual soak session.
func TestSoak_SustainedMixedWorkload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping soak test in -short mode")
	}
	const duration = 5 * time.Second // real, documented duration — see t.Logf below

	dir := t.TempDir()
	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir, "always_sync": false}},
		{Name: "kv", Enabled: true},
		{Name: "object", Enabled: true},
	}}
	k := kernel.New(manifest)
	plugins := []api.Plugin{storagelsm.New(), kv.New("storage-lsm"), object.New("storage-lsm")}
	ctx, cancel := context.WithTimeout(context.Background(), duration+5*time.Second)
	defer cancel()

	if err := k.Boot(ctx, plugins, manifest.Enabled()); err != nil {
		t.Fatalf("boot: %v", err)
	}

	kvSvc := k.Registry().MustLookup("kv").(api.KVService)
	objSvc := k.Registry().MustLookup("object").(api.ObjectService)
	if err := objSvc.CreateBucket(ctx, "soak"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	goroutinesBefore := runtime.NumGoroutine()

	var mu sync.Mutex
	writtenKV := map[string]string{}
	writtenObj := map[string]string{}

	// A closed channel, not time.After: time.After's channel delivers
	// exactly one value, so with N concurrent readers only ONE goroutine
	// would ever observe it — the other N-1 would spin on "default:"
	// forever. close() broadcasts to every receiver.
	stop := make(chan struct{})
	time.AfterFunc(duration, func() { close(stop) })
	var wg sync.WaitGroup
	workers := 8
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			i := 0
			for {
				select {
				case <-stop:
					return
				default:
				}
				i++
				key := fmt.Sprintf("soak:kv:%d:%d", id, i)
				val := fmt.Sprintf("val-%d-%d", id, i)
				if err := kvSvc.Put(ctx, key, []byte(val)); err != nil {
					t.Errorf("worker %d: kv Put: %v", id, err)
					return
				}
				mu.Lock()
				writtenKV[key] = val
				mu.Unlock()

				if i%5 == 0 {
					okey := fmt.Sprintf("obj-%d-%d.txt", id, i)
					oval := fmt.Sprintf("object-body-%d-%d", id, i)
					if _, err := objSvc.PutObject(ctx, "soak", okey, strings.NewReader(oval), api.ObjectMeta{}); err != nil {
						t.Errorf("worker %d: PutObject: %v", id, err)
						return
					}
					mu.Lock()
					writtenObj[okey] = oval
					mu.Unlock()
				}

				if i%7 == 0 {
					// A read interleaved with writes, exercising the
					// concurrent read/write path, not just concurrent
					// writes.
					if _, _, err := kvSvc.Get(ctx, key); err != nil {
						t.Errorf("worker %d: kv Get: %v", id, err)
						return
					}
				}
				if i%11 == 0 {
					delKey := fmt.Sprintf("soak:kv:%d:%d", id, i-1)
					_ = kvSvc.Delete(ctx, delKey)
					mu.Lock()
					delete(writtenKV, delKey)
					mu.Unlock()
				}
			}
		}(w)
	}
	wg.Wait()

	// Spot-check EVERY tracked write (small enough dataset at 5s/8 workers
	// to check exhaustively rather than sampling) against what's actually
	// stored.
	mu.Lock()
	kvSnapshot := make(map[string]string, len(writtenKV))
	for k, v := range writtenKV {
		kvSnapshot[k] = v
	}
	objSnapshot := make(map[string]string, len(writtenObj))
	for k, v := range writtenObj {
		objSnapshot[k] = v
	}
	mu.Unlock()

	mismatches := 0
	for key, want := range kvSnapshot {
		got, found, err := kvSvc.Get(ctx, key)
		if err != nil || !found || string(got) != want {
			mismatches++
			t.Logf("kv mismatch: key=%s found=%v err=%v got=%q want=%q", key, found, err, got, want)
		}
	}
	for okey, want := range objSnapshot {
		rc, _, err := objSvc.GetObject(ctx, "soak", okey, "")
		if err != nil {
			mismatches++
			t.Logf("object mismatch: key=%s err=%v", okey, err)
			continue
		}
		body, _ := io.ReadAll(rc)
		rc.Close()
		if string(body) != want {
			mismatches++
			t.Logf("object body mismatch: key=%s got=%q want=%q", okey, body, want)
		}
	}
	if mismatches > 0 {
		t.Fatalf("%d data-consistency mismatches after sustained concurrent load (%d kv keys, %d objects tracked)",
			mismatches, len(kvSnapshot), len(objSnapshot))
	}
	t.Logf("consistency verified: %d kv keys, %d objects, zero mismatches after %s of concurrent load across %d workers",
		len(kvSnapshot), len(objSnapshot), duration, workers)

	if err := k.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// Goroutine-leak check: allow a small fixed slack (the Go runtime
	// itself, test harness goroutines, etc. can vary by a handful), but
	// flag a clearly-growing leak. This is a soft-but-real check, not
	// flaky noise — a genuine leak here would show as dozens, not single
	// digits, of stragglers.
	runtime.GC()
	time.Sleep(100 * time.Millisecond) // let any exiting goroutines actually finish exiting
	goroutinesAfter := runtime.NumGoroutine()
	t.Logf("goroutines: before=%d after=%d (informational memory check below is not a pass/fail gate)", goroutinesBefore, goroutinesAfter)
	if goroutinesAfter > goroutinesBefore+10 {
		t.Errorf("possible goroutine leak: %d before shutdown, %d after (delta %d exceeds the +10 slack)",
			goroutinesBefore, goroutinesAfter, goroutinesAfter-goroutinesBefore)
	}

	var memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memAfter)
	t.Logf("informational: HeapAlloc after final GC = %d bytes (not asserted — Go's GC behavior varies run to run)", memAfter.HeapAlloc)
}
