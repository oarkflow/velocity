package object

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// TestConcurrentPutDifferentKeys stresses concurrent PutObject calls to
// DIFFERENT keys in the same bucket, followed by concurrent GetObject
// reads — every object must be retrievable with correct content, with no
// data races (run this under -race).
func TestConcurrentPutDifferentKeys(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	if err := p.CreateBucket(ctx, "b"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%03d", i)
			body := fmt.Sprintf("body-for-%03d", i)
			if _, err := p.PutObject(ctx, "b", key, bytes.NewReader([]byte(body)), api.ObjectMeta{}); err != nil {
				t.Errorf("PutObject(%s): %v", key, err)
			}
		}(i)
	}
	wg.Wait()

	var wg2 sync.WaitGroup
	for i := 0; i < n; i++ {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			key := fmt.Sprintf("key-%03d", i)
			want := fmt.Sprintf("body-for-%03d", i)
			rc, _, err := p.GetObject(ctx, "b", key, "")
			if err != nil {
				t.Errorf("GetObject(%s): %v", key, err)
				return
			}
			defer rc.Close()
			var buf bytes.Buffer
			buf.ReadFrom(rc)
			if buf.String() != want {
				t.Errorf("GetObject(%s): got %q, want %q", key, buf.String(), want)
			}
		}(i)
	}
	wg2.Wait()
}

// TestConcurrentPutSameKeyCreatesAllVersions puts to the SAME key from
// many goroutines concurrently. Ordering among simultaneous writers is
// not deterministic (documented, not a bug), but every write must be
// durably present as some version afterward — none may be lost or
// corrupted, and each version's content must match what that specific
// writer sent (proving no cross-writer data corruption).
func TestConcurrentPutSameKeyCreatesAllVersions(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	if err := p.CreateBucket(ctx, "b"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	const n = 50
	versionIDs := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf("version-writer-%03d", i)
			meta, err := p.PutObject(ctx, "b", "shared-key", bytes.NewReader([]byte(body)), api.ObjectMeta{})
			if err != nil {
				t.Errorf("PutObject writer %d: %v", i, err)
				return
			}
			versionIDs[i] = meta.VersionID
		}(i)
	}
	wg.Wait()

	// Every writer's versionID must be unique (no collisions from
	// concurrent newVersionID() calls) and independently retrievable with
	// exactly that writer's content.
	seen := make(map[string]bool, n)
	for i, vID := range versionIDs {
		if vID == "" {
			t.Fatalf("writer %d never got a version ID", i)
		}
		if seen[vID] {
			t.Fatalf("version ID collision: %q used by more than one writer", vID)
		}
		seen[vID] = true
	}

	var wg2 sync.WaitGroup
	for i := 0; i < n; i++ {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			want := fmt.Sprintf("version-writer-%03d", i)
			rc, _, err := p.GetObject(ctx, "b", "shared-key", versionIDs[i])
			if err != nil {
				t.Errorf("GetObject version %d (%s): %v", i, versionIDs[i], err)
				return
			}
			defer rc.Close()
			var buf bytes.Buffer
			buf.ReadFrom(rc)
			if buf.String() != want {
				t.Errorf("version %d content mismatch: got %q, want %q (cross-writer corruption)", i, buf.String(), want)
			}
		}(i)
	}
	wg2.Wait()

	// ListObjects must still show exactly one row for "shared-key"
	// (whichever version ended up as "latest" — non-deterministic among
	// concurrent writers, but there must be exactly one, not zero or
	// duplicated).
	objs, err := p.ListObjects(ctx, "b", "")
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	count := 0
	for _, o := range objs {
		if o.Key == "shared-key" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 ListObjects row for shared-key, got %d", count)
	}
}
