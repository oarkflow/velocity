package object

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

func TestTenants_IdenticalBucketAndKeyDoNotCollide(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	ctxA := api.WithTenant(ctx, "tenant-a")
	ctxB := api.WithTenant(ctx, "tenant-b")

	if err := p.CreateBucket(ctxA, "docs"); err != nil {
		t.Fatalf("CreateBucket A: %v", err)
	}
	if err := p.CreateBucket(ctxB, "docs"); err != nil {
		t.Fatalf("CreateBucket B: %v", err)
	}

	if _, err := p.PutObject(ctxA, "docs", "readme.txt", strings.NewReader("A content"), api.ObjectMeta{}); err != nil {
		t.Fatalf("PutObject A: %v", err)
	}
	if _, err := p.PutObject(ctxB, "docs", "readme.txt", strings.NewReader("B content"), api.ObjectMeta{}); err != nil {
		t.Fatalf("PutObject B: %v", err)
	}

	rA, _, err := p.GetObject(ctxA, "docs", "readme.txt", "")
	if err != nil {
		t.Fatalf("GetObject A: %v", err)
	}
	bA, _ := io.ReadAll(rA)
	rA.Close()
	if string(bA) != "A content" {
		t.Fatalf("tenant A got wrong content: %q", bA)
	}

	rB, _, err := p.GetObject(ctxB, "docs", "readme.txt", "")
	if err != nil {
		t.Fatalf("GetObject B: %v", err)
	}
	bB, _ := io.ReadAll(rB)
	rB.Close()
	if string(bB) != "B content" {
		t.Fatalf("tenant B got wrong content: %q", bB)
	}
}

func TestTenants_ListObjectsNeverLeaksAcrossTenants(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	ctxA := api.WithTenant(ctx, "a")
	ctxB := api.WithTenant(ctx, "b")

	_ = p.CreateBucket(ctxA, "bucket1")
	_ = p.CreateBucket(ctxB, "bucket1")

	_, _ = p.PutObject(ctxA, "bucket1", "a-only.txt", strings.NewReader("a"), api.ObjectMeta{})
	// Crafted key content attempting to look like a path escape into
	// tenant a's namespace — must remain inert, ordinary key content.
	_, _ = p.PutObject(ctxB, "bucket1", "../a/a-only.txt", strings.NewReader("b-should-not-leak"), api.ObjectMeta{})

	listA, err := p.ListObjects(ctxA, "bucket1", "")
	if err != nil {
		t.Fatalf("ListObjects A: %v", err)
	}
	if len(listA) != 1 || listA[0].Key != "a-only.txt" {
		t.Fatalf("tenant A's ListObjects leaked or missed data: %+v", listA)
	}

	if _, _, err := p.GetObject(ctxA, "bucket1", "../a/a-only.txt", ""); err == nil {
		t.Fatalf("tenant A should not be able to read tenant B's crafted key")
	}
}

func TestTenants_NoTenantInContextIsUnchangedGlobalBehavior(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	if err := p.CreateBucket(ctx, "globalbucket"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if _, err := p.PutObject(ctx, "globalbucket", "file.txt", strings.NewReader("global"), api.ObjectMeta{}); err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	// Confirm the raw bucket metadata key has NO tenant prefix.
	_, ok, err := p.storage.Get(ctx, []byte(bucketMetaKey("globalbucket")))
	if err != nil || !ok {
		t.Fatalf("expected raw bucket meta key to exist untouched, ok=%v err=%v", ok, err)
	}

	r, _, err := p.GetObject(ctx, "globalbucket", "file.txt", "")
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if string(b) != "global" {
		t.Fatalf("got %q", b)
	}
}

var _ = time.Minute // keep time import used if lifecycleInterval helper is unused elsewhere
