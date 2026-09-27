package object

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

func newTestPlugin() *Plugin {
	return &Plugin{storage: newMemBackend(), stopCh: make(chan struct{}), lifecycleInterval: time.Minute}
}

func TestBucketLifecycleBasic(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	if err := p.CreateBucket(ctx, "b1"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if err := p.CreateBucket(ctx, "b1"); err != ErrBucketExists {
		t.Fatalf("expected ErrBucketExists, got %v", err)
	}
	if err := p.DeleteBucket(ctx, "b1"); err != nil {
		t.Fatalf("DeleteBucket: %v", err)
	}
	if err := p.DeleteBucket(ctx, "missing"); err != ErrBucketNotFound {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}
}

func TestPutGetObjectRoundTrip(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	_ = p.CreateBucket(ctx, "docs")

	meta, err := p.PutObject(ctx, "docs", "hello.txt", strings.NewReader("hello world"), api.ObjectMeta{ContentType: "text/plain"})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if meta.VersionID == "" || meta.ETag == "" || meta.Size != int64(len("hello world")) {
		t.Fatalf("unexpected meta: %+v", meta)
	}

	rc, gotMeta, err := p.GetObject(ctx, "docs", "hello.txt", "")
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	defer rc.Close()
	body, _ := io.ReadAll(rc)
	if string(body) != "hello world" {
		t.Fatalf("unexpected body: %q", body)
	}
	if gotMeta.VersionID != meta.VersionID {
		t.Fatalf("version mismatch: %q vs %q", gotMeta.VersionID, meta.VersionID)
	}
}

func TestVersioningKeepsOldVersionRetrievable(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	_ = p.CreateBucket(ctx, "docs")

	v1, err := p.PutObject(ctx, "docs", "k", strings.NewReader("v1"), api.ObjectMeta{})
	if err != nil {
		t.Fatalf("PutObject v1: %v", err)
	}
	v2, err := p.PutObject(ctx, "docs", "k", strings.NewReader("v2"), api.ObjectMeta{})
	if err != nil {
		t.Fatalf("PutObject v2: %v", err)
	}
	if v1.VersionID == v2.VersionID {
		t.Fatalf("expected distinct version IDs")
	}

	rc, _, err := p.GetObject(ctx, "docs", "k", v1.VersionID)
	if err != nil {
		t.Fatalf("GetObject old version: %v", err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if string(body) != "v1" {
		t.Fatalf("expected old version body 'v1', got %q", body)
	}

	rc2, latestMeta, err := p.GetObject(ctx, "docs", "k", "")
	if err != nil {
		t.Fatalf("GetObject latest: %v", err)
	}
	body2, _ := io.ReadAll(rc2)
	rc2.Close()
	if string(body2) != "v2" || latestMeta.VersionID != v2.VersionID {
		t.Fatalf("expected latest to be v2, got body=%q meta=%+v", body2, latestMeta)
	}
}

func TestComplianceLockRejectsDeleteEvenWithBypass(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	_ = p.CreateBucket(ctx, "locked")
	_, _ = p.PutObject(ctx, "locked", "k", strings.NewReader("data"), api.ObjectMeta{})

	if err := p.PutRetention(ctx, "locked", "k", api.RetentionPolicy{
		Mode:        api.LockCompliance,
		RetainUntil: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("PutRetention: %v", err)
	}

	if err := p.DeleteObject(ctx, "locked", "k", "", true); err != ErrObjectLocked {
		t.Fatalf("expected ErrObjectLocked even with bypassGovernance=true on a COMPLIANCE lock, got %v", err)
	}
}

func TestGovernanceLockAllowsBypass(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	_ = p.CreateBucket(ctx, "gov")
	_, _ = p.PutObject(ctx, "gov", "k", strings.NewReader("data"), api.ObjectMeta{})

	if err := p.PutRetention(ctx, "gov", "k", api.RetentionPolicy{
		Mode:        api.LockGovernance,
		RetainUntil: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("PutRetention: %v", err)
	}

	if err := p.DeleteObject(ctx, "gov", "k", "", false); err != ErrObjectLocked {
		t.Fatalf("expected ErrObjectLocked without bypass, got %v", err)
	}
	if err := p.DeleteObject(ctx, "gov", "k", "", true); err != nil {
		t.Fatalf("expected bypass to succeed on GOVERNANCE lock, got %v", err)
	}
}

func TestListObjects(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	_ = p.CreateBucket(ctx, "list")
	_, _ = p.PutObject(ctx, "list", "a", strings.NewReader("1"), api.ObjectMeta{})
	_, _ = p.PutObject(ctx, "list", "b", strings.NewReader("2"), api.ObjectMeta{})
	_, _ = p.PutObject(ctx, "list", "a", strings.NewReader("1b"), api.ObjectMeta{}) // second version of "a"

	objs, err := p.ListObjects(ctx, "list", "")
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if len(objs) != 2 {
		t.Fatalf("expected 2 distinct objects (versions collapsed), got %d: %+v", len(objs), objs)
	}
}

func TestLifecycleExpiry(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	_ = p.CreateBucket(ctx, "exp")
	_, _ = p.PutObject(ctx, "exp", "old", strings.NewReader("data"), api.ObjectMeta{})

	if err := p.SetLifecycle(ctx, "exp", []api.LifecycleRule{{ExpireAfter: time.Millisecond}}); err != nil {
		t.Fatalf("SetLifecycle: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	p.runLifecycleOnce(ctx)

	if _, _, err := p.GetObject(ctx, "exp", "old", ""); err != ErrObjectNotFound {
		t.Fatalf("expected object to be expired and removed, got err=%v", err)
	}
}

func TestLifecycleRespectsLegalHold(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	_ = p.CreateBucket(ctx, "hold")
	_, _ = p.PutObject(ctx, "hold", "k", strings.NewReader("data"), api.ObjectMeta{})
	_ = p.PutRetention(ctx, "hold", "k", api.RetentionPolicy{LegalHold: true})
	_ = p.SetLifecycle(ctx, "hold", []api.LifecycleRule{{ExpireAfter: -time.Second}})

	p.runLifecycleOnce(ctx)

	if _, _, err := p.GetObject(ctx, "hold", "k", ""); err != nil {
		t.Fatalf("expected object under legal hold to survive lifecycle expiry, got err=%v", err)
	}
}
