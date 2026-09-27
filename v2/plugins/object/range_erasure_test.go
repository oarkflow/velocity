package object

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/erasure"
)

// countingBackend wraps memBackend and counts bytes returned by Get, so
// tests can assert GetObjectRange reads much less than the full object
// instead of just trusting the implementation.
type countingBackend struct {
	*memBackend
	getBytes int64
	getCalls int
}

func newCountingBackend() *countingBackend {
	return &countingBackend{memBackend: newMemBackend()}
}

func (c *countingBackend) Get(ctx context.Context, key []byte) ([]byte, bool, error) {
	v, ok, err := c.memBackend.Get(ctx, key)
	if ok {
		c.getBytes += int64(len(v))
		c.getCalls++
	}
	return v, ok, err
}

func TestGetObjectRange_ReadsFarFewerBytesThanFullObject(t *testing.T) {
	ctx := context.Background()
	backend := newCountingBackend()
	p := &Plugin{storage: backend, stopCh: make(chan struct{}), lifecycleInterval: time.Minute}
	_ = p.CreateBucket(ctx, "big")

	// 20 MiB body -> ~80 blocks at the 256KiB block size, so a 1-block
	// range read is a clearly small fraction (~1.25%) of the whole object.
	body := make([]byte, 20*1024*1024)
	rand.New(rand.NewSource(1)).Read(body)
	meta, err := p.PutObject(ctx, "big", "blob", bytes.NewReader(body), api.ObjectMeta{})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	// Baseline: a full GetObject necessarily reads every byte.
	backend.getBytes = 0
	rc, _, err := p.GetObject(ctx, "big", "blob", "")
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	fullBody, _ := io.ReadAll(rc)
	rc.Close()
	fullReadBytes := backend.getBytes
	if int64(len(fullBody)) != meta.Size {
		t.Fatalf("full body size mismatch: got %d want %d", len(fullBody), meta.Size)
	}

	// Now request a tiny range near the end of the object.
	backend.getBytes = 0
	backend.getCalls = 0
	start := meta.Size - 100
	end := meta.Size - 1
	rc2, _, err := p.GetObjectRange(ctx, "big", "blob", "", start, end)
	if err != nil {
		t.Fatalf("GetObjectRange: %v", err)
	}
	rangeBody, _ := io.ReadAll(rc2)
	rc2.Close()

	if !bytes.Equal(rangeBody, body[start:end+1]) {
		t.Fatalf("range body mismatch: got %d bytes, want %d bytes matching source", len(rangeBody), end-start+1)
	}

	t.Logf("full read: %d bytes from storage; range read: %d bytes from storage (%d Get calls)", fullReadBytes, backend.getBytes, backend.getCalls)

	if backend.getBytes >= fullReadBytes {
		t.Fatalf("range read (%d bytes from storage) did not read fewer bytes than full read (%d bytes)", backend.getBytes, fullReadBytes)
	}
	// A 100-byte range should cost at most a couple of 256KiB blocks out of
	// ~80 total — bound it well under 5% of the full object to prove this
	// isn't just "slightly less."
	if backend.getBytes > fullReadBytes/20 {
		t.Fatalf("range read (%d bytes) is not meaningfully smaller than full read (%d bytes)", backend.getBytes, fullReadBytes)
	}
}

func TestGetObjectRange_SpanningMultipleBlocks(t *testing.T) {
	ctx := context.Background()
	p := &Plugin{storage: newMemBackend(), stopCh: make(chan struct{}), lifecycleInterval: time.Minute}
	_ = p.CreateBucket(ctx, "b")

	body := make([]byte, 3*rangeBlockSize+123)
	for i := range body {
		body[i] = byte(i % 256)
	}
	_, err := p.PutObject(ctx, "b", "k", bytes.NewReader(body), api.ObjectMeta{})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	start := int64(rangeBlockSize - 50)
	end := int64(2*rangeBlockSize + 50)
	rc, _, err := p.GetObjectRange(ctx, "b", "k", "", start, end)
	if err != nil {
		t.Fatalf("GetObjectRange: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	want := body[start : end+1]
	if !bytes.Equal(got, want) {
		t.Fatalf("cross-block range mismatch: got %d bytes, want %d bytes", len(got), len(want))
	}
}

// newTestKernel boots a bare kernel with only a storage backend
// pre-registered, for Init'ing individual plugins directly without a full
// Boot() (mirrors the pattern used by plugins/compliance's tests).
func newTestKernel(t *testing.T, storage api.StorageBackend) *kernel.Kernel {
	t.Helper()
	k := kernel.New(kernel.Manifest{})
	if err := k.Registry().Provide("storage", storage); err != nil {
		t.Fatalf("provide storage: %v", err)
	}
	return k
}

func TestErasureBackedObject_SurvivesShardCorruption(t *testing.T) {
	ctx := context.Background()
	backend := newMemBackend()
	k := newTestKernel(t, backend)

	erasurePlugin := erasure.NewPlugin("storage")
	if err := erasurePlugin.Init(ctx, k); err != nil {
		t.Fatalf("erasure Init: %v", err)
	}

	objPlugin := New("storage")
	// Configure via the same k.Config() path Init reads from: build a
	// kernel whose manifest enables "object" with the erasure opt-in, so
	// Scoped("object") returns these values.
	k2 := kernel.New(kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "object", Enabled: true, Config: map[string]any{
			"use_erasure_for_large_objects": true,
			"erasure_threshold_bytes":       float64(16), // force even small test bodies through erasure
		}},
	}})
	if err := k2.Registry().Provide("storage", backend); err != nil {
		t.Fatalf("provide storage: %v", err)
	}
	if err := k2.Registry().Provide("erasure", erasurePlugin); err != nil {
		t.Fatalf("provide erasure: %v", err)
	}
	if err := objPlugin.Init(ctx, k2); err != nil {
		t.Fatalf("object Init: %v", err)
	}
	if objPlugin.erasure == nil {
		t.Fatalf("expected object plugin to have picked up the erasure ShardStore")
	}

	_ = objPlugin.CreateBucket(ctx, "docs")
	body := []byte("this body is definitely over the 16-byte erasure threshold configured above")
	meta, err := objPlugin.PutObject(ctx, "docs", "important", bytes.NewReader(body), api.ObjectMeta{})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	rec, err := objPlugin.getVersionRecord(ctx, "docs", "important", "")
	if err != nil {
		t.Fatalf("getVersionRecord: %v", err)
	}
	if !rec.StoredViaErasure {
		t.Fatalf("expected version to be marked StoredViaErasure")
	}

	// Corrupt one underlying SHARD (not the metadata entry) directly via
	// the storage backend, using the erasure plugin's own key scheme
	// ("erasure/<id>/shard/<n>", distinct from "erasure/<id>/meta").
	dataKey := objectVersionDataKey("docs", "important", meta.VersionID)
	corrupted := false
	it, err := backend.Scan(ctx, []byte("erasure/"))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for it.Next() {
		k := string(it.Key())
		if bytes.Contains([]byte(k), []byte(dataKey)) && bytes.Contains([]byte(k), []byte("/shard/")) {
			junk := make([]byte, len(it.Value()))
			for i := range junk {
				junk[i] = 0xFF
			}
			if err := backend.Put(ctx, api.Entry{Key: []byte(k), Value: junk}); err != nil {
				t.Fatalf("corrupt shard: %v", err)
			}
			corrupted = true
			break
		}
	}
	it.Close()
	if !corrupted {
		t.Fatalf("did not find any erasure shard key containing %q to corrupt — key scheme assumption is wrong", dataKey)
	}

	// GetObject must still return the correct body, reconstructed via
	// parity, despite the corrupted shard.
	rc, gotMeta, err := objPlugin.GetObject(ctx, "docs", "important", "")
	if err != nil {
		t.Fatalf("GetObject after shard corruption: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, body) {
		t.Fatalf("body not correctly reconstructed after shard corruption: got %q want %q", got, body)
	}
	if gotMeta.VersionID != meta.VersionID {
		t.Fatalf("version mismatch after reconstruction")
	}
}

func TestNonErasureObjectsUnaffectedByErasureOptIn(t *testing.T) {
	ctx := context.Background()
	backend := newMemBackend()
	p := New("storage")
	k := kernel.New(kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "object", Enabled: true, Config: map[string]any{
			"use_erasure_for_large_objects": false, // disabled — default path
		}},
	}})
	_ = k.Registry().Provide("storage", backend)
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}
	_ = p.CreateBucket(ctx, "b")
	_, err := p.PutObject(ctx, "b", "k", bytes.NewReader([]byte("small body")), api.ObjectMeta{})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	rec, err := p.getVersionRecord(ctx, "b", "k", "")
	if err != nil {
		t.Fatalf("getVersionRecord: %v", err)
	}
	if rec.StoredViaErasure {
		t.Fatalf("expected normal block storage when use_erasure_for_large_objects is false")
	}
}
