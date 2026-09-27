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
	cryptoxchacha "github.com/oarkflow/velocity/v2/plugins/crypto-xchacha"
	"github.com/oarkflow/velocity/v2/plugins/erasure"
)

// realCryptoProvider boots the actual crypto-xchacha plugin against a real
// kernel and returns the api.CryptoProvider it registers.
func realCryptoProvider(t *testing.T) api.CryptoProvider {
	t.Helper()
	m := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "crypto-xchacha", Enabled: true, Config: map[string]any{
			"key": "01234567890123456789012345678901", // 32 bytes, fixed for reproducible tests
		}},
	}}
	k := kernel.New(m)
	cp := cryptoxchacha.New()
	if err := cp.Init(context.Background(), k); err != nil {
		t.Fatalf("crypto-xchacha Init: %v", err)
	}
	svc, ok := k.Registry().Lookup("crypto")
	if !ok {
		t.Fatal("crypto-xchacha did not register \"crypto\"")
	}
	provider, ok := svc.(api.CryptoProvider)
	if !ok {
		t.Fatal("\"crypto\" service does not implement api.CryptoProvider")
	}
	return provider
}

func TestEncrypt_PutGetRoundTripAndRawBlocksAreNotPlaintext(t *testing.T) {
	ctx := context.Background()
	backend := newMemBackend()
	p := &Plugin{storage: backend, stopCh: make(chan struct{}), lifecycleInterval: time.Minute, crypto: realCryptoProvider(t)}
	if err := p.CreateBucket(ctx, "b"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	plaintext := []byte("this object body must not appear on disk in the clear")
	meta, err := p.PutObject(ctx, "b", "k", bytes.NewReader(plaintext), api.ObjectMeta{})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	rc, _, err := p.GetObject(ctx, "b", "k", "")
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("GetObject = %q, want %q", got, plaintext)
	}

	// The raw block bytes in the storage backend must NOT be the
	// plaintext — proof encryption actually happened.
	raw, ok, err := backend.Get(ctx, []byte(blockKey("b", "k", meta.VersionID, 0)))
	if err != nil || !ok {
		t.Fatalf("raw block Get: ok=%v err=%v", ok, err)
	}
	if bytes.Contains(raw, plaintext) {
		t.Fatalf("raw block bytes contain the plaintext: %q", raw)
	}
}

func TestEncrypt_RangeReadStillEfficientWithEncryptionOn(t *testing.T) {
	ctx := context.Background()
	backend := newCountingBackend()
	p := &Plugin{storage: backend, stopCh: make(chan struct{}), lifecycleInterval: time.Minute, crypto: realCryptoProvider(t)}
	_ = p.CreateBucket(ctx, "big")

	body := make([]byte, 20*1024*1024)
	rand.New(rand.NewSource(1)).Read(body)
	meta, err := p.PutObject(ctx, "big", "blob", bytes.NewReader(body), api.ObjectMeta{})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	backend.getBytes = 0
	rc, _, err := p.GetObject(ctx, "big", "blob", "")
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	fullBody, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(fullBody, body) {
		t.Fatal("full GetObject with encryption on did not reconstruct the original body correctly")
	}
	fullReadBytes := backend.getBytes

	backend.getBytes = 0
	backend.getCalls = 0
	rangeRC, rangeMeta, err := p.GetObjectRange(ctx, "big", "blob", "", 100, 199)
	if err != nil {
		t.Fatalf("GetObjectRange: %v", err)
	}
	rangeData, _ := io.ReadAll(rangeRC)
	rangeRC.Close()
	if !bytes.Equal(rangeData, body[100:200]) {
		t.Fatal("range read with encryption on returned wrong bytes")
	}
	if rangeMeta.VersionID != meta.VersionID {
		t.Fatal("unexpected version id on range read")
	}

	// The whole point: decrypting only the block(s) actually needed keeps
	// this O(range), not O(size), even with encryption enabled — same
	// property the pre-existing (unencrypted) range-read test verifies.
	if backend.getBytes >= fullReadBytes/10 {
		t.Fatalf("range read with encryption on read %d bytes from storage, full object read %d bytes — encryption broke the O(1)-blocks optimization", backend.getBytes, fullReadBytes)
	}
	t.Logf("full read: %d bytes; encrypted range read: %d bytes (%d Get calls)", fullReadBytes, backend.getBytes, backend.getCalls)
}

func TestEncrypt_TamperedBlockIsRejected(t *testing.T) {
	ctx := context.Background()
	backend := newMemBackend()
	p := &Plugin{storage: backend, stopCh: make(chan struct{}), lifecycleInterval: time.Minute, crypto: realCryptoProvider(t)}
	_ = p.CreateBucket(ctx, "b")

	meta, err := p.PutObject(ctx, "b", "k", bytes.NewReader([]byte("original content")), api.ObjectMeta{})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	key := []byte(blockKey("b", "k", meta.VersionID, 0))
	raw, ok, err := backend.Get(ctx, key)
	if err != nil || !ok {
		t.Fatalf("raw Get: ok=%v err=%v", ok, err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0xFF
	if err := backend.Put(ctx, api.Entry{Key: key, Value: tampered}); err != nil {
		t.Fatalf("writing tampered block: %v", err)
	}

	if _, _, err := p.GetObject(ctx, "b", "k", ""); err == nil {
		t.Fatal("expected GetObject to reject a tampered block, got nil error")
	}
}

// TestEncrypt_ErasureBackedObjectIsAlsoSealed proves the whole-blob
// sealWhole/unsealWhole path used for erasure-coded storage works
// correctly: PutObject through the erasure path with encryption on, read
// it back correctly, and confirm the raw shard bytes on disk are not the
// plaintext either.
func TestEncrypt_ErasureBackedObjectIsAlsoSealed(t *testing.T) {
	ctx := context.Background()
	backend := newMemBackend()

	// Wire crypto-xchacha and erasure into one shared registry, mirroring
	// TestErasureBackedObject_SurvivesShardCorruption's two-kernel pattern
	// (Init reads config from k2's manifest, but both plugins publish
	// into the same underlying Registry via explicit Provide calls).
	k1 := kernel.New(kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "crypto-xchacha", Enabled: true, Config: map[string]any{"key": "01234567890123456789012345678901"}},
	}})
	if err := k1.Registry().Provide("storage", backend); err != nil {
		t.Fatalf("provide storage: %v", err)
	}
	cp := cryptoxchacha.New()
	if err := cp.Init(ctx, k1); err != nil {
		t.Fatalf("crypto Init: %v", err)
	}
	cryptoSvc, _ := k1.Registry().Lookup("crypto")

	erasurePlugin := erasure.NewPlugin("storage")
	if err := erasurePlugin.Init(ctx, k1); err != nil {
		t.Fatalf("erasure Init: %v", err)
	}

	k2 := kernel.New(kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "object", Enabled: true, Config: map[string]any{
			"use_erasure_for_large_objects": true,
			"erasure_threshold_bytes":       float64(16),
			"encrypt":                       true,
		}},
	}})
	if err := k2.Registry().Provide("storage", backend); err != nil {
		t.Fatalf("provide storage: %v", err)
	}
	if err := k2.Registry().Provide("erasure", erasurePlugin); err != nil {
		t.Fatalf("provide erasure: %v", err)
	}
	if err := k2.Registry().Provide("crypto", cryptoSvc); err != nil {
		t.Fatalf("provide crypto: %v", err)
	}

	objPlugin := New("storage")
	if err := objPlugin.Init(ctx, k2); err != nil {
		t.Fatalf("object Init: %v", err)
	}
	if objPlugin.erasure == nil || objPlugin.crypto == nil {
		t.Fatalf("expected object plugin to have picked up both erasure and crypto")
	}

	_ = objPlugin.CreateBucket(ctx, "docs")
	plaintext := []byte("this body is over the 16-byte erasure threshold and must be sealed")
	meta, err := objPlugin.PutObject(ctx, "docs", "important", bytes.NewReader(plaintext), api.ObjectMeta{})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	rec, err := objPlugin.getVersionRecord(ctx, "docs", "important", "")
	if err != nil || !rec.StoredViaErasure {
		t.Fatalf("expected erasure-backed version, err=%v rec=%+v", err, rec)
	}

	rc, _, err := objPlugin.GetObject(ctx, "docs", "important", "")
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("GetObject = %q, want %q", got, plaintext)
	}

	// Confirm at least one raw shard on disk is not the plaintext.
	dataKey := objectVersionDataKey("docs", "important", meta.VersionID)
	it, err := backend.Scan(ctx, []byte("erasure/"))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	foundShard := false
	for it.Next() {
		k := string(it.Key())
		if bytes.Contains([]byte(k), []byte(dataKey)) && bytes.Contains([]byte(k), []byte("/shard/")) {
			foundShard = true
			if bytes.Contains(it.Value(), plaintext) {
				t.Fatalf("shard %q contains the plaintext — erasure-path encryption did not happen", k)
			}
		}
	}
	it.Close()
	if !foundShard {
		t.Fatal("did not find any shard entries to inspect — test setup problem")
	}
}

func TestEncrypt_InitFailsWithoutCryptoWhenRequested(t *testing.T) {
	m := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "object", Enabled: true, Config: map[string]any{"encrypt": true}},
	}}
	k := kernel.New(m)
	if err := k.Registry().Provide("storage", newMemBackend()); err != nil {
		t.Fatalf("Provide storage: %v", err)
	}
	p := New("storage-lsm")
	if err := p.Init(context.Background(), k); err == nil {
		t.Fatal("expected Init to fail when encrypt=true and no crypto plugin is registered, got nil")
	}
}

func TestEncrypt_DisabledByDefaultIsUnchanged(t *testing.T) {
	m := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "object", Enabled: true, Config: map[string]any{}},
	}}
	k := kernel.New(m)
	backend := newMemBackend()
	if err := k.Registry().Provide("storage", backend); err != nil {
		t.Fatalf("Provide storage: %v", err)
	}
	p := New("storage-lsm")
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v (encrypt defaults to false, must not require crypto)", err)
	}
	ctx := context.Background()
	_ = p.CreateBucket(ctx, "b")
	meta, err := p.PutObject(ctx, "b", "k", bytes.NewReader([]byte("hello")), api.ObjectMeta{})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	raw, ok, err := backend.Get(ctx, []byte(blockKey("b", "k", meta.VersionID, 0)))
	if err != nil || !ok || string(raw) != "hello" {
		t.Fatalf("raw block should be plaintext \"hello\" by default, got %q, ok=%v err=%v", raw, ok, err)
	}
}
