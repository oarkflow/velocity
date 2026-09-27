package kv

import (
	"bytes"
	"context"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	cryptoxchacha "github.com/oarkflow/velocity/v2/plugins/crypto-xchacha"
)

// realCryptoProvider boots the actual crypto-xchacha plugin against a real
// kernel and returns the api.CryptoProvider it registers — using the real
// AEAD implementation here (not a fake) is what lets these tests prove
// something meaningful about the sealed bytes and AAD binding.
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

func TestEncrypt_RoundTripAndRawBytesAreNotPlaintext(t *testing.T) {
	ctx := context.Background()
	backend := newMemBackend()
	p := &Plugin{storage: backend, crypto: realCryptoProvider(t)}

	plaintext := []byte("this must not appear on disk in the clear")
	if err := p.Put(ctx, "secret-key", plaintext); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Round trip through the API returns the correct plaintext.
	got, ok, err := p.Get(ctx, "secret-key")
	if err != nil || !ok || !bytes.Equal(got, plaintext) {
		t.Fatalf("Get = %q, %v, %v, want %q", got, ok, err, plaintext)
	}

	// The RAW bytes actually sitting in the storage backend must NOT be
	// the plaintext — this is the proof encryption actually happened, not
	// just that the API still works.
	raw, ok, err := backend.Get(ctx, []byte("secret-key"))
	if err != nil || !ok {
		t.Fatalf("raw Get: ok=%v err=%v", ok, err)
	}
	if bytes.Equal(raw, plaintext) {
		t.Fatalf("raw storage bytes equal plaintext — encryption did not happen: %q", raw)
	}
	if bytes.Contains(raw, plaintext) {
		t.Fatalf("raw storage bytes contain the plaintext as a substring: %q", raw)
	}
}

func TestEncrypt_ScanAndIncrAlsoRoundTrip(t *testing.T) {
	ctx := context.Background()
	backend := newMemBackend()
	p := &Plugin{storage: backend, crypto: realCryptoProvider(t)}

	if err := p.Put(ctx, "a1", []byte("alpha")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := p.Put(ctx, "a2", []byte("beta")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	items, _, err := p.Scan(ctx, "a", 10, "")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if string(items["a1"]) != "alpha" || string(items["a2"]) != "beta" {
		t.Fatalf("Scan returned wrong plaintext: %+v", items)
	}

	if _, err := p.Incr(ctx, "counter", 5); err != nil {
		t.Fatalf("Incr: %v", err)
	}
	next, err := p.Incr(ctx, "counter", 3)
	if err != nil {
		t.Fatalf("Incr: %v", err)
	}
	if next != 8 {
		t.Fatalf("Incr = %d, want 8", next)
	}
	raw, _, _ := backend.Get(ctx, []byte("counter"))
	if bytes.Equal(raw, []byte("8")) {
		t.Fatal("counter's raw storage bytes are plaintext \"8\" — Incr is not encrypting")
	}
}

func TestEncrypt_TamperedCiphertextIsRejected(t *testing.T) {
	ctx := context.Background()
	backend := newMemBackend()
	p := &Plugin{storage: backend, crypto: realCryptoProvider(t)}

	if err := p.Put(ctx, "k", []byte("original value")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	raw, ok, err := backend.Get(ctx, []byte("k"))
	if err != nil || !ok {
		t.Fatalf("raw Get: ok=%v err=%v", ok, err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0xFF // flip a bit in the auth tag
	if err := backend.Put(ctx, api.Entry{Key: []byte("k"), Value: tampered}); err != nil {
		t.Fatalf("writing tampered bytes: %v", err)
	}

	if _, _, err := p.Get(ctx, "k"); err == nil {
		t.Fatal("expected Get to reject tampered ciphertext, got nil error")
	}
}

func TestEncrypt_InitFailsWithoutCryptoWhenRequested(t *testing.T) {
	m := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "kv", Enabled: true, Config: map[string]any{"encrypt": true}},
	}}
	k := kernel.New(m)
	p := New("storage-lsm")
	// Provide a storage backend directly so the failure we're testing is
	// specifically about the missing crypto dependency, not storage.
	if err := k.Registry().Provide("storage", newMemBackend()); err != nil {
		t.Fatalf("Provide storage: %v", err)
	}
	err := p.Init(context.Background(), k)
	if err == nil {
		t.Fatal("expected Init to fail when encrypt=true and no crypto plugin is registered, got nil")
	}
}

func TestEncrypt_DisabledByDefaultIsUnchanged(t *testing.T) {
	m := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "kv", Enabled: true, Config: map[string]any{}},
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
	if err := p.Put(ctx, "plain", []byte("hello")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	raw, ok, err := backend.Get(ctx, []byte("plain"))
	if err != nil || !ok || string(raw) != "hello" {
		t.Fatalf("raw bytes should be plaintext \"hello\" by default, got %q, ok=%v err=%v", raw, ok, err)
	}
}
