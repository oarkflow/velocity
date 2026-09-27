package cryptofips

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

type stubEventBus struct{}

func (stubEventBus) Publish(ctx context.Context, ev api.Event)              {}
func (stubEventBus) Subscribe(topic string, h api.Handler) api.Subscription { return stubSub{} }

type stubSub struct{}

func (stubSub) Unsubscribe() {}

type stubRegistry struct{ services map[string]any }

func (r *stubRegistry) Provide(name string, svc any) error { r.services[name] = svc; return nil }
func (r *stubRegistry) Lookup(name string) (any, bool)     { s, ok := r.services[name]; return s, ok }
func (r *stubRegistry) MustLookup(name string) any         { return r.services[name] }

type stubConfig struct{ data map[string]any }

func (c stubConfig) Scoped(string) api.PluginConfig { return stubPluginConfig{data: c.data} }

type stubPluginConfig struct{ data map[string]any }

func (c stubPluginConfig) Raw() map[string]any { return c.data }
func (c stubPluginConfig) String(key, def string) string {
	if v, ok := c.data[key].(string); ok {
		return v
	}
	return def
}
func (c stubPluginConfig) Int(key string, def int) int {
	if v, ok := c.data[key].(int); ok {
		return v
	}
	return def
}
func (c stubPluginConfig) Bool(key string, def bool) bool {
	if v, ok := c.data[key].(bool); ok {
		return v
	}
	return def
}
func (c stubPluginConfig) Duration(key string, def time.Duration) time.Duration { return def }

type stubLogger struct{}

func (stubLogger) Debug(string, ...any) {}
func (stubLogger) Info(string, ...any)  {}
func (stubLogger) Warn(string, ...any)  {}
func (stubLogger) Error(string, ...any) {}

type stubKernel struct {
	reg *stubRegistry
	cfg stubConfig
}

func (k stubKernel) Registry() api.Registry     { return k.reg }
func (k stubKernel) Events() api.EventBus       { return stubEventBus{} }
func (k stubKernel) Config() api.ConfigProvider { return k.cfg }
func (k stubKernel) Logger() api.Logger         { return stubLogger{} }

func newTestKernel(cfgData map[string]any) stubKernel {
	return stubKernel{reg: &stubRegistry{services: map[string]any{}}, cfg: stubConfig{data: cfgData}}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	p := New()
	k := newTestKernel(nil)
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}
	cp, _ := k.Registry().Lookup("crypto")
	provider := cp.(api.CryptoProvider)
	if provider.Name() != "aes256gcm-fips" {
		t.Fatalf("unexpected provider name: %s", provider.Name())
	}

	plaintext := []byte("fips payload")
	aad := []byte("aad")
	ct, err := provider.Encrypt(context.Background(), plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := provider.Decrypt(context.Background(), ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round trip mismatch")
	}
}

func TestDisabledRefusesToLoad(t *testing.T) {
	p := New()
	k := newTestKernel(map[string]any{"enabled": false})
	if err := p.Init(context.Background(), k); err == nil {
		t.Fatalf("expected Init to fail when enabled=false")
	}
}

func TestPasswordDerivationRejectsShortSalt(t *testing.T) {
	p := New()
	k := newTestKernel(map[string]any{"password": "hunter2", "salt": "short"})
	if err := p.Init(context.Background(), k); err == nil {
		t.Fatalf("expected Init to reject salt shorter than 16 bytes")
	}
}

func TestPasswordDerivationSucceedsWithValidSaltAndIterations(t *testing.T) {
	p := New()
	k := newTestKernel(map[string]any{
		"password":          "hunter2-hunter2",
		"salt":              "0123456789abcdef",
		"pbkdf2_iterations": 10000,
	})
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}
}

func TestValidateFIPSCompliance(t *testing.T) {
	if err := ValidateFIPSCompliance(KeyDerivation{Iterations: 9999, SaltLength: 32}); err == nil {
		t.Fatalf("expected rejection of <10000 iterations")
	}
	if err := ValidateFIPSCompliance(KeyDerivation{Iterations: 10000, SaltLength: 15}); err == nil {
		t.Fatalf("expected rejection of <16-byte salt")
	}
	if err := ValidateFIPSCompliance(KeyDerivation{Iterations: 10000, SaltLength: 16}); err != nil {
		t.Fatalf("expected valid config to pass: %v", err)
	}
}

func TestStreamRoundTrip(t *testing.T) {
	p := New()
	k := newTestKernel(nil)
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}
	cp, _ := k.Registry().Lookup("crypto")
	provider := cp.(api.CryptoProvider)

	var buf bytes.Buffer
	w, err := provider.EncryptStream(&buf)
	if err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	payload := bytes.Repeat([]byte("fips-stream-"), 10000)
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r, err := provider.DecryptStream(&buf)
	if err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("stream round trip mismatch: got %d want %d bytes", len(got), len(payload))
	}
}
