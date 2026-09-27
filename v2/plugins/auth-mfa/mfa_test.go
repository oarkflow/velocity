package authmfa

import (
	"context"
	"encoding/base32"
	"sync"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// memBackend is a minimal in-test api.StorageBackend stub, avoiding a
// dependency on another agent's in-flight plugins/storage-mem package.
type memBackend struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemBackend() *memBackend { return &memBackend{data: map[string][]byte{}} }

func (m *memBackend) Get(_ context.Context, key []byte) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[string(key)]
	return v, ok, nil
}
func (m *memBackend) Put(_ context.Context, e api.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[string(e.Key)] = e.Value
	return nil
}
func (m *memBackend) Delete(_ context.Context, key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, string(key))
	return nil
}
func (m *memBackend) Batch(ctx context.Context, ops []api.BatchOp) error {
	for _, op := range ops {
		if op.Delete {
			if err := m.Delete(ctx, op.Entry.Key); err != nil {
				return err
			}
			continue
		}
		if err := m.Put(ctx, op.Entry); err != nil {
			return err
		}
	}
	return nil
}
func (m *memBackend) Scan(context.Context, []byte) (api.Iterator, error) { return nil, nil }
func (m *memBackend) Snapshot(context.Context) (api.Snapshot, error)     { return nil, nil }
func (m *memBackend) Close() error                                       { return nil }

// RFC 6238 Appendix B test vector: SHA1, 8-digit codes, secret
// "12345678901234567890" (raw ASCII, NOT base32), T0=0, X=30s. At
// T=59s the time-counter is 1 and the published code is "94287082".
// Since truncation is `value mod 10^digits`, and 10^6 divides 10^8, the
// last 6 digits of that 8-digit code ("287082") must equal our 6-digit
// HOTP output for the same counter — this cross-validates hotp() against
// a published, independent test vector rather than just testing itself.
func TestHOTP_RFC6238Vector(t *testing.T) {
	secret := []byte("12345678901234567890")
	got8 := hotp(SHA1, secret, 1, 8)
	if got8 != "94287082" {
		t.Fatalf("8-digit HOTP(counter=1) = %q, want 94287082 (RFC 6238 Appendix B vector)", got8)
	}
	got6 := hotp(SHA1, secret, 1, 6)
	if got6 != "287082" {
		t.Fatalf("6-digit HOTP(counter=1) = %q, want 287082 (last 6 digits of RFC vector)", got6)
	}
}

func TestGenerateAndValidateCode(t *testing.T) {
	ctx := context.Background()
	p := NewPlugin("")
	p.storage = newMemBackend()
	p.health = api.Health{Status: "ok"}

	secretB32, err := p.GenerateSecret(ctx, "alice")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}

	counter := time.Now().Unix() / int64(p.period.Seconds())
	code := hotp(p.algorithm, secretBytes, uint64(counter), p.digits)

	ok, err := p.ValidateCode(ctx, "alice", code)
	if err != nil {
		t.Fatalf("ValidateCode: %v", err)
	}
	if !ok {
		t.Fatal("expected correct code to validate")
	}

	ok, err = p.ValidateCode(ctx, "alice", "000000")
	if err != nil {
		t.Fatalf("ValidateCode wrong code: %v", err)
	}
	if ok && code != "000000" {
		t.Fatal("expected wrong code to be rejected")
	}
}

func TestValidateCode_SkewTolerance(t *testing.T) {
	ctx := context.Background()
	p := NewPlugin("")
	p.storage = newMemBackend()
	p.health = api.Health{Status: "ok"}

	secretB32, err := p.GenerateSecret(ctx, "bob")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	secretBytes, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)

	currentCounter := time.Now().Unix() / int64(p.period.Seconds())

	// One step back: within the +/-1 skew window, must validate.
	oneStepBack := hotp(p.algorithm, secretBytes, uint64(currentCounter-1), p.digits)
	ok, err := p.ValidateCode(ctx, "bob", oneStepBack)
	if err != nil {
		t.Fatalf("ValidateCode (one step back): %v", err)
	}
	if !ok {
		t.Fatal("expected code one time-step behind to validate within skew tolerance")
	}

	// Two steps away: outside the +/-1 skew window, must NOT validate
	// (unless it happens to collide with a code inside the window, which
	// we guard against by only asserting rejection when it actually
	// differs from every code in [-1, +1]).
	twoStepsAway := hotp(p.algorithm, secretBytes, uint64(currentCounter+2), p.digits)
	collides := false
	for i := -1; i <= 1; i++ {
		if hotp(p.algorithm, secretBytes, uint64(currentCounter+int64(i)), p.digits) == twoStepsAway {
			collides = true
		}
	}
	if !collides {
		ok, err = p.ValidateCode(ctx, "bob", twoStepsAway)
		if err != nil {
			t.Fatalf("ValidateCode (two steps away): %v", err)
		}
		if ok {
			t.Fatal("expected code two time-steps away to be rejected (outside skew tolerance)")
		}
	}
}

func TestValidateCode_UnenrolledSubject(t *testing.T) {
	p := NewPlugin("")
	p.storage = newMemBackend()
	_, err := p.ValidateCode(context.Background(), "nobody", "123456")
	if err == nil {
		t.Fatal("expected an error validating a code for a subject with no enrolled secret")
	}
}
