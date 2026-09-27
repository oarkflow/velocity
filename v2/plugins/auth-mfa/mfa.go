// Package authmfa implements Velocity v2's MFA plugin: RFC 4226 (HOTP) /
// RFC 6238 (TOTP) one-time codes, ported from v1's pkg/auth/mfa.go.
// Per-subject secrets are persisted via a looked-up api.StorageBackend.
// Registers under the fixed service name "mfa" as an api.MFAProvider.
package authmfa

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

const pluginName = "mfa"

// Algorithm selects the HMAC hash used for code generation. v1 defaulted
// to SHA1 for authenticator-app compatibility (Google Authenticator and
// most TOTP apps assume SHA1 unless told otherwise) — v2 keeps that
// default but exposes SHA256/SHA512 for deployments that control both
// sides (server and authenticator) and want a stronger hash.
type Algorithm string

const (
	SHA1   Algorithm = "SHA1"
	SHA256 Algorithm = "SHA256"
	SHA512 Algorithm = "SHA512"
)

// Plugin implements api.Plugin and api.MFAProvider.
type Plugin struct {
	storageDep string
	storage    api.StorageBackend
	health     api.Health

	algorithm Algorithm
	digits    int
	period    time.Duration
	skewSteps int
}

// NewPlugin constructs the MFA plugin. storageDep names the concrete
// storage plugin to depend on for boot ordering (Registry lookups always
// use the fixed service name "storage"). Empty defaults to "storage-lsm".
func NewPlugin(storageDep string) *Plugin {
	if storageDep == "" {
		storageDep = "storage-lsm"
	}
	return &Plugin{
		storageDep: storageDep,
		algorithm:  SHA1,
		digits:     6,
		period:     30 * time.Second,
		skewSteps:  1,
	}
}

func (p *Plugin) Name() string           { return pluginName }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return []string{p.storageDep} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.storage = k.Registry().MustLookup("storage").(api.StorageBackend)

	cfg := k.Config().Scoped(pluginName)
	if alg := cfg.String("algorithm", ""); alg != "" {
		p.algorithm = Algorithm(alg)
	}
	p.digits = cfg.Int("digits", p.digits)
	p.period = cfg.Duration("period", p.period)
	p.skewSteps = cfg.Int("skew_steps", p.skewSteps)

	if err := k.Registry().Provide(pluginName, p); err != nil {
		return err
	}
	p.health = api.Health{Status: "ok"}
	return nil
}

func (p *Plugin) Start(context.Context) error { return nil }
func (p *Plugin) Stop(context.Context) error  { return nil }
func (p *Plugin) Health() api.Health          { return p.health }

var (
	_ api.Plugin      = (*Plugin)(nil)
	_ api.MFAProvider = (*Plugin)(nil)
)

func secretKey(subject string) []byte { return []byte("mfa/secret/" + subject) }

// GenerateSecret creates a new random 160-bit TOTP secret for subject,
// persists it, and returns the base32 encoding (no padding, matching the
// format authenticator apps expect in a provisioning URI).
func (p *Plugin) GenerateSecret(ctx context.Context, subject string) (string, error) {
	if subject == "" {
		return "", fmt.Errorf("%s: subject is required", pluginName)
	}
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("%s: generating secret: %w", pluginName, err)
	}
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	if err := p.storage.Put(ctx, api.Entry{Key: secretKey(subject), Value: []byte(b32)}); err != nil {
		return "", fmt.Errorf("%s: persisting secret for %q: %w", pluginName, subject, err)
	}
	return b32, nil
}

// ValidateCode checks code against subject's stored secret for the
// current TOTP time step, tolerating +/- skewSteps of clock drift.
func (p *Plugin) ValidateCode(ctx context.Context, subject, code string) (bool, error) {
	if subject == "" {
		return false, fmt.Errorf("%s: subject is required", pluginName)
	}
	if len(code) != p.digits {
		return false, nil
	}
	data, ok, err := p.storage.Get(ctx, secretKey(subject))
	if err != nil {
		return false, fmt.Errorf("%s: reading secret for %q: %w", pluginName, subject, err)
	}
	if !ok {
		return false, fmt.Errorf("%s: no MFA secret enrolled for %q", pluginName, subject)
	}
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(data))
	if err != nil {
		return false, fmt.Errorf("%s: corrupt secret for %q: %w", pluginName, subject, err)
	}

	currentCounter := time.Now().Unix() / int64(p.period.Seconds())
	for i := -p.skewSteps; i <= p.skewSteps; i++ {
		if hotp(p.algorithm, secretBytes, uint64(currentCounter+int64(i)), p.digits) == code {
			return true, nil
		}
	}
	return false, nil
}

// hotp implements RFC 4226's HOTP algorithm: HMAC(secret, counter),
// dynamic truncation, then reduce mod 10^digits. TOTP (RFC 6238) is HOTP
// with counter = unixTime/period, which is how ValidateCode calls this.
func hotp(alg Algorithm, secret []byte, counter uint64, digits int) string {
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	var h hash.Hash
	switch alg {
	case SHA256:
		h = hmac.New(sha256.New, secret)
	case SHA512:
		h = hmac.New(sha512.New, secret)
	default:
		h = hmac.New(sha1.New, secret)
	}
	h.Write(counterBytes)
	sum := h.Sum(nil)

	offset := sum[len(sum)-1] & 0x0F
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7FFFFFFF

	divisor := uint32(1)
	for range digits {
		divisor *= 10
	}
	code %= divisor
	return fmt.Sprintf("%0*d", digits, code)
}
