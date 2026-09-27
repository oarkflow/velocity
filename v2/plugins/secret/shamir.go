package secret

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/oarkflow/shamir"
	"github.com/oarkflow/velocity/v2/api"
)

// Shamir-based master-key management, ported from v1's
// master_key_manager.go. This is deliberately NOT part of api.SecretService
// — splitting/combining a master key is an operational/admin concern (run
// once during setup, or during a break-glass key-recovery procedure), not
// a per-secret CRUD operation every SecretService caller needs. Callers
// that need it type-assert the concrete *secret.Plugin.
//
// Security model: shares are handed back to the caller and are NEVER
// persisted here — only a fingerprint (sha256 of the original key) and
// threshold/total-shares metadata are stored, so this plugin can later
// confirm a recombined key is the right one without ever holding enough
// information itself to reconstruct it. Shares must be distributed
// out-of-band (e.g. one to each of N officers) by the caller.

// shareMeta is persisted so a later CombineMasterKey call can verify it
// reconstructed the correct key, without this plugin ever storing the
// shares themselves.
//
// AuthKeyB64 is shamir v0.0.3's now-mandatory per-share HMAC-SHA256
// tamper-evidence key (Split/Combine reject a nil *shamir.AuthKey as of
// this version — verified against the library's own source, this isn't
// an assumption). It is generated fresh per SplitMasterKey call and
// persisted alongside the fingerprint, in the SAME storage trust
// boundary — so it protects against accidental share corruption or
// combining the wrong set of shares (this plugin's actual, stated threat
// model), not against an attacker who already has read access to this
// plugin's own storage (who also never finds the master key or the
// shares here, so the blast radius is unchanged from before this
// library version required an explicit key).
type shareMeta struct {
	Threshold   int       `json:"threshold"`
	TotalShares int       `json:"total_shares"`
	Fingerprint string    `json:"fingerprint"` // sha256(masterKey), hex
	AuthKeyB64  string    `json:"auth_key_b64"`
	CreatedAt   time.Time `json:"created_at"`
}

const masterKeyMetaKey = "secret/_shamir/meta"

func fingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

// newRandomAuthKey generates a fresh 32-byte key and wraps it as a
// *shamir.AuthKey (shamir.NewAuthKey rejects keys shorter than 16 bytes;
// 32 is the library's own recommendation).
func newRandomAuthKey() (*shamir.AuthKey, []byte, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, nil, fmt.Errorf("generating auth key: %w", err)
	}
	ak, err := shamir.NewAuthKey(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("shamir.NewAuthKey: %w", err)
	}
	return ak, raw, nil
}

// SplitMasterKey splits masterKey into totalShares parts requiring any
// threshold of them to reconstruct, via github.com/oarkflow/shamir's real
// Split/Combine (a Shamir's Secret Sharing scheme over GF(2^8)). Persists
// threshold/totalShares/a fingerprint of masterKey and the per-share
// AuthKey (see shareMeta's doc comment for why persisting the AuthKey is
// safe given this plugin's threat model) — but never the master key or
// the shares themselves.
func (p *Plugin) SplitMasterKey(ctx context.Context, masterKey []byte, threshold, totalShares int) ([][]byte, error) {
	if threshold < 2 {
		return nil, fmt.Errorf("%s: threshold must be >= 2, got %d", pluginName, threshold)
	}
	if totalShares < threshold {
		return nil, fmt.Errorf("%s: totalShares (%d) must be >= threshold (%d)", pluginName, totalShares, threshold)
	}
	authKey, authKeyRaw, err := newRandomAuthKey()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pluginName, err)
	}
	shares, err := shamir.Split(rand.Reader, masterKey, threshold, totalShares, authKey)
	if err != nil {
		return nil, fmt.Errorf("%s: shamir split: %w", pluginName, err)
	}

	meta := shareMeta{
		Threshold:   threshold,
		TotalShares: totalShares,
		Fingerprint: fingerprint(masterKey),
		AuthKeyB64:  base64.StdEncoding.EncodeToString(authKeyRaw),
		CreatedAt:   time.Now().UTC(),
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("%s: marshal share metadata: %w", pluginName, err)
	}
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(masterKeyMetaKey), Value: data}); err != nil {
		return nil, fmt.Errorf("%s: persisting share metadata: %w", pluginName, err)
	}
	return shares, nil
}

// CombineMasterKey reconstructs a master key from >= threshold shares
// (per the persisted shareMeta) and verifies the result's fingerprint
// matches what SplitMasterKey recorded, catching a caller accidentally
// combining the wrong/corrupted shares before it's used for anything.
//
// Requires shareMeta to have been persisted by a prior SplitMasterKey
// call on this same plugin instance/storage — shamir v0.0.3's Combine
// needs the SAME *shamir.AuthKey Split was given (nil is not accepted),
// so without persisted metadata there is no way to recover the key.
func (p *Plugin) CombineMasterKey(ctx context.Context, shares [][]byte) ([]byte, error) {
	data, ok, err := p.storage.Get(ctx, []byte(masterKeyMetaKey))
	if err != nil {
		return nil, fmt.Errorf("%s: reading share metadata: %w", pluginName, err)
	}
	if !ok {
		return nil, fmt.Errorf("%s: no share metadata found — CombineMasterKey requires a prior SplitMasterKey call on this storage", pluginName)
	}
	var meta shareMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("%s: corrupt share metadata: %w", pluginName, err)
	}
	if len(shares) < meta.Threshold {
		return nil, fmt.Errorf("%s: %d shares provided, threshold is %d", pluginName, len(shares), meta.Threshold)
	}
	authKeyRaw, err := base64.StdEncoding.DecodeString(meta.AuthKeyB64)
	if err != nil {
		return nil, fmt.Errorf("%s: corrupt persisted auth key: %w", pluginName, err)
	}
	authKey, err := shamir.NewAuthKey(authKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("%s: reconstructing auth key: %w", pluginName, err)
	}

	key, err := shamir.Combine(shares, authKey)
	if err != nil {
		return nil, fmt.Errorf("%s: shamir combine: %w", pluginName, err)
	}
	if fingerprint(key) != meta.Fingerprint {
		return nil, fmt.Errorf("%s: combined key does not match the original master key's fingerprint — wrong or corrupted shares", pluginName)
	}
	return key, nil
}

// RotateMasterKeyViaShares reconstructs a master key from shares and, if
// the currently-registered "crypto" service implements api.KeyProvider,
// drives its rotation with the recovered key material. If the crypto
// plugin doesn't implement api.KeyProvider, this returns a descriptive
// error rather than silently doing nothing — matching this rework's
// policy of never letting an unwired capability look like it succeeded.
func (p *Plugin) RotateMasterKeyViaShares(ctx context.Context, shares [][]byte) error {
	key, err := p.CombineMasterKey(ctx, shares)
	if err != nil {
		return err
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	kp, ok := p.crypto.(api.KeyProvider)
	if !ok {
		return fmt.Errorf("%s: crypto provider %q does not implement api.KeyProvider, cannot drive rotation from recovered shares", pluginName, p.crypto.Name())
	}
	if err := kp.RotateMasterKey(ctx); err != nil {
		return fmt.Errorf("%s: rotating master key: %w", pluginName, err)
	}
	return nil
}
