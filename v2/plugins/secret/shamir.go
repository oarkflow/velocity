package secret

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
type shareMeta struct {
	Threshold   int       `json:"threshold"`
	TotalShares int       `json:"total_shares"`
	Fingerprint string    `json:"fingerprint"` // sha256(masterKey), hex
	CreatedAt   time.Time `json:"created_at"`
}

const masterKeyMetaKey = "secret/_shamir/meta"

func fingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

// SplitMasterKey splits masterKey into totalShares parts requiring any
// threshold of them to reconstruct (github.com/oarkflow/shamir's
// Split/Combine — a straight Shamir's Secret Sharing scheme over
// GF(2^8), no separate auth-key wrapper in this library version, unlike
// v1's shamir.Split(rand.Reader, key, t, n, authKey) signature). Persists
// only threshold/totalShares/a fingerprint of masterKey, never the key or
// the shares.
func (p *Plugin) SplitMasterKey(ctx context.Context, masterKey []byte, threshold, totalShares int) ([][]byte, error) {
	if threshold < 2 {
		return nil, fmt.Errorf("%s: threshold must be >= 2, got %d", pluginName, threshold)
	}
	if totalShares < threshold {
		return nil, fmt.Errorf("%s: totalShares (%d) must be >= threshold (%d)", pluginName, totalShares, threshold)
	}
	shares, err := shamir.Split(masterKey, threshold, totalShares)
	if err != nil {
		return nil, fmt.Errorf("%s: shamir split: %w", pluginName, err)
	}

	meta := shareMeta{
		Threshold:   threshold,
		TotalShares: totalShares,
		Fingerprint: fingerprint(masterKey),
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
func (p *Plugin) CombineMasterKey(ctx context.Context, shares [][]byte) ([]byte, error) {
	key, err := shamir.Combine(shares)
	if err != nil {
		return nil, fmt.Errorf("%s: shamir combine: %w", pluginName, err)
	}

	data, ok, err := p.storage.Get(ctx, []byte(masterKeyMetaKey))
	if err != nil {
		return nil, fmt.Errorf("%s: reading share metadata: %w", pluginName, err)
	}
	if ok {
		var meta shareMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			return nil, fmt.Errorf("%s: corrupt share metadata: %w", pluginName, err)
		}
		if len(shares) < meta.Threshold {
			return nil, fmt.Errorf("%s: %d shares provided, threshold is %d", pluginName, len(shares), meta.Threshold)
		}
		if fingerprint(key) != meta.Fingerprint {
			return nil, fmt.Errorf("%s: combined key does not match the original master key's fingerprint — wrong or corrupted shares", pluginName)
		}
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
