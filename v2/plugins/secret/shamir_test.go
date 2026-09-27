package secret

import (
	"bytes"
	"context"
	"testing"
)

func TestShamir_SplitAndCombine(t *testing.T) {
	ctx := context.Background()
	p := &Plugin{storage: newMemBackend()}

	masterKey := []byte("this-is-a-32-byte-test-masterky!")

	shares, err := p.SplitMasterKey(ctx, masterKey, 3, 5)
	if err != nil {
		t.Fatalf("SplitMasterKey: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("got %d shares, want 5", len(shares))
	}

	// Any 3 of the 5 shares must reconstruct the original key.
	combined, err := p.CombineMasterKey(ctx, shares[1:4])
	if err != nil {
		t.Fatalf("CombineMasterKey with 3 shares: %v", err)
	}
	if !bytes.Equal(combined, masterKey) {
		t.Fatalf("combined key = %q, want %q", combined, masterKey)
	}
}

func TestShamir_BelowThresholdRejected(t *testing.T) {
	ctx := context.Background()
	p := &Plugin{storage: newMemBackend()}

	masterKey := []byte("another-32-byte-test-master-key")
	shares, err := p.SplitMasterKey(ctx, masterKey, 3, 5)
	if err != nil {
		t.Fatalf("SplitMasterKey: %v", err)
	}

	// Only 2 of the 5 shares — below the threshold of 3. The persisted
	// shareMeta.Threshold check must reject this explicitly rather than
	// silently returning a wrong key.
	_, err = p.CombineMasterKey(ctx, shares[:2])
	if err == nil {
		t.Fatal("expected an error combining fewer shares than the threshold")
	}
}

func TestShamir_WrongSharesDetected(t *testing.T) {
	ctx := context.Background()
	p := &Plugin{storage: newMemBackend()}

	keyA := []byte("key-A-32-bytes-aaaaaaaaaaaaaaaaa")
	keyB := []byte("key-B-32-bytes-bbbbbbbbbbbbbbbbb")

	sharesA, err := p.SplitMasterKey(ctx, keyA, 3, 5)
	if err != nil {
		t.Fatalf("split keyA: %v", err)
	}
	// A second split overwrites the persisted shareMeta fingerprint (only
	// one master key's metadata is tracked at a time in this simple
	// scheme) — splitting keyB, then trying to combine keyA's shares must
	// now be caught by the fingerprint mismatch check.
	if _, err := p.SplitMasterKey(ctx, keyB, 3, 5); err != nil {
		t.Fatalf("split keyB: %v", err)
	}

	_, err = p.CombineMasterKey(ctx, sharesA[:3])
	if err == nil {
		t.Fatal("expected fingerprint mismatch error combining stale keyA shares after keyB was split")
	}
}
