package erasure

import (
	"bytes"
	"testing"
)

func TestCodecEncodeDecodeRoundTrip(t *testing.T) {
	codec, err := NewCodec(DefaultConfig())
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	data := []byte("the quick brown fox jumps over the lazy dog, repeated for length ")
	data = bytes.Repeat(data, 5)

	shards, err := codec.Encode(data)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(shards) != DefaultConfig().TotalShards() {
		t.Fatalf("expected %d shards, got %d", DefaultConfig().TotalShards(), len(shards))
	}

	ok, err := codec.Verify(shards)
	if err != nil || !ok {
		t.Fatalf("Verify on freshly-encoded shards: ok=%v err=%v", ok, err)
	}

	got, err := codec.Decode(shards, len(data))
	if err != nil {
		t.Fatalf("Decode with all shards present: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("round trip mismatch: got %q want %q", got, data)
	}
}

func TestCodecReconstructsUpToParityCount(t *testing.T) {
	cfg := Config{DataShards: 4, ParityShards: 2}
	codec, err := NewCodec(cfg)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	data := []byte("erasure coding must survive losing up to ParityShards shards")

	shards, err := codec.Encode(data)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Zero out exactly ParityShards (2) shards -- a mix of data and parity.
	damaged := append([][]byte(nil), shards...)
	lostIdx := []int{1, 4} // one data shard, one parity shard
	for _, i := range lostIdx {
		damaged[i] = nil
	}

	got, err := codec.Decode(damaged, len(data))
	if err != nil {
		t.Fatalf("Decode with %d shards missing (== ParityShards): %v", len(lostIdx), err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("reconstruction mismatch: got %q want %q", got, data)
	}
}

func TestCodecFailsBeyondParityCount(t *testing.T) {
	cfg := Config{DataShards: 4, ParityShards: 2}
	codec, err := NewCodec(cfg)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	data := []byte("losing more shards than parity allows must fail, not silently corrupt")

	shards, err := codec.Encode(data)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	damaged := append([][]byte(nil), shards...)
	// Lose 3 shards when only 2 parity shards exist -- must error.
	for _, i := range []int{0, 1, 4} {
		damaged[i] = nil
	}

	if _, err := codec.Decode(damaged, len(data)); err == nil {
		t.Fatalf("expected Decode to fail when more shards are missing than ParityShards allows, got nil error")
	}
}

func TestCodecVerifyDetectsCorruption(t *testing.T) {
	codec, err := NewCodec(DefaultConfig())
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	data := []byte("verify must detect a single corrupted byte in any shard")
	shards, err := codec.Encode(data)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Corrupt one byte in a data shard.
	corrupted := append([][]byte(nil), shards...)
	tampered := append([]byte(nil), corrupted[0]...)
	tampered[0] ^= 0xFF
	corrupted[0] = tampered

	ok, err := codec.Verify(corrupted)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatalf("expected Verify to detect corruption, got ok=true")
	}
}
