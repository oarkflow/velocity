package velocity

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sort"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Erasure Encoder Tests
// ---------------------------------------------------------------------------

func TestErasureEncoder(t *testing.T) {
	t.Run("NewErasureEncoder with valid config", func(t *testing.T) {
		enc, err := NewErasureEncoder(ErasureConfig{DataShards: 4, ParityShards: 2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if enc == nil {
			t.Fatal("expected non-nil encoder")
		}
	})

	t.Run("NewErasureEncoder rejects invalid shard counts", func(t *testing.T) {
		cases := []struct {
			name   string
			config ErasureConfig
		}{
			{"zero data shards", ErasureConfig{DataShards: 0, ParityShards: 2}},
			{"negative data shards", ErasureConfig{DataShards: -1, ParityShards: 2}},
			{"zero parity shards", ErasureConfig{DataShards: 4, ParityShards: 0}},
			{"negative parity shards", ErasureConfig{DataShards: 4, ParityShards: -1}},
			{"exceeds GF(2^8) limit", ErasureConfig{DataShards: 200, ParityShards: 200}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				enc, err := NewErasureEncoder(tc.config)
				if err == nil {
					t.Fatalf("expected error for config %+v, got encoder %v", tc.config, enc)
				}
			})
		}
	})

	t.Run("Encode produces correct number of shards", func(t *testing.T) {
		enc := mustEncoder(t, 4, 2)
		data := []byte("hello, erasure coding world!")
		shards, err := enc.Encode(data)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		want := 4 + 2
		if len(shards) != want {
			t.Fatalf("expected %d shards, got %d", want, len(shards))
		}
		// All shards must be the same length
		for i := 1; i < len(shards); i++ {
			if len(shards[i]) != len(shards[0]) {
				t.Fatalf("shard %d length %d != shard 0 length %d", i, len(shards[i]), len(shards[0]))
			}
		}
	})

	t.Run("Decode reconstructs original data from all shards", func(t *testing.T) {
		enc := mustEncoder(t, 4, 2)
		data := []byte("the quick brown fox jumps over the lazy dog")
		shards, err := enc.Encode(data)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}

		got, err := enc.Decode(shards, len(data))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("decoded data mismatch:\n  got:  %q\n  want: %q", got, data)
		}
	})

	t.Run("Decode reconstructs when parity shards are missing", func(t *testing.T) {
		enc := mustEncoder(t, 4, 2)
		data := []byte("reconstruction test with missing parity shards")
		shards, err := enc.Encode(data)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}

		// Remove both parity shards (indices 4 and 5)
		shards[4] = nil
		shards[5] = nil

		got, err := enc.Decode(shards, len(data))
		if err != nil {
			t.Fatalf("decode with missing parity: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("decoded data mismatch after parity loss")
		}
	})

	t.Run("Decode reconstructs when some data shards are missing", func(t *testing.T) {
		enc := mustEncoder(t, 4, 2)
		data := []byte("reconstruction test with missing data shards")
		shards, err := enc.Encode(data)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}

		// Remove 2 data shards (within parity tolerance)
		shards[0] = nil
		shards[2] = nil

		got, err := enc.Decode(shards, len(data))
		if err != nil {
			t.Fatalf("decode with missing data shards: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("decoded data mismatch after data shard loss")
		}
	})

	t.Run("Decode fails when too many shards missing", func(t *testing.T) {
		enc := mustEncoder(t, 4, 2)
		data := []byte("too many missing shards test")
		shards, err := enc.Encode(data)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}

		// Remove 3 shards (more than 2 parity can recover)
		shards[0] = nil
		shards[1] = nil
		shards[4] = nil

		_, err = enc.Decode(shards, len(data))
		if err == nil {
			t.Fatal("expected error when too many shards are missing")
		}
	})

	t.Run("Verify returns true for valid shard set", func(t *testing.T) {
		enc := mustEncoder(t, 4, 2)
		data := []byte("verify valid shards")
		shards, err := enc.Encode(data)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}

		if !enc.Verify(shards) {
			t.Fatal("Verify returned false for valid shards")
		}
	})

	t.Run("Verify returns false when shard is corrupted", func(t *testing.T) {
		enc := mustEncoder(t, 4, 2)
		data := []byte("verify corrupted shards")
		shards, err := enc.Encode(data)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}

		// Corrupt a data shard by flipping bytes
		for i := range shards[0] {
			shards[0][i] ^= 0xFF
		}

		if enc.Verify(shards) {
			t.Fatal("Verify returned true for corrupted shards")
		}
	})

	t.Run("Round-trip encode then decode various sizes", func(t *testing.T) {
		enc := mustEncoder(t, 4, 2)
		sizes := []struct {
			name string
			size int
		}{
			{"small 13 bytes", 13},
			{"medium 4096 bytes", 4096},
			{"1MB", 1 << 20},
		}
		for _, tc := range sizes {
			t.Run(tc.name, func(t *testing.T) {
				data := make([]byte, tc.size)
				if _, err := rand.Read(data); err != nil {
					t.Fatalf("rand.Read: %v", err)
				}

				shards, err := enc.Encode(data)
				if err != nil {
					t.Fatalf("encode: %v", err)
				}

				got, err := enc.Decode(shards, len(data))
				if err != nil {
					t.Fatalf("decode: %v", err)
				}
				if !bytes.Equal(got, data) {
					t.Fatalf("round-trip mismatch for size %d", tc.size)
				}
			})
		}
	})

	t.Run("Empty data handling", func(t *testing.T) {
		enc := mustEncoder(t, 4, 2)
		data := []byte{}
		shards, err := enc.Encode(data)
		if err != nil {
			t.Fatalf("encode empty: %v", err)
		}
		// Empty data produces zero-length shards; the encoder must not panic.
		total := 4 + 2
		if len(shards) != total {
			t.Fatalf("expected %d shards, got %d", total, len(shards))
		}
		for i, s := range shards {
			if len(s) != 0 {
				t.Fatalf("shard %d should be empty, got length %d", i, len(s))
			}
		}
		// Decode of zero-length shards may error; verify it does not panic.
		_, _ = enc.Decode(shards, 0)
	})
}

// mustEncoder is a test helper that creates an encoder or fails.
func mustEncoder(t *testing.T, data, parity int) *ErasureEncoder {
	t.Helper()
	enc, err := NewErasureEncoder(ErasureConfig{DataShards: data, ParityShards: parity})
	if err != nil {
		t.Fatalf("NewErasureEncoder(%d,%d): %v", data, parity, err)
	}
	return enc
}

// ---------------------------------------------------------------------------
// Consistent Hash Ring Tests
// ---------------------------------------------------------------------------

func TestConsistentHashRing(t *testing.T) {
	t.Run("AddNode adds to ring and NodeCount returns correct count", func(t *testing.T) {
		ring := NewConsistentHashRing(64)
		ring.AddNode("node-1")
		ring.AddNode("node-2")
		ring.AddNode("node-3")

		if got := ring.NodeCount(); got != 3 {
			t.Fatalf("expected 3 nodes, got %d", got)
		}
	})

	t.Run("RemoveNode removes from ring", func(t *testing.T) {
		ring := NewConsistentHashRing(64)
		ring.AddNode("node-1")
		ring.AddNode("node-2")
		ring.RemoveNode("node-1")

		if ring.HasNode("node-1") {
			t.Fatal("node-1 should have been removed")
		}
		if got := ring.NodeCount(); got != 1 {
			t.Fatalf("expected 1 node after removal, got %d", got)
		}
	})

	t.Run("GetNode returns consistent results for same key", func(t *testing.T) {
		ring := NewConsistentHashRing(64)
		ring.AddNode("node-a")
		ring.AddNode("node-b")
		ring.AddNode("node-c")

		key := "my-important-key"
		first := ring.GetNode(key)
		for i := 0; i < 100; i++ {
			got := ring.GetNode(key)
			if got != first {
				t.Fatalf("inconsistent result on iteration %d: got %q, want %q", i, got, first)
			}
		}
	})

	t.Run("GetNode distributes across nodes", func(t *testing.T) {
		ring := NewConsistentHashRing(256)
		ring.AddNode("node-x")
		ring.AddNode("node-y")
		ring.AddNode("node-z")

		counts := map[string]int{}
		numKeys := 10000
		for i := 0; i < numKeys; i++ {
			node := ring.GetNode(fmt.Sprintf("key-%d", i))
			counts[node]++
		}

		// Each of the 3 nodes should get at least 10% of keys (very conservative)
		minExpected := numKeys / 10
		for node, count := range counts {
			if count < minExpected {
				t.Errorf("node %s got only %d keys (minimum expected %d)", node, count, minExpected)
			}
		}
		if len(counts) != 3 {
			t.Fatalf("expected keys on 3 nodes, got %d", len(counts))
		}
	})

	t.Run("GetNodes returns N distinct nodes for replication", func(t *testing.T) {
		ring := NewConsistentHashRing(64)
		ring.AddNode("r1")
		ring.AddNode("r2")
		ring.AddNode("r3")
		ring.AddNode("r4")

		nodes := ring.GetNodes("repl-key", 3)
		if len(nodes) != 3 {
			t.Fatalf("expected 3 nodes, got %d", len(nodes))
		}

		seen := map[string]bool{}
		for _, n := range nodes {
			if seen[n] {
				t.Fatalf("duplicate node %q in GetNodes result", n)
			}
			seen[n] = true
		}
	})

	t.Run("GetNodes caps at available node count", func(t *testing.T) {
		ring := NewConsistentHashRing(64)
		ring.AddNode("only-1")
		ring.AddNode("only-2")

		nodes := ring.GetNodes("some-key", 10)
		if len(nodes) != 2 {
			t.Fatalf("expected 2 nodes (capped), got %d", len(nodes))
		}
	})

	t.Run("GetRebalanceMap returns source nodes affected by new node", func(t *testing.T) {
		ring := NewConsistentHashRing(64)
		ring.AddNode("existing-1")
		ring.AddNode("existing-2")

		rebalanceMap := ring.GetRebalanceMap("new-node")
		// The map should contain at least one existing node that will lose ranges
		if len(rebalanceMap) == 0 {
			t.Fatal("expected non-empty rebalance map")
		}
		for src := range rebalanceMap {
			if src != "existing-1" && src != "existing-2" {
				t.Errorf("unexpected source node %q in rebalance map", src)
			}
		}
	})

	t.Run("HasNode and ListNodes", func(t *testing.T) {
		ring := NewConsistentHashRing(64)
		ring.AddNode("alpha")
		ring.AddNode("beta")

		if !ring.HasNode("alpha") {
			t.Fatal("expected HasNode(alpha) == true")
		}
		if ring.HasNode("gamma") {
			t.Fatal("expected HasNode(gamma) == false")
		}

		nodes := ring.ListNodes()
		sort.Strings(nodes)
		if len(nodes) != 2 || nodes[0] != "alpha" || nodes[1] != "beta" {
			t.Fatalf("expected [alpha beta], got %v", nodes)
		}
	})

	t.Run("Empty ring returns empty string and nil", func(t *testing.T) {
		ring := NewConsistentHashRing(64)

		if got := ring.GetNode("any-key"); got != "" {
			t.Fatalf("expected empty string from empty ring, got %q", got)
		}
		if got := ring.GetNodes("any-key", 3); got != nil {
			t.Fatalf("expected nil from empty ring GetNodes, got %v", got)
		}
	})
}

// ---------------------------------------------------------------------------
// Bucket Versioning Tests
// ---------------------------------------------------------------------------

func TestBucketVersioning(t *testing.T) {
	t.Run("SetVersioning and GetVersioning roundtrip", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		bv := NewBucketVersioning(db)
		if err := bv.SetVersioning("test-bucket", VersioningEnabled); err != nil {
			t.Fatalf("SetVersioning: %v", err)
		}

		got, err := bv.GetVersioning("test-bucket")
		if err != nil {
			t.Fatalf("GetVersioning: %v", err)
		}
		if got != VersioningEnabled {
			t.Fatalf("expected %q, got %q", VersioningEnabled, got)
		}
	})

	t.Run("IsVersioningEnabled returns true for Enabled", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		bv := NewBucketVersioning(db)
		if err := bv.SetVersioning("b1", VersioningEnabled); err != nil {
			t.Fatalf("SetVersioning: %v", err)
		}
		if !bv.IsVersioningEnabled("b1") {
			t.Fatal("expected IsVersioningEnabled == true for Enabled bucket")
		}
	})

	t.Run("IsVersioningEnabled returns false for Suspended", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		bv := NewBucketVersioning(db)
		if err := bv.SetVersioning("b2", VersioningSuspended); err != nil {
			t.Fatalf("SetVersioning: %v", err)
		}
		if bv.IsVersioningEnabled("b2") {
			t.Fatal("expected IsVersioningEnabled == false for Suspended bucket")
		}
	})

	t.Run("IsVersioningEnabled returns false for Unset", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		bv := NewBucketVersioning(db)
		// Never set versioning for this bucket
		if bv.IsVersioningEnabled("never-set") {
			t.Fatal("expected IsVersioningEnabled == false for unset bucket")
		}
	})

	t.Run("ShouldCreateVersion returns true and ID for Enabled", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		bv := NewBucketVersioning(db)
		if err := bv.SetVersioning("v-enabled", VersioningEnabled); err != nil {
			t.Fatalf("SetVersioning: %v", err)
		}

		create, versionID := bv.ShouldCreateVersion("v-enabled")
		if !create {
			t.Fatal("expected ShouldCreateVersion == true for Enabled")
		}
		if versionID == "" || versionID == "null" {
			t.Fatalf("expected non-null version ID, got %q", versionID)
		}
	})

	t.Run("ShouldCreateVersion returns false and null for Suspended", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		bv := NewBucketVersioning(db)
		if err := bv.SetVersioning("v-suspended", VersioningSuspended); err != nil {
			t.Fatalf("SetVersioning: %v", err)
		}

		create, versionID := bv.ShouldCreateVersion("v-suspended")
		if create {
			t.Fatal("expected ShouldCreateVersion == false for Suspended")
		}
		if versionID != "null" {
			t.Fatalf("expected version ID %q, got %q", "null", versionID)
		}
	})

	t.Run("Default state is VersioningUnset", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		bv := NewBucketVersioning(db)
		state, err := bv.GetVersioning("nonexistent-bucket")
		if err != nil {
			t.Fatalf("GetVersioning: %v", err)
		}
		if state != VersioningUnset {
			t.Fatalf("expected %q for default, got %q", VersioningUnset, state)
		}
	})

	t.Run("Invalid state rejected", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		bv := NewBucketVersioning(db)
		err := bv.SetVersioning("bad", VersioningState("InvalidState"))
		if err == nil {
			t.Fatal("expected error for invalid versioning state")
		}
	})
}

// ---------------------------------------------------------------------------
// Object Lock Manager Tests
// ---------------------------------------------------------------------------

func TestObjectLockManager(t *testing.T) {
	t.Run("SetBucketObjectLock and GetBucketObjectLock roundtrip", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		olm := NewObjectLockManager(db)
		config := ObjectLockConfig{
			Enabled: true,
			DefaultRetention: &ObjectLockRetentionRule{
				Mode: LockModeGovernance,
				Days: 30,
			},
		}
		if err := olm.SetBucketObjectLock("lock-bucket", config); err != nil {
			t.Fatalf("SetBucketObjectLock: %v", err)
		}

		got, err := olm.GetBucketObjectLock("lock-bucket")
		if err != nil {
			t.Fatalf("GetBucketObjectLock: %v", err)
		}
		if !got.Enabled {
			t.Fatal("expected Enabled == true")
		}
		if got.DefaultRetention == nil {
			t.Fatal("expected non-nil DefaultRetention")
		}
		if got.DefaultRetention.Mode != LockModeGovernance {
			t.Fatalf("expected mode %q, got %q", LockModeGovernance, got.DefaultRetention.Mode)
		}
		if got.DefaultRetention.Days != 30 {
			t.Fatalf("expected 30 days, got %d", got.DefaultRetention.Days)
		}
	})

	t.Run("SetBucketObjectLock validates retention mode", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		olm := NewObjectLockManager(db)
		config := ObjectLockConfig{
			Enabled: true,
			DefaultRetention: &ObjectLockRetentionRule{
				Mode: ObjectLockMode("INVALID"),
				Days: 10,
			},
		}
		err := olm.SetBucketObjectLock("bad-bucket", config)
		if err == nil {
			t.Fatal("expected error for invalid retention mode")
		}
	})

	t.Run("SetObjectRetention with GOVERNANCE mode", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		olm := NewObjectLockManager(db)
		future := time.Now().Add(24 * time.Hour)
		err := olm.SetObjectRetention("bucket", "obj1", ObjectRetention{
			Mode:            LockModeGovernance,
			RetainUntilDate: future,
		})
		if err != nil {
			t.Fatalf("SetObjectRetention GOVERNANCE: %v", err)
		}

		got, err := olm.GetObjectRetention("bucket", "obj1")
		if err != nil {
			t.Fatalf("GetObjectRetention: %v", err)
		}
		if got == nil {
			t.Fatal("expected non-nil retention")
		}
		if got.Mode != LockModeGovernance {
			t.Fatalf("expected GOVERNANCE, got %q", got.Mode)
		}
	})

	t.Run("SetObjectRetention with COMPLIANCE mode", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		olm := NewObjectLockManager(db)
		future := time.Now().Add(24 * time.Hour)
		err := olm.SetObjectRetention("bucket", "obj2", ObjectRetention{
			Mode:            LockModeCompliance,
			RetainUntilDate: future,
		})
		if err != nil {
			t.Fatalf("SetObjectRetention COMPLIANCE: %v", err)
		}

		got, err := olm.GetObjectRetention("bucket", "obj2")
		if err != nil {
			t.Fatalf("GetObjectRetention: %v", err)
		}
		if got == nil {
			t.Fatal("expected non-nil retention")
		}
		if got.Mode != LockModeCompliance {
			t.Fatalf("expected COMPLIANCE, got %q", got.Mode)
		}
	})

	t.Run("SetObjectRetention rejects past dates", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		olm := NewObjectLockManager(db)
		past := time.Now().Add(-24 * time.Hour)
		err := olm.SetObjectRetention("bucket", "obj-past", ObjectRetention{
			Mode:            LockModeGovernance,
			RetainUntilDate: past,
		})
		if err == nil {
			t.Fatal("expected error for past retain-until date")
		}
	})

	t.Run("COMPLIANCE mode cannot be shortened", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		olm := NewObjectLockManager(db)
		longFuture := time.Now().Add(48 * time.Hour)
		shortFuture := time.Now().Add(24 * time.Hour)

		// Set long COMPLIANCE retention first
		err := olm.SetObjectRetention("bucket", "obj-comp", ObjectRetention{
			Mode:            LockModeCompliance,
			RetainUntilDate: longFuture,
		})
		if err != nil {
			t.Fatalf("SetObjectRetention (long): %v", err)
		}

		// Attempt to shorten should fail
		err = olm.SetObjectRetention("bucket", "obj-comp", ObjectRetention{
			Mode:            LockModeCompliance,
			RetainUntilDate: shortFuture,
		})
		if err == nil {
			t.Fatal("expected error when shortening COMPLIANCE retention")
		}
	})

	t.Run("SetObjectLegalHold ON and OFF", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		olm := NewObjectLockManager(db)

		// Set ON
		if err := olm.SetObjectLegalHold("bucket", "hold-obj", ObjectLegalHold{Status: "ON"}); err != nil {
			t.Fatalf("SetObjectLegalHold ON: %v", err)
		}
		hold, err := olm.GetObjectLegalHold("bucket", "hold-obj")
		if err != nil {
			t.Fatalf("GetObjectLegalHold: %v", err)
		}
		if hold.Status != "ON" {
			t.Fatalf("expected ON, got %q", hold.Status)
		}

		// Set OFF
		if err := olm.SetObjectLegalHold("bucket", "hold-obj", ObjectLegalHold{Status: "OFF"}); err != nil {
			t.Fatalf("SetObjectLegalHold OFF: %v", err)
		}
		hold, err = olm.GetObjectLegalHold("bucket", "hold-obj")
		if err != nil {
			t.Fatalf("GetObjectLegalHold: %v", err)
		}
		if hold.Status != "OFF" {
			t.Fatalf("expected OFF, got %q", hold.Status)
		}
	})

	t.Run("IsObjectLocked returns true for legal hold ON", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		olm := NewObjectLockManager(db)
		if err := olm.SetObjectLegalHold("bucket", "locked-hold", ObjectLegalHold{Status: "ON"}); err != nil {
			t.Fatalf("SetObjectLegalHold: %v", err)
		}

		locked, err := olm.IsObjectLocked("bucket", "locked-hold")
		if err != nil {
			t.Fatalf("IsObjectLocked: %v", err)
		}
		if !locked {
			t.Fatal("expected object to be locked via legal hold")
		}
	})

	t.Run("IsObjectLocked returns true for active retention", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		olm := NewObjectLockManager(db)
		future := time.Now().Add(24 * time.Hour)
		if err := olm.SetObjectRetention("bucket", "locked-ret", ObjectRetention{
			Mode:            LockModeCompliance,
			RetainUntilDate: future,
		}); err != nil {
			t.Fatalf("SetObjectRetention: %v", err)
		}

		locked, err := olm.IsObjectLocked("bucket", "locked-ret")
		if err != nil {
			t.Fatalf("IsObjectLocked: %v", err)
		}
		if !locked {
			t.Fatal("expected object to be locked via active retention")
		}
	})

	t.Run("CanDeleteObject returns false for legal hold", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		olm := NewObjectLockManager(db)
		if err := olm.SetObjectLegalHold("bucket", "del-hold", ObjectLegalHold{Status: "ON"}); err != nil {
			t.Fatalf("SetObjectLegalHold: %v", err)
		}

		allowed, reason, err := olm.CanDeleteObject("bucket", "del-hold", "admin", true)
		if err != nil {
			t.Fatalf("CanDeleteObject: %v", err)
		}
		if allowed {
			t.Fatal("expected deletion to be denied under legal hold")
		}
		if reason == "" {
			t.Fatal("expected non-empty denial reason")
		}
	})

	t.Run("CanDeleteObject returns false for COMPLIANCE retention", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		olm := NewObjectLockManager(db)
		future := time.Now().Add(24 * time.Hour)
		if err := olm.SetObjectRetention("bucket", "del-comp", ObjectRetention{
			Mode:            LockModeCompliance,
			RetainUntilDate: future,
		}); err != nil {
			t.Fatalf("SetObjectRetention: %v", err)
		}

		allowed, reason, err := olm.CanDeleteObject("bucket", "del-comp", "admin", true)
		if err != nil {
			t.Fatalf("CanDeleteObject: %v", err)
		}
		if allowed {
			t.Fatal("expected deletion to be denied under COMPLIANCE retention")
		}
		if reason == "" {
			t.Fatal("expected non-empty denial reason")
		}
	})

	t.Run("CanDeleteObject returns true for GOVERNANCE with bypass", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		olm := NewObjectLockManager(db)
		future := time.Now().Add(24 * time.Hour)
		if err := olm.SetObjectRetention("bucket", "del-gov", ObjectRetention{
			Mode:            LockModeGovernance,
			RetainUntilDate: future,
		}); err != nil {
			t.Fatalf("SetObjectRetention: %v", err)
		}

		// Without bypass should fail
		allowed, _, err := olm.CanDeleteObject("bucket", "del-gov", "user", false)
		if err != nil {
			t.Fatalf("CanDeleteObject (no bypass): %v", err)
		}
		if allowed {
			t.Fatal("expected denial without bypass flag")
		}

		// With bypass should succeed
		allowed, _, err = olm.CanDeleteObject("bucket", "del-gov", "admin", true)
		if err != nil {
			t.Fatalf("CanDeleteObject (bypass): %v", err)
		}
		if !allowed {
			t.Fatal("expected deletion allowed with GOVERNANCE bypass")
		}
	})

	t.Run("ApplyDefaultRetention applies bucket-level defaults", func(t *testing.T) {
		db := mustOpenDB(t)
		defer db.Close()

		olm := NewObjectLockManager(db)

		// Configure bucket with default 30-day GOVERNANCE retention
		config := ObjectLockConfig{
			Enabled: true,
			DefaultRetention: &ObjectLockRetentionRule{
				Mode: LockModeGovernance,
				Days: 30,
			},
		}
		if err := olm.SetBucketObjectLock("def-bucket", config); err != nil {
			t.Fatalf("SetBucketObjectLock: %v", err)
		}

		// Apply default retention to a new object
		if err := olm.ApplyDefaultRetention("def-bucket", "new-obj"); err != nil {
			t.Fatalf("ApplyDefaultRetention: %v", err)
		}

		// Verify object now has retention
		ret, err := olm.GetObjectRetention("def-bucket", "new-obj")
		if err != nil {
			t.Fatalf("GetObjectRetention: %v", err)
		}
		if ret == nil {
			t.Fatal("expected retention to be set after ApplyDefaultRetention")
		}
		if ret.Mode != LockModeGovernance {
			t.Fatalf("expected GOVERNANCE mode, got %q", ret.Mode)
		}

		// The retain-until date should be roughly 30 days from now
		expectedMin := time.Now().Add(29 * 24 * time.Hour)
		expectedMax := time.Now().Add(31 * 24 * time.Hour)
		if ret.RetainUntilDate.Before(expectedMin) || ret.RetainUntilDate.After(expectedMax) {
			t.Fatalf("retain-until date %v not within expected 30-day range", ret.RetainUntilDate)
		}
	})
}

// mustOpenDB is a test helper that opens a temporary database or fails.
func mustOpenDB(t *testing.T) *DB {
	t.Helper()
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return db
}
