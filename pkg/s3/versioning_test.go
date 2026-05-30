package s3_test

import (
	"testing"

	"github.com/oarkflow/velocity"
	. "github.com/oarkflow/velocity/pkg/s3"
)

func openVersioningDB(t *testing.T) *velocity.DB {
	t.Helper()
	db, err := velocity.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestBucketVersioning(t *testing.T) {
	t.Run("SetVersioning and GetVersioning roundtrip", func(t *testing.T) {
		db := openVersioningDB(t)
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
		db := openVersioningDB(t)
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
		db := openVersioningDB(t)
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
		db := openVersioningDB(t)
		defer db.Close()

		bv := NewBucketVersioning(db)
		if bv.IsVersioningEnabled("never-set") {
			t.Fatal("expected IsVersioningEnabled == false for unset bucket")
		}
	})

	t.Run("ShouldCreateVersion returns true and ID for Enabled", func(t *testing.T) {
		db := openVersioningDB(t)
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
		db := openVersioningDB(t)
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
		db := openVersioningDB(t)
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
		db := openVersioningDB(t)
		defer db.Close()

		bv := NewBucketVersioning(db)
		err := bv.SetVersioning("bad", VersioningState("InvalidState"))
		if err == nil {
			t.Fatal("expected error for invalid versioning state")
		}
	})
}
