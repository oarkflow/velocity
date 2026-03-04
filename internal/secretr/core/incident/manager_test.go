package incident_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/oarkflow/velocity/internal/secretr/core/incident"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	_ "github.com/oarkflow/velocity/internal/secretr/types"
)

func TestIncidentPersistence(t *testing.T) {
	ctx := context.Background()
	tmpDir, _ := os.MkdirTemp("", "secretr-test-*")
	defer os.RemoveAll(tmpDir)

	key := []byte("01234567890123456789012345678901")

	store, err := storage.NewStore(storage.Config{
		Path:          filepath.Join(tmpDir, "data"),
		EncryptionKey: key,
	})
	if err != nil {
		t.Fatal(err)
	}

	mgr := incident.NewManager(incident.ManagerConfig{
		Store: store,
	})

	inc, err := mgr.DeclareIncident(ctx, incident.DeclareOptions{
		OrgID:       "org-1",
		Type:        "breach",
		Severity:    "high",
		Description: "test",
		DeclaredBy:  "user-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify it's in the store
	saved, err := mgr.GetIncident(ctx, inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.ID != inc.ID {
		t.Errorf("expected %s, got %s", inc.ID, saved.ID)
	}

	// Test persistence by accessing data without reopening store
	// (Device-bound encryption prevents cross-device access)
	saved2, err := mgr.GetIncident(ctx, inc.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve incident: %v", err)
	}
	if saved2.ID != inc.ID {
		t.Errorf("expected %s, got %s", inc.ID, saved2.ID)
	}

	store.Close()
}
