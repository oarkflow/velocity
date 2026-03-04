package share

import (
	"context"
	"testing"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/storage"
)

func TestOfflinePackageExportImport(t *testing.T) {
	store, err := storage.NewStore(storage.Config{
		Path:          t.TempDir(),
		EncryptionKey: []byte("01234567890123456789012345678901"),
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	m := NewManager(ManagerConfig{Store: store})
	ctx := context.Background()

	recipient := []byte("abcdefghijklmnopqrstuvwxyz123456")
	shareObj, err := m.CreateShare(ctx, CreateShareOptions{
		Type:            "secret",
		ResourceID:      "db.password",
		CreatorID:       "creator-1",
		RecipientPubKey: recipient,
		ExpiresIn:       time.Hour,
	})
	if err != nil {
		t.Fatalf("create share: %v", err)
	}

	pkg, err := m.CreateOfflinePackage(ctx, OfflinePackageOptions{
		ShareID:         shareObj.ID,
		ResourceData:    []byte("super-secret"),
		RecipientPubKey: recipient,
		ExpiresIn:       time.Hour,
	})
	if err != nil {
		t.Fatalf("create offline package: %v", err)
	}

	data, err := m.ExportOfflinePackage(ctx, pkg.ID)
	if err != nil {
		t.Fatalf("export offline package: %v", err)
	}

	imported, err := m.ImportOfflinePackage(ctx, data, recipient)
	if err != nil {
		t.Fatalf("import offline package: %v", err)
	}

	if string(imported.Data) != "super-secret" {
		t.Fatalf("decrypted payload mismatch: %q", string(imported.Data))
	}
}
