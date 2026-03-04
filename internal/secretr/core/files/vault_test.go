package files

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

type mockKeyProvider struct{}

func (m *mockKeyProvider) GetKey(ctx context.Context, id types.ID) ([]byte, error) {
	return make([]byte, 32), nil
}
func (m *mockKeyProvider) GetCurrentKeyID(ctx context.Context) (types.ID, error) {
	return "key1", nil
}

func TestFileUploadDownload(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := storage.NewStore(storage.Config{
		Path:          tmpDir,
		EncryptionKey: make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	// Use small chunk size to force chunking
	vault := NewVault(VaultConfig{
		Store:      store,
		KeyManager: &mockKeyProvider{},
		ChunkSize:  10,
	})

	ctx := context.Background()

	// 1. Upload
	content := []byte("This is a long test string to force multiple chunks.")
	reader := bytes.NewReader(content)

	file, err := vault.Upload(ctx, UploadOptions{
		Name:         "test.txt",
		OriginalName: "test.txt",
		ContentType:  "text/plain",
		Reader:       reader,
		UploaderID:   "user1",
	})
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	if file.ChunkCount <= 1 {
		t.Errorf("Expected multiple chunks, got %d", file.ChunkCount)
	}

	// 2. Download
	var writer bytes.Buffer
	err = vault.Download(ctx, "test.txt", DownloadOptions{
		AccessorID: "user1",
	}, &writer)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	if writer.String() != string(content) {
		t.Errorf("Content mismatch. Got %q, want %q", writer.String(), string(content))
	}
}

func TestFileSealing(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := storage.NewStore(storage.Config{Path: tmpDir, EncryptionKey: make([]byte, 32)})
	defer store.Close()
	vault := NewVault(VaultConfig{Store: store, KeyManager: &mockKeyProvider{}})
	ctx := context.Background()

	vault.Upload(ctx, UploadOptions{Name: "seal.txt", Reader: strings.NewReader("data"), UploaderID: "user1"})

	// Seal
	if err := vault.Seal(ctx, "seal.txt", "admin"); err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Try download (should fail)
	var w bytes.Buffer
	if err := vault.Download(ctx, "seal.txt", DownloadOptions{AccessorID: "user1"}, &w); err != ErrFileSealed {
		t.Errorf("Expected ErrFileSealed, got %v", err)
	}

	// Unseal
	if err := vault.Unseal(ctx, "seal.txt", "admin"); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	// Try download (should succeed)
	if err := vault.Download(ctx, "seal.txt", DownloadOptions{AccessorID: "user1"}, &w); err != nil {
		t.Errorf("Download failed after unseal: %v", err)
	}
}

func TestProtectedDownload(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := storage.NewStore(storage.Config{Path: tmpDir, EncryptionKey: make([]byte, 32)})
	defer store.Close()

	pm := NewProtectionManager(ProtectionManagerConfig{Store: store})
	vault := NewVault(VaultConfig{
		Store:      store,
		KeyManager: &mockKeyProvider{},
		Protection: pm,
	})
	ctx := context.Background()

	// Upload
	vault.Upload(ctx, UploadOptions{Name: "protected.txt", Reader: strings.NewReader("secret"), UploaderID: "user1"})

	// Get File ID
	file, _ := vault.GetMetadata(ctx, "protected.txt")

	// Create Policy: Max Download = 1
	err := pm.CreatePolicy(ctx, &FileProtectionPolicy{
		FileID:           file.ID,
		Name:             "Limit Downloads",
		MaxDownloadCount: 1,
		TrackAccess:      true,
		AllowCopy:        true,
		AllowPrint:       true,
		AllowForward:     true,
		AllowEdit:        true,
	})
	if err != nil {
		t.Fatalf("CreatePolicy failed: %v", err)
	}

	// 1st Download - Should succeed
	var w bytes.Buffer
	if err := vault.Download(ctx, "protected.txt", DownloadOptions{AccessorID: "user1"}, &w); err != nil {
		t.Errorf("First download failed: %v", err)
	}

	// 2nd Download - Should fail
	if err := vault.Download(ctx, "protected.txt", DownloadOptions{AccessorID: "user1"}, &w); err == nil {
		t.Errorf("Second download should have failed due to restrictions")
	} else if err.Error() != "protection: use count exceeded" { // Error string from protection.go
		t.Errorf("Unexpected error: %v", err)
	}
}
