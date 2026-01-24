package velocity

import (
	"testing"
)

func TestMinimalSystemOperation(t *testing.T) {
	db, err := NewWithConfig(Config{
		Path:          t.TempDir(),
		EncryptionKey: make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	// Try to store with SystemOperation
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	_, err = db.StoreObject("test/file.bin", "application/octet-stream", "user1", data, &ObjectOptions{
		Encrypt:         true,
		SystemOperation: true,
	})
	if err != nil {
		t.Fatalf("store object with system operation: %v", err)
	}
}
