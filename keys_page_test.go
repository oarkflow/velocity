package velocity

import (
	"fmt"
	"os"
	"testing"
)

func TestKeysPageBasic(t *testing.T) {
	dir := "./testdb_keys"
	_ = os.RemoveAll(dir)
	db, err := New(dir)
	if err != nil {
		t.Fatalf("New db failed: %v", err)
	}
	defer func() { _ = db.Close(); _ = os.RemoveAll(dir) }()

	// insert 500 keys
	for i := 0; i < 500; i++ {
		k := []byte(fmt.Sprintf("k%04d", i))
		v := []byte(fmt.Sprintf("v%04d", i))
		db.Put(k, v)
	}

	keys, total := db.KeysPage(0, 10)
	if len(keys) != 10 {
		t.Fatalf("expected 10 keys, got %d", len(keys))
	}
	if total <= 0 {
		t.Fatalf("expected total > 0, got %d", total)
	}
}
