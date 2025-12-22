package velocity

import (
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"
)

func TestSparseIndexAndGet(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	path := "./test_sstable.dat"
	_ = os.Remove(path)
	crypto, _ := newCryptoProvider(make([]byte, 32))
	// create many entries > 2048 to ensure we don't materialize full index
	n := 5000
	entries := make([]*Entry, 0, n)
	for i := 0; i < n; i++ {
		k := []byte(fmt.Sprintf("key-%08d", i))
		v := []byte(fmt.Sprintf("value-%08d", i))
		entries = append(entries, &Entry{Key: k, Value: v})
	}

	sst, err := NewSSTable(path, entries, crypto)
	if err != nil {
		t.Fatalf("NewSSTable failed: %v", err)
	}
	_ = sst.Close()

	sst2, err := LoadSSTable(path, crypto)
	if err != nil {
		t.Fatalf("LoadSSTable failed: %v", err)
	}
	defer sst2.Close()

	if sst2.indexData != nil {
		t.Fatalf("expected indexData to be nil for large SSTable")
	}

	// random gets
	for i := 0; i < 10; i++ {
		idx := rand.Intn(n)
		key := []byte(fmt.Sprintf("key-%08d", idx))
		ent, err := sst2.Get(key)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if ent == nil {
			t.Fatalf("expected entry for key %s", key)
		}
		if string(ent.Value) != fmt.Sprintf("value-%08d", idx) {
			t.Fatalf("value mismatch for %s: got %s", key, ent.Value)
		}
	}

	_ = os.Remove(path)
}
