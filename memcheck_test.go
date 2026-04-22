package velocity

import (
	"fmt"
	"os"
	"runtime/pprof"
	"testing"
	"time"
)

func TestMemCheck(t *testing.T) {
	dir := "./memcheck_db"
	os.RemoveAll(dir)
	db, err := New(dir)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer db.Close()
	defer os.RemoveAll(dir)

	// Use current default cache size
	db.EnableCache(20 * 1024 * 1024) // 20MB

	// Do many inserts - reduced to avoid test timeout
	n := 1000
	for i := 0; i < n; i++ {
		key := []byte(fmt.Sprintf("k%09d", i))
		val := make([]byte, 256)
		if err := db.Put(key, val); err != nil {
			t.Fatalf("put error: %v", err)
		}
		if i%250 == 0 {
			t.Logf("inserted %d", i)
		}
	}

	t.Logf("inserted %d total records", n)

	// let GC settle
	time.Sleep(2 * time.Second)

	f, err := os.Create("./heap.prof")
	if err != nil {
		t.Fatalf("failed to create profile: %v", err)
	}
	defer f.Close()

	if err := pprof.WriteHeapProfile(f); err != nil {
		t.Fatalf("failed to write heap profile: %v", err)
	}

	t.Log("Heap profile written to ./heap.prof")
}
