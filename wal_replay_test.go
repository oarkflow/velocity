package velocity

import (
	"testing"
)

func TestWALReplay(t *testing.T) {
	path := t.TempDir()

	db, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	// Put some keys and close to ensure WAL is flushed
	if err := db.Put([]byte("k1"), []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := db.Put([]byte("k2"), []byte("v2")); err != nil {
		t.Fatal(err)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen and check values were restored via WAL replay
	db2, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()

	v, err := db2.Get([]byte("k1"))
	if err != nil {
		t.Fatalf("Get k1 error: %v", err)
	}
	if string(v) != "v1" {
		t.Fatalf("expected v1 got %s", v)
	}

	v2, err := db2.Get([]byte("k2"))
	if err != nil {
		t.Fatalf("Get k2 error: %v", err)
	}
	if string(v2) != "v2" {
		t.Fatalf("expected v2 got %s", v2)
	}
}
