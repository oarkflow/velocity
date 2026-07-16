package velocity

import "testing"

func TestMemTableEmptyKeyDoesNotPanic(t *testing.T) {
	mt := NewMemTable()
	mt.Put(nil, []byte("value"))
	got := mt.Get(nil)
	if got == nil || string(got.Value) != "value" {
		t.Fatalf("empty key lookup = %#v, want value", got)
	}
}

func TestMemTableDeleteUpdatesSizeAndMetadata(t *testing.T) {
	mt := NewMemTable()
	mt.Put([]byte("key"), []byte("a comparatively large value"))
	before := mt.Size()
	mt.Delete([]byte("key"))
	after := mt.Size()
	if after >= before {
		t.Fatalf("delete size = %d, want less than put size %d", after, before)
	}
	got := mt.Get([]byte("key"))
	if got == nil || !got.Deleted {
		t.Fatalf("delete entry = %#v, want tombstone", got)
	}
	if got.ExpiresAt != 0 {
		t.Fatalf("delete expiry = %d, want zero", got.ExpiresAt)
	}
}

func TestMemTableMergePreservesNewerEntries(t *testing.T) {
	old := NewMemTable()
	old.Put([]byte("same"), []byte("old"))
	old.Put([]byte("only-old"), []byte("restored"))

	current := NewMemTable()
	current.Put([]byte("same"), []byte("new"))
	current.mergeFrom(old)

	if got := current.Get([]byte("same")); got == nil || string(got.Value) != "new" {
		t.Fatalf("same = %#v, want newer value", got)
	}
	if got := current.Get([]byte("only-old")); got == nil || string(got.Value) != "restored" {
		t.Fatalf("only-old = %#v, want restored value", got)
	}
}
