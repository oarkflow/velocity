package velocity

import (
	"errors"
	"testing"
)

func TestValidateKVBounds(t *testing.T) {
	if !errors.Is(validateKey(nil), ErrEmptyKey) {
		t.Fatal("empty key must be rejected")
	}
	if !errors.Is(validateKVLengths(MaxKeySize+1, 0), ErrKeyTooLarge) {
		t.Fatal("oversized key must be rejected")
	}
	if !errors.Is(validateKVLengths(1, MaxValueSize+1), ErrValueTooLarge) {
		t.Fatal("oversized value must be rejected")
	}
}

func TestMemTableReadCopyPattern(t *testing.T) {
	mt := NewMemTable()
	mt.Put([]byte("key"), []byte("value"))
	entry := mt.Get([]byte("key"))
	if entry == nil {
		t.Fatal("expected entry")
	}
	dst := make([]byte, 0, len(entry.Value))
	dst = append(dst, entry.Value...)
	dst[0] = 'X'
	if got := string(mt.Get([]byte("key")).Value); got != "value" {
		t.Fatalf("caller-owned copy changed stored value: %q", got)
	}
}
