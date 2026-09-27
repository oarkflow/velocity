package backup

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

func newTestPlugin(t *testing.T, store *memStore) *Plugin {
	t.Helper()
	p := &Plugin{storage: store, hmacKey: []byte("test-hmac-key-0123456789")}
	return p
}

func seed(t *testing.T, store *memStore, kvs map[string]string) {
	t.Helper()
	for k, v := range kvs {
		if err := store.Put(context.Background(), api.Entry{Key: []byte(k), Value: []byte(v)}); err != nil {
			t.Fatalf("seed put %q: %v", k, err)
		}
	}
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	src := newMemStore()
	seed(t, src, map[string]string{
		"a":        "1",
		"b":        "2",
		"prefix/x": "10",
		"prefix/y": "20",
	})
	p := newTestPlugin(t, src)

	var buf bytes.Buffer
	if err := p.Backup(ctx, &buf); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	dst := newMemStore()
	seed(t, dst, map[string]string{"stale": "should-be-wiped"})
	p2 := newTestPlugin(t, dst)
	if err := p2.Restore(ctx, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	want := map[string]string{"a": "1", "b": "2", "prefix/x": "10", "prefix/y": "20"}
	for k, v := range want {
		got, ok, err := dst.Get(ctx, []byte(k))
		if err != nil || !ok {
			t.Fatalf("key %q missing after restore (ok=%v err=%v)", k, ok, err)
		}
		if string(got) != v {
			t.Fatalf("key %q = %q, want %q", k, got, v)
		}
	}
	if _, ok, _ := dst.Get(ctx, []byte("stale")); ok {
		t.Fatalf("Restore should have wiped pre-existing keys, but \"stale\" survived")
	}
}

func TestRestoreRejectsTamperedStream(t *testing.T) {
	ctx := context.Background()
	src := newMemStore()
	seed(t, src, map[string]string{"a": "1", "b": "2"})
	p := newTestPlugin(t, src)

	var buf bytes.Buffer
	if err := p.Backup(ctx, &buf); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	tampered := buf.Bytes()
	// Flip a byte in the middle of the payload (well before the trailing
	// HMAC tag), simulating corruption/tampering.
	mid := len(tampered) / 2
	tampered[mid] ^= 0xFF

	dst := newMemStore()
	seed(t, dst, map[string]string{"untouched": "yes"})
	p2 := newTestPlugin(t, dst)

	err := p2.Restore(ctx, bytes.NewReader(tampered))
	if err == nil {
		t.Fatalf("Restore accepted a tampered stream")
	}
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("Restore error = %v, want ErrTampered", err)
	}

	// Nothing should have been applied — destination store must be
	// exactly as it was before the rejected Restore.
	if v, ok, _ := dst.Get(ctx, []byte("untouched")); !ok || string(v) != "yes" {
		t.Fatalf("Restore mutated the store despite rejecting the tampered stream (ok=%v v=%q)", ok, v)
	}
	if _, ok, _ := dst.Get(ctx, []byte("a")); ok {
		t.Fatalf("Restore applied records from a tampered stream")
	}
}

func TestExportImportPrefixScoping(t *testing.T) {
	ctx := context.Background()
	src := newMemStore()
	seed(t, src, map[string]string{
		"keep/1":  "a",
		"keep/2":  "b",
		"other/1": "c",
	})
	p := newTestPlugin(t, src)

	var buf bytes.Buffer
	if err := p.Export(ctx, &buf, "keep/"); err != nil {
		t.Fatalf("Export: %v", err)
	}

	dst := newMemStore()
	seed(t, dst, map[string]string{"pre-existing": "stays"})
	p2 := newTestPlugin(t, dst)
	if err := p2.Import(ctx, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("Import: %v", err)
	}

	for _, k := range []string{"keep/1", "keep/2"} {
		if _, ok, _ := dst.Get(ctx, []byte(k)); !ok {
			t.Fatalf("Import missing expected key %q", k)
		}
	}
	if _, ok, _ := dst.Get(ctx, []byte("other/1")); ok {
		t.Fatalf("Import pulled in a key outside the exported prefix")
	}
	// Import must not clear pre-existing keys (unlike Restore).
	if v, ok, _ := dst.Get(ctx, []byte("pre-existing")); !ok || string(v) != "stays" {
		t.Fatalf("Import cleared a pre-existing key it shouldn't have touched")
	}
}
