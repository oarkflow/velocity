package mem

import (
	"context"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

func TestPutGetDeleteRoundTrip(t *testing.T) {
	ctx := context.Background()
	e := NewEngine()

	if err := e.Put(ctx, api.Entry{Key: []byte("a"), Value: []byte("1")}); err != nil {
		t.Fatal(err)
	}
	v, ok, err := e.Get(ctx, []byte("a"))
	if err != nil || !ok || string(v) != "1" {
		t.Fatalf("got %q %v %v", v, ok, err)
	}

	if err := e.Delete(ctx, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := e.Get(ctx, []byte("a")); ok {
		t.Fatal("expected key deleted")
	}
}

func TestBatch(t *testing.T) {
	ctx := context.Background()
	e := NewEngine()
	ops := []api.BatchOp{
		{Entry: api.Entry{Key: []byte("x"), Value: []byte("1")}},
		{Entry: api.Entry{Key: []byte("y"), Value: []byte("2")}},
	}
	if err := e.Batch(ctx, ops); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := e.Get(ctx, []byte("x")); !ok {
		t.Fatal("expected x present")
	}
	if err := e.Batch(ctx, []api.BatchOp{{Delete: true, Entry: api.Entry{Key: []byte("x")}}}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := e.Get(ctx, []byte("x")); ok {
		t.Fatal("expected x deleted by batch")
	}
}

func TestScanPrefix(t *testing.T) {
	ctx := context.Background()
	e := NewEngine()
	for _, k := range []string{"user:1", "user:2", "order:1"} {
		if err := e.Put(ctx, api.Entry{Key: []byte(k), Value: []byte("v")}); err != nil {
			t.Fatal(err)
		}
	}
	it, err := e.Scan(ctx, []byte("user:"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for it.Next() {
		got = append(got, string(it.Key()))
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 keys, got %v", got)
	}
}

func TestSnapshotIsolation(t *testing.T) {
	ctx := context.Background()
	e := NewEngine()
	if err := e.Put(ctx, api.Entry{Key: []byte("k"), Value: []byte("v1")}); err != nil {
		t.Fatal(err)
	}
	snap, err := e.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Release()

	if err := e.Put(ctx, api.Entry{Key: []byte("k"), Value: []byte("v2")}); err != nil {
		t.Fatal(err)
	}
	v, ok, _ := snap.Get([]byte("k"))
	if !ok || string(v) != "v1" {
		t.Fatalf("expected snapshot to retain v1, got %q ok=%v", v, ok)
	}
	v2, _, _ := e.Get(ctx, []byte("k"))
	if string(v2) != "v2" {
		t.Fatalf("expected live engine to reflect v2, got %q", v2)
	}
}

func TestTTLExpiry(t *testing.T) {
	ctx := context.Background()
	e := NewEngine()
	if err := e.Put(ctx, api.Entry{Key: []byte("temp"), Value: []byte("v"), TTL: 10 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if _, ok, _ := e.Get(ctx, []byte("temp")); ok {
		t.Fatal("expected expired key to be absent")
	}
}
