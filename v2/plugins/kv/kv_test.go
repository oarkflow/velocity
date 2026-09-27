package kv

import (
	"context"
	"testing"
)

func newTestPlugin() *Plugin {
	return &Plugin{storage: newMemBackend()}
}

func TestPutGetDelete(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	if err := p.Put(ctx, "a", []byte("1")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	v, ok, err := p.Get(ctx, "a")
	if err != nil || !ok || string(v) != "1" {
		t.Fatalf("Get = %q, %v, %v", v, ok, err)
	}
	if err := p.Delete(ctx, "a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, ok, err = p.Get(ctx, "a")
	if err != nil || ok {
		t.Fatalf("expected deleted key to be absent, got ok=%v err=%v", ok, err)
	}
}

func TestEmptyKeyRejected(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	if err := p.Put(ctx, "", []byte("x")); err != ErrEmptyKey {
		t.Fatalf("expected ErrEmptyKey, got %v", err)
	}
	if _, _, err := p.Get(ctx, ""); err != ErrEmptyKey {
		t.Fatalf("expected ErrEmptyKey, got %v", err)
	}
}

func TestExists(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	ok, err := p.Exists(ctx, "missing")
	if err != nil || ok {
		t.Fatalf("expected false, got ok=%v err=%v", ok, err)
	}
	_ = p.Put(ctx, "present", []byte("v"))
	ok, err = p.Exists(ctx, "present")
	if err != nil || !ok {
		t.Fatalf("expected true, got ok=%v err=%v", ok, err)
	}
}

func TestIncrConcurrent(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	const n = 200
	done := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			if _, err := p.Incr(ctx, "counter", 1); err != nil {
				t.Errorf("Incr: %v", err)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < n; i++ {
		<-done
	}
	v, ok, err := p.Get(ctx, "counter")
	if err != nil || !ok {
		t.Fatalf("Get counter: ok=%v err=%v", ok, err)
	}
	if string(v) != "200" {
		t.Fatalf("expected counter=200 after %d concurrent increments, got %q", n, v)
	}
}

func TestKeysGlob(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	_ = p.Put(ctx, "user:1", []byte("a"))
	_ = p.Put(ctx, "user:2", []byte("b"))
	_ = p.Put(ctx, "order:1", []byte("c"))

	keys, err := p.Keys(ctx, "user:*")
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 user:* keys, got %v", keys)
	}
}

func TestScanPagination(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	for _, k := range []string{"p:1", "p:2", "p:3", "p:4", "p:5"} {
		_ = p.Put(ctx, k, []byte(k))
	}

	items, cursor, err := p.Scan(ctx, "p:", 2, "")
	if err != nil {
		t.Fatalf("Scan page1: %v", err)
	}
	if len(items) != 2 || cursor == "" {
		t.Fatalf("expected 2 items and a cursor, got %d items cursor=%q", len(items), cursor)
	}

	items2, cursor2, err := p.Scan(ctx, "p:", 2, cursor)
	if err != nil {
		t.Fatalf("Scan page2: %v", err)
	}
	if len(items2) != 2 || cursor2 == "" {
		t.Fatalf("expected 2 items and a cursor on page2, got %d items cursor=%q", len(items2), cursor2)
	}

	items3, cursor3, err := p.Scan(ctx, "p:", 2, cursor2)
	if err != nil {
		t.Fatalf("Scan page3: %v", err)
	}
	if len(items3) != 1 || cursor3 != "" {
		t.Fatalf("expected final page of 1 item and empty cursor, got %d items cursor=%q", len(items3), cursor3)
	}
}
