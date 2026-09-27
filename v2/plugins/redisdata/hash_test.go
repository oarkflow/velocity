package redisdata

import (
	"context"
	"testing"
)

func TestHash_SetGetDelGetAllLen(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	if err := p.HSet(ctx, "h", "name", []byte("alice")); err != nil {
		t.Fatal(err)
	}
	if err := p.HSet(ctx, "h", "age", []byte("30")); err != nil {
		t.Fatal(err)
	}
	// Overwrite an existing field.
	if err := p.HSet(ctx, "h", "name", []byte("alice2")); err != nil {
		t.Fatal(err)
	}

	v, ok, err := p.HGet(ctx, "h", "name")
	if err != nil || !ok || string(v) != "alice2" {
		t.Fatalf("HGet(name): v=%q ok=%v err=%v", v, ok, err)
	}

	if n, err := p.HLen(ctx, "h"); err != nil || n != 2 {
		t.Fatalf("HLen: n=%d err=%v", n, err)
	}

	all, err := p.HGetAll(ctx, "h")
	if err != nil {
		t.Fatal(err)
	}
	if string(all["name"]) != "alice2" || string(all["age"]) != "30" || len(all) != 2 {
		t.Fatalf("HGetAll: got %v", all)
	}

	if err := p.HDel(ctx, "h", "age"); err != nil {
		t.Fatal(err)
	}
	if n, err := p.HLen(ctx, "h"); err != nil || n != 1 {
		t.Fatalf("HLen after HDel: n=%d err=%v", n, err)
	}
	if _, ok, err := p.HGet(ctx, "h", "age"); err != nil || ok {
		t.Fatalf("HGet(age) after HDel: ok=%v err=%v", ok, err)
	}
}
