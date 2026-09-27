package redisdata

import (
	"context"
	"sort"
	"testing"
)

func TestSet_AddRemMembersIsMemberCard(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	added, err := p.SAdd(ctx, "s", bs("a", "b", "c")...)
	if err != nil || added != 3 {
		t.Fatalf("SAdd: added=%d err=%v", added, err)
	}
	// Duplicate add: "a" already present, "d" new.
	added, err = p.SAdd(ctx, "s", bs("a", "d")...)
	if err != nil || added != 1 {
		t.Fatalf("SAdd duplicate: added=%d err=%v", added, err)
	}

	card, err := p.SCard(ctx, "s")
	if err != nil || card != 4 {
		t.Fatalf("SCard: card=%d err=%v", card, err)
	}

	ok, err := p.SIsMember(ctx, "s", []byte("b"))
	if err != nil || !ok {
		t.Fatalf("SIsMember(b): ok=%v err=%v", ok, err)
	}
	ok, err = p.SIsMember(ctx, "s", []byte("zzz"))
	if err != nil || ok {
		t.Fatalf("SIsMember(zzz): ok=%v err=%v", ok, err)
	}

	members, err := p.SMembers(ctx, "s")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range members {
		got = append(got, string(m))
	}
	sort.Strings(got)
	want := []string{"a", "b", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("SMembers: got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("SMembers: got %v, want %v", got, want)
		}
	}

	removed, err := p.SRem(ctx, "s", []byte("a"), []byte("nonexistent"))
	if err != nil || removed != 1 {
		t.Fatalf("SRem: removed=%d err=%v", removed, err)
	}
	card, err = p.SCard(ctx, "s")
	if err != nil || card != 3 {
		t.Fatalf("SCard after SRem: card=%d err=%v", card, err)
	}
}
