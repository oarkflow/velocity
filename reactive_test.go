package velocity

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchKeyAndPrefix(t *testing.T) {
	db, err := NewWithConfig(Config{
		Path:              t.TempDir(),
		DisableEncryption: true,
		DisableWAL:        true,
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	keyEvents := db.WatchKey(ctx, []byte("user:1"), 4)
	prefixEvents := db.WatchPrefix(ctx, []byte("user:"), 4)

	if err := db.Put([]byte("user:1"), []byte("ada")); err != nil {
		t.Fatalf("put user:1: %v", err)
	}
	if err := db.Put([]byte("team:1"), []byte("platform")); err != nil {
		t.Fatalf("put team:1: %v", err)
	}
	if err := db.Delete([]byte("user:1")); err != nil {
		t.Fatalf("delete user:1: %v", err)
	}

	first := mustWatchEvent(t, keyEvents)
	if first.Type != WatchPut || string(first.Key) != "user:1" || string(first.Value) != "ada" {
		t.Fatalf("unexpected key put event: %+v", first)
	}
	second := mustWatchEvent(t, keyEvents)
	if second.Type != WatchDelete || string(second.Key) != "user:1" || !second.Deleted {
		t.Fatalf("unexpected key delete event: %+v", second)
	}
	if second.Sequence <= first.Sequence {
		t.Fatalf("sequence did not increase: %d then %d", first.Sequence, second.Sequence)
	}

	prefixFirst := mustWatchEvent(t, prefixEvents)
	prefixSecond := mustWatchEvent(t, prefixEvents)
	if string(prefixFirst.Key) != "user:1" || string(prefixSecond.Key) != "user:1" {
		t.Fatalf("prefix watcher received non-matching events: %+v %+v", prefixFirst, prefixSecond)
	}
}

func TestWatchQueryRefreshesOnMatchingPrefix(t *testing.T) {
	db, err := NewWithConfig(Config{
		Path:              t.TempDir(),
		DisableEncryption: true,
		DisableWAL:        true,
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	updates, err := db.WatchQuery(ctx, SearchQuery{Prefix: "user", Limit: 10}, 4)
	if err != nil {
		t.Fatalf("watch query: %v", err)
	}
	initial := mustQueryWatchEvent(t, updates)
	if len(initial.Results) != 0 {
		t.Fatalf("expected empty initial result, got %d", len(initial.Results))
	}

	if err := db.Put([]byte("user:1"), []byte(`{"name":"Ada"}`)); err != nil {
		t.Fatalf("put user:1: %v", err)
	}
	refreshed := mustQueryWatchEvent(t, updates)
	if len(refreshed.Results) != 1 || string(refreshed.Results[0].Key) != "user:1" {
		t.Fatalf("unexpected refreshed query result: %+v", refreshed.Results)
	}
}

func TestBatchWriterPublishesCommittedEntries(t *testing.T) {
	db, err := NewWithConfig(Config{
		Path:              t.TempDir(),
		DisableEncryption: true,
		DisableWAL:        true,
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := db.WatchPrefix(ctx, []byte("batch:"), 4)

	bw := db.NewBatchWriter(10)
	if err := bw.Put([]byte("batch:1"), []byte("one")); err != nil {
		t.Fatalf("batch put 1: %v", err)
	}
	if err := bw.Put([]byte("batch:2"), []byte("two")); err != nil {
		t.Fatalf("batch put 2: %v", err)
	}
	if err := bw.Flush(); err != nil {
		t.Fatalf("batch flush: %v", err)
	}

	first := mustWatchEvent(t, events)
	second := mustWatchEvent(t, events)
	if string(first.Key) != "batch:1" || string(second.Key) != "batch:2" {
		t.Fatalf("unexpected batch events: %+v %+v", first, second)
	}
	if second.Sequence <= first.Sequence {
		t.Fatalf("sequence did not increase: %d then %d", first.Sequence, second.Sequence)
	}
}

func TestWatchDoesNoReactiveWorkWithoutMatchingSubscribers(t *testing.T) {
	db, err := NewWithConfig(Config{
		Path:              t.TempDir(),
		DisableEncryption: true,
		DisableWAL:        true,
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := db.Put([]byte("cold:1"), []byte("value")); err != nil {
		t.Fatalf("put without watchers: %v", err)
	}
	if got := atomic.LoadUint64(&db.nextSequence); got != 0 {
		t.Fatalf("sequence advanced without subscribers: %d", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := db.WatchPrefix(ctx, []byte("hot:"), 4)

	if err := db.Put([]byte("cold:2"), []byte("value")); err != nil {
		t.Fatalf("put unmatched watcher: %v", err)
	}
	if got := atomic.LoadUint64(&db.nextSequence); got != 0 {
		t.Fatalf("sequence advanced for unmatched subscriber: %d", got)
	}
	assertNoWatchEvent(t, events)

	if err := db.Put([]byte("hot:1"), []byte("value")); err != nil {
		t.Fatalf("put matched watcher: %v", err)
	}
	ev := mustWatchEvent(t, events)
	if ev.Sequence != 1 || string(ev.Key) != "hot:1" {
		t.Fatalf("unexpected matched event: %+v", ev)
	}
}

func TestWatchLifecycleCleansDependencyBuckets(t *testing.T) {
	db, err := NewWithConfig(Config{
		Path:              t.TempDir(),
		DisableEncryption: true,
		DisableWAL:        true,
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	keyCtx, keyCancel := context.WithCancel(context.Background())
	prefixCtx, prefixCancel := context.WithCancel(context.Background())
	allCtx, allCancel := context.WithCancel(context.Background())

	keyEvents := db.WatchKey(keyCtx, []byte("k:1"), 1)
	prefixEvents := db.WatchPrefix(prefixCtx, []byte("p:"), 1)
	allEvents := db.WatchAll(allCtx, 1)

	if got := atomic.LoadInt64(&db.activeWatchers); got != 3 {
		t.Fatalf("active watchers = %d, want 3", got)
	}

	keyCancel()
	prefixCancel()
	allCancel()

	assertClosed(t, keyEvents)
	assertClosed(t, prefixEvents)
	assertClosed(t, allEvents)

	db.watchMu.RLock()
	defer db.watchMu.RUnlock()
	if len(db.watchKeys) != 0 || len(db.watchPrefixes) != 0 || len(db.watchAll) != 0 {
		t.Fatalf("watch buckets not cleaned: keys=%d prefixes=%d all=%d", len(db.watchKeys), len(db.watchPrefixes), len(db.watchAll))
	}
	if got := atomic.LoadInt64(&db.activeWatchers); got != 0 {
		t.Fatalf("active watchers after cancel = %d, want 0", got)
	}
}

func TestWatchEventOrderingIsDeterministicForLogicalWorkload(t *testing.T) {
	first := runDeterministicWatchWorkload(t, 42)
	second := runDeterministicWatchWorkload(t, 42)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("watch workload was not deterministic\nfirst:  %#v\nsecond: %#v", first, second)
	}
}

type comparableWatchEvent struct {
	Sequence uint64
	Type     string
	Key      string
	Value    string
	Deleted  bool
}

func runDeterministicWatchWorkload(t *testing.T, seed int64) []comparableWatchEvent {
	t.Helper()
	db, err := NewWithConfig(Config{
		Path:              t.TempDir(),
		DisableEncryption: true,
		DisableWAL:        true,
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := db.WatchPrefix(ctx, []byte("det:"), 128)

	rng := rand.New(rand.NewSource(seed))
	expected := 0
	for i := 0; i < 50; i++ {
		key := []byte(fmt.Sprintf("det:%02d", rng.Intn(8)))
		if rng.Intn(5) == 0 {
			if err := db.Delete(key); err != nil {
				t.Fatalf("delete %s: %v", key, err)
			}
		} else {
			value := []byte(fmt.Sprintf("value:%02d", rng.Intn(100)))
			if err := db.Put(key, value); err != nil {
				t.Fatalf("put %s: %v", key, err)
			}
		}
		expected++
	}

	out := make([]comparableWatchEvent, 0, expected)
	for len(out) < expected {
		ev := mustWatchEvent(t, events)
		out = append(out, comparableWatchEvent{
			Sequence: ev.Sequence,
			Type:     ev.Type,
			Key:      string(ev.Key),
			Value:    string(ev.Value),
			Deleted:  ev.Deleted,
		})
	}
	return out
}

func mustWatchEvent(t *testing.T, ch <-chan WatchEvent) WatchEvent {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("watch channel closed")
		}
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for watch event")
		return WatchEvent{}
	}
}

func mustQueryWatchEvent(t *testing.T, ch <-chan QueryWatchEvent) QueryWatchEvent {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("query watch channel closed")
		}
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for query watch event")
		return QueryWatchEvent{}
	}
}

func assertNoWatchEvent(t *testing.T, ch <-chan WatchEvent) {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("watch channel closed")
		}
		t.Fatalf("unexpected watch event: %+v", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

func assertClosed(t *testing.T, ch <-chan WatchEvent) {
	t.Helper()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected closed watch channel")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for watch channel close")
	}
}
