package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/oarkflow/velocity"
)

type WatchHooks struct {
	OnPut    func(velocity.WatchEvent)
	OnDelete func(velocity.WatchEvent)
	OnAny    func(velocity.WatchEvent)
}

func main() {
	dir := mustTempDir()
	defer os.RemoveAll(dir)

	db, err := velocity.NewWithConfig(velocity.Config{
		Path:                    dir,
		DisableEncryption:       true,
		DisableWAL:              true,
		DisableIndexPersistence: true,
		SearchIndexEnabled:      true,
	})
	check(err)
	defer db.Close()

	userSchema := &velocity.SearchSchema{Fields: []velocity.SearchSchemaField{
		{Name: "name", Searchable: true},
		{Name: "role", HashSearch: true},
		{Name: "region", Searchable: true, HashSearch: true},
	}}
	db.SetSearchSchemaForPrefix("users", userSchema)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	hookLog := make(chan string, 16)

	keyEvents := db.WatchKey(ctx, []byte("users:1"), 8)
	prefixEvents := db.WatchPrefix(ctx, []byte("users:"), 8)
	allEvents := db.WatchAll(ctx, 8)
	hookEvents := db.WatchKey(ctx, []byte("users:1"), 8)
	queryEvents, err := db.WatchQuery(ctx, velocity.SearchQuery{
		Prefix: "users",
		Filters: []velocity.SearchFilter{
			{Field: "role", Op: "==", Value: "admin", HashOnly: true},
		},
		Limit: 10,
	}, 8)
	check(err)

	hooks := WatchHooks{
		OnPut: func(ev velocity.WatchEvent) {
			hookLog <- fmt.Sprintf("hook put    seq=%02d key=%s value=%s", ev.Sequence, ev.Key, ev.Value)
		},
		OnDelete: func(ev velocity.WatchEvent) {
			hookLog <- fmt.Sprintf("hook delete seq=%02d key=%s", ev.Sequence, ev.Key)
		},
		OnAny: func(ev velocity.WatchEvent) {
			hookLog <- fmt.Sprintf("hook any    seq=%02d type=%s key=%s", ev.Sequence, ev.Type, ev.Key)
		},
	}

	startHookLoop(ctx, &wg, hookEvents, hooks)

	fmt.Println("initial query snapshot")
	printQuery("query:admins", mustQueryUpdate(queryEvents))

	check(db.Put([]byte("users:1"), []byte(`{"name":"Ada","role":"admin","region":"EU"}`)))
	printWatch("key:users:1", mustWatchEvent(keyEvents))
	printWatch("prefix:users:", mustWatchEvent(prefixEvents))
	printWatch("all", mustWatchEvent(allEvents))
	printQuery("query:admins", mustQueryUpdate(queryEvents))

	check(db.Put([]byte("users:2"), []byte(`{"name":"Grace","role":"operator","region":"US"}`)))
	printWatch("prefix:users:", mustWatchEvent(prefixEvents))
	printWatch("all", mustWatchEvent(allEvents))
	printQuery("query:admins", mustQueryUpdate(queryEvents))

	check(db.Put([]byte("orders:1"), []byte(`{"total":42}`)))
	printWatch("all", mustWatchEvent(allEvents))

	check(db.Put([]byte("users:1"), []byte(`{"name":"Ada","role":"reviewer","region":"EU"}`)))
	printWatch("key:users:1", mustWatchEvent(keyEvents))
	printWatch("prefix:users:", mustWatchEvent(prefixEvents))
	printWatch("all", mustWatchEvent(allEvents))
	printQuery("query:admins", mustQueryUpdate(queryEvents))

	check(db.Delete([]byte("users:2")))
	printWatch("prefix:users:", mustWatchEvent(prefixEvents))
	printWatch("all", mustWatchEvent(allEvents))
	printQuery("query:admins", mustQueryUpdate(queryEvents))

	drainHooks(hookLog)

	// Subscription lifecycle: cancelling the context closes every watch stream.
	cancel()
	wg.Wait()
	fmt.Println("subscriptions: closed")

	fmt.Println("http watch:")
	fmt.Println("  GET /api/watch?key=users:1")
	fmt.Println("  GET /api/watch?prefix=users:")
	fmt.Println("  GET /api/watch?prefix=users:&heartbeat_seconds=15  # optional proxy keepalive")
	fmt.Println("  SSE events use id=<sequence>, event=put/delete, and JSON data payloads.")
}

func startHookLoop(ctx context.Context, wg *sync.WaitGroup, events <-chan velocity.WatchEvent, hooks WatchHooks) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-events:
				if !ok {
					return
				}
				if hooks.OnAny != nil {
					hooks.OnAny(ev)
				}
				switch ev.Type {
				case velocity.WatchPut:
					if hooks.OnPut != nil {
						hooks.OnPut(ev)
					}
				case velocity.WatchDelete:
					if hooks.OnDelete != nil {
						hooks.OnDelete(ev)
					}
				}
			}
		}
	}()
}

func printWatch(name string, ev velocity.WatchEvent) {
	fmt.Printf("%-14s seq=%02d type=%-6s key=%s\n", name, ev.Sequence, ev.Type, ev.Key)
}

func printQuery(name string, update velocity.QueryWatchEvent) {
	fmt.Printf("%-14s seq=%02d results=%d\n", name, update.Sequence, len(update.Results))
}

func drainHooks(events <-chan string) {
	for {
		select {
		case line := <-events:
			fmt.Println(line)
		case <-time.After(100 * time.Millisecond):
			return
		}
	}
}

func mustWatchEvent(events <-chan velocity.WatchEvent) velocity.WatchEvent {
	select {
	case ev := <-events:
		return ev
	case <-time.After(2 * time.Second):
		panic("timed out waiting for watch event")
	}
}

func mustQueryUpdate(updates <-chan velocity.QueryWatchEvent) velocity.QueryWatchEvent {
	select {
	case update := <-updates:
		return update
	case <-time.After(2 * time.Second):
		panic("timed out waiting for query update")
	}
}

func mustTempDir() string {
	dir, err := os.MkdirTemp("", "velocity_reactive_watch_hooks_")
	check(err)
	return dir
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
