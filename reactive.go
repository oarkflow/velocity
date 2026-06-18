package velocity

import (
	"bytes"
	"context"
	"sort"
	"sync/atomic"
)

const (
	WatchPut    = "put"
	WatchDelete = "delete"
)

// WatchEvent is emitted after a logical key mutation is durable and visible.
// Sequence is monotonically increasing within one DB process and gives clients
// a deterministic ordering for events observed from concurrent writers.
type WatchEvent struct {
	Sequence  uint64 `json:"sequence"`
	Type      string `json:"type"`
	Key       []byte `json:"key"`
	Value     []byte `json:"value,omitempty"`
	Timestamp uint64 `json:"timestamp"`
	Deleted   bool   `json:"deleted"`
}

// WatchFilter selects which logical key mutations a subscription receives.
// If Key and Prefix are empty, every user-data mutation is delivered.
type WatchFilter struct {
	Key    []byte
	Prefix []byte
}

// QueryWatchEvent contains the latest result set for a subscribed query.
type QueryWatchEvent struct {
	Sequence uint64         `json:"sequence"`
	Query    SearchQuery    `json:"query"`
	Results  []SearchResult `json:"results"`
}

type watcher struct {
	id     uint64
	filter WatchFilter
	ch     chan WatchEvent
	once   atomic.Bool
	db     *DB
	kind   watchKind
	bucket string
}

type watchKind uint8

const (
	watchKindAll watchKind = iota
	watchKindKey
	watchKindPrefix
)

// Watch subscribes to key changes. The returned channel is closed when ctx is
// cancelled, the DB closes, or the subscription is cancelled by the caller.
func (db *DB) Watch(ctx context.Context, filter WatchFilter, buffer int) <-chan WatchEvent {
	if buffer < 1 {
		buffer = 1
	}
	w := &watcher{
		id:     atomic.AddUint64(&db.nextWatcherID, 1),
		filter: cloneWatchFilter(filter),
		ch:     make(chan WatchEvent, buffer),
		db:     db,
	}
	w.kind, w.bucket = watchBucket(w.filter)

	db.watchMu.Lock()
	db.addWatcherLocked(w)
	atomic.AddInt64(&db.activeWatchers, 1)
	db.watchMu.Unlock()

	go func() {
		select {
		case <-ctx.Done():
		case <-db.shutdownCh:
		}
		w.close()
	}()

	return w.ch
}

// WatchKey subscribes to changes for one key.
func (db *DB) WatchKey(ctx context.Context, key []byte, buffer int) <-chan WatchEvent {
	return db.Watch(ctx, WatchFilter{Key: key}, buffer)
}

// WatchPrefix subscribes to changes for keys with the given prefix.
func (db *DB) WatchPrefix(ctx context.Context, prefix []byte, buffer int) <-chan WatchEvent {
	return db.Watch(ctx, WatchFilter{Prefix: prefix}, buffer)
}

// WatchAll subscribes to every user-data mutation.
func (db *DB) WatchAll(ctx context.Context, buffer int) <-chan WatchEvent {
	return db.Watch(ctx, WatchFilter{}, buffer)
}

// WatchQuery subscribes to a Search query. It emits an initial snapshot and
// then emits a refreshed result set whenever a mutation that can affect the
// query's prefix is committed.
func (db *DB) WatchQuery(ctx context.Context, q SearchQuery, buffer int) (<-chan QueryWatchEvent, error) {
	if buffer < 1 {
		buffer = 1
	}
	out := make(chan QueryWatchEvent, buffer)
	results, err := db.Search(q)
	if err != nil {
		close(out)
		return out, err
	}
	sendQueryEvent(ctx, out, QueryWatchEvent{Sequence: atomic.LoadUint64(&db.nextSequence), Query: q, Results: cloneSearchResults(results)})

	events := db.Watch(ctx, WatchFilter{Prefix: []byte(q.Prefix)}, buffer)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-events:
				if !ok {
					return
				}
				results, err := db.Search(q)
				if err != nil {
					continue
				}
				if !sendQueryEvent(ctx, out, QueryWatchEvent{Sequence: ev.Sequence, Query: q, Results: cloneSearchResults(results)}) {
					return
				}
			}
		}
	}()

	return out, nil
}

func sendQueryEvent(ctx context.Context, ch chan<- QueryWatchEvent, ev QueryWatchEvent) bool {
	select {
	case ch <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

func (w *watcher) close() {
	if !w.once.CompareAndSwap(false, true) {
		return
	}
	w.db.watchMu.Lock()
	w.db.removeWatcherLocked(w)
	atomic.AddInt64(&w.db.activeWatchers, -1)
	w.db.watchMu.Unlock()
	close(w.ch)
}

func (db *DB) publishWatchEvent(event WatchEvent) {
	if len(event.Key) == 0 || isIndexKey(event.Key) {
		return
	}
	if atomic.LoadInt64(&db.activeWatchers) == 0 {
		return
	}

	db.watchMu.RLock()
	watchers := db.watchersForKeyLocked(event.Key)
	db.watchMu.RUnlock()
	if len(watchers) == 0 {
		return
	}

	event.Sequence = atomic.AddUint64(&db.nextSequence, 1)
	event.Key = append([]byte(nil), event.Key...)
	event.Value = append([]byte(nil), event.Value...)

	for _, w := range watchers {
		ev := WatchEvent{
			Sequence:  event.Sequence,
			Type:      event.Type,
			Key:       append([]byte(nil), event.Key...),
			Value:     append([]byte(nil), event.Value...),
			Timestamp: event.Timestamp,
			Deleted:   event.Deleted,
		}
		w.send(ev)
	}
}

func (w *watcher) send(ev WatchEvent) {
	defer func() {
		_ = recover()
	}()
	select {
	case w.ch <- ev:
	default:
		select {
		case w.ch <- ev:
		case <-w.db.shutdownCh:
		}
	}
}

func (db *DB) publishPut(key, value []byte, timestamp uint64) {
	db.publishWatchEvent(WatchEvent{
		Type:      WatchPut,
		Key:       key,
		Value:     value,
		Timestamp: timestamp,
	})
}

func (db *DB) publishDelete(key []byte, timestamp uint64) {
	db.publishWatchEvent(WatchEvent{
		Type:      WatchDelete,
		Key:       key,
		Timestamp: timestamp,
		Deleted:   true,
	})
}

func (db *DB) publishEntries(entries []Entry) {
	for i := range entries {
		entry := &entries[i]
		if entry.Deleted {
			db.publishDelete(entry.Key, entry.Timestamp)
			continue
		}
		db.publishPut(entry.Key, entry.Value, entry.Timestamp)
	}
}

func cloneWatchFilter(filter WatchFilter) WatchFilter {
	return WatchFilter{
		Key:    append([]byte(nil), filter.Key...),
		Prefix: append([]byte(nil), filter.Prefix...),
	}
}

func watchBucket(filter WatchFilter) (watchKind, string) {
	if len(filter.Key) > 0 {
		return watchKindKey, string(filter.Key)
	}
	if len(filter.Prefix) > 0 {
		return watchKindPrefix, string(filter.Prefix)
	}
	return watchKindAll, ""
}

func (db *DB) addWatcherLocked(w *watcher) {
	switch w.kind {
	case watchKindKey:
		if db.watchKeys == nil {
			db.watchKeys = make(map[string]map[uint64]*watcher)
		}
		addWatcherToBucket(db.watchKeys, w.bucket, w)
	case watchKindPrefix:
		if db.watchPrefixes == nil {
			db.watchPrefixes = make(map[string]map[uint64]*watcher)
		}
		addWatcherToBucket(db.watchPrefixes, w.bucket, w)
	default:
		if db.watchAll == nil {
			db.watchAll = make(map[uint64]*watcher)
		}
		db.watchAll[w.id] = w
	}
}

func (db *DB) removeWatcherLocked(w *watcher) {
	switch w.kind {
	case watchKindKey:
		removeWatcherFromBucket(db.watchKeys, w.bucket, w.id)
	case watchKindPrefix:
		removeWatcherFromBucket(db.watchPrefixes, w.bucket, w.id)
	default:
		delete(db.watchAll, w.id)
	}
}

func addWatcherToBucket(buckets map[string]map[uint64]*watcher, bucket string, w *watcher) {
	watchers := buckets[bucket]
	if watchers == nil {
		watchers = make(map[uint64]*watcher)
		buckets[bucket] = watchers
	}
	watchers[w.id] = w
}

func removeWatcherFromBucket(buckets map[string]map[uint64]*watcher, bucket string, id uint64) {
	watchers := buckets[bucket]
	if watchers == nil {
		return
	}
	delete(watchers, id)
	if len(watchers) == 0 {
		delete(buckets, bucket)
	}
}

func (db *DB) watchersForKeyLocked(key []byte) []*watcher {
	total := len(db.watchAll)
	keyWatchers := db.watchKeys[string(key)]
	total += len(keyWatchers)

	prefixes := make([]string, 0, len(db.watchPrefixes))
	for prefix, watchers := range db.watchPrefixes {
		if len(watchers) > 0 && bytes.HasPrefix(key, []byte(prefix)) {
			prefixes = append(prefixes, prefix)
			total += len(watchers)
		}
	}
	if total == 0 {
		return nil
	}

	sort.Strings(prefixes)
	out := make([]*watcher, 0, total)
	for _, w := range db.watchAll {
		out = append(out, w)
	}
	for _, w := range keyWatchers {
		out = append(out, w)
	}
	for _, prefix := range prefixes {
		for _, w := range db.watchPrefixes[prefix] {
			out = append(out, w)
		}
	}
	return out
}

func cloneSearchResults(results []SearchResult) []SearchResult {
	if len(results) == 0 {
		return nil
	}
	out := make([]SearchResult, len(results))
	for i := range results {
		out[i] = SearchResult{
			Key:        append([]byte(nil), results[i].Key...),
			Value:      append([]byte(nil), results[i].Value...),
			Score:      results[i].Score,
			Highlights: cloneHighlights(results[i].Highlights),
		}
	}
	return out
}

func cloneHighlights(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}
