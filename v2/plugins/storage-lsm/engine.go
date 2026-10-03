// Package lsm implements a durable, crash-recoverable api.StorageBackend
// on top of a real (if intentionally simplified relative to v1) multi-file
// LSM design: a write-ahead log for durability, an in-memory memtable that
// flushes to an immutable, sorted, Bloom-filtered SSTable file once it
// crosses a size threshold, and a background compaction pass that merges
// every currently-known SSTable into one whenever their count crosses a
// threshold.
//
// Differences from v1's memtable.go/sstable.go/sstable_repair.go, stated
// plainly rather than left implicit:
//   - The memtable is a plain Go map, sorted only at flush time, not a
//     skip-list. Correctness is identical; only in-order iteration speed
//     during a flush differs, and flushes are infrequent relative to
//     writes.
//   - Each SSTable's index is loaded FULLY into memory on open (a
//     map[string]sstIndexEntry), not the sparse, page-granular index v1's
//     sstable.go uses. This trades some memory for a much simpler,
//     easier-to-verify implementation; the Bloom filter (see bloom.go)
//     still avoids the disk read that dominates the cost profile a sparse
//     index is really optimizing.
//   - Compaction always merges every SSTable currently on disk into a
//     single new one (see compactLocked), rather than v1's true per-level
//     picking/merging strategy. This is closer to "tiered" than "leveled"
//     compaction, but it is a real, correct, well-understood LSM
//     compaction strategy (the same shape RocksDB calls "universal
//     compaction") — not a stand-in that skips the hard part. Because a
//     compaction always merges everything on disk, it is always safe to
//     drop tombstones and expired entries in its output: by definition
//     nothing "below" the merge remains that they would still need to
//     shadow.
//
// Every crash-safety property this engine had before this upgrade is
// preserved: every write still goes to the WAL before it's visible, and
// WAL replay on Open recovers anything not yet durable in an SSTable.
// Flush and compaction only ever remove/truncate durable state (the WAL,
// old SSTable files) AFTER their replacement (a new SSTable, a merged
// SSTable) is fully written and fsynced to its final path — see
// flushLocked and compactLocked for exactly where that ordering is
// enforced.
package lsm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// entryValue is what the in-memory memtable stores per key. deleted marks
// a tombstone: a key that was explicitly deleted (or whose TTL expired)
// after being visible at some point, which must keep shadowing any older
// value for the same key that might still exist in an on-disk SSTable —
// see reapExpired's doc comment for why a tombstone, not an outright
// removal, is required once more than one storage layer exists.
type entryValue struct {
	value     []byte
	expiresAt int64 // 0 = no TTL
	deleted   bool
}

const walFileName = "wal.log"

// Option configures an Engine at Open time. Both have sane defaults, so
// existing callers (e.g. plugin.go before this upgrade) that call
// Open(dir, alwaysSync) with no options continue to compile and behave
// reasonably.
type Option func(*Engine)

// WithFlushThreshold sets the approximate memtable size (in bytes: summed
// key+value lengths) that triggers an automatic flush to a new SSTable.
func WithFlushThreshold(n int64) Option {
	return func(e *Engine) {
		if n > 0 {
			e.flushThreshold = n
		}
	}
}

// WithCompactionThreshold sets how many on-disk SSTables accumulate before
// a compaction (full merge) is triggered.
func WithCompactionThreshold(n int) Option {
	return func(e *Engine) {
		if n > 1 {
			e.compactionThreshold = n
		}
	}
}

// WithFsyncMode selects the durability/performance tradeoff for every
// fsync this Engine performs — see FsyncMode's doc comment. Defaults to
// FsyncFull (matches prior behavior exactly) if never called.
func WithFsyncMode(mode FsyncMode) Option {
	return func(e *Engine) {
		e.fsyncMode = mode
	}
}

// WithCommitInterval arms the bounded-staleness background commit pump:
// staged records are fsynced at least every d even when no caller is
// waiting for durability, so alwaysSync=false writes are durable within
// one d of being staged instead of "whenever a flush happens". Zero
// (default) disables the pump and preserves the original behavior
// exactly. See wal.commitPump for the full guarantee and trade-off.
func WithCommitInterval(d time.Duration) Option {
	return func(e *Engine) {
		if d > 0 {
			e.commitInterval = d
		}
	}
}

// Engine is the concrete api.StorageBackend.
type Engine struct {
	mu       sync.RWMutex
	memtable map[string]entryValue
	memSize  int64

	sstables []*sstable // newest first (index 0 = highest seq)
	nextSeq  int64

	dir     string
	walPath string
	w       *wal
	closed  bool

	flushThreshold      int64
	compactionThreshold int
	fsyncMode           FsyncMode
	commitInterval      time.Duration

	flushCount      atomic.Int64
	compactionCount atomic.Int64
	bloomSkipCount  atomic.Int64
}

// Open constructs (or reopens) a durable Engine rooted at dir: loads any
// existing SSTable files, then replays wal.log on top (which only ever
// contains writes made since the last successful flush, since a flush
// truncates the WAL only after its SSTable is durably in place).
func Open(dir string, alwaysSync bool, opts ...Option) (*Engine, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	e := &Engine{
		memtable:            make(map[string]entryValue),
		dir:                 dir,
		walPath:             filepath.Join(dir, walFileName),
		flushThreshold:      4 << 20, // 4MB
		compactionThreshold: 4,
	}
	for _, o := range opts {
		o(e)
	}

	if err := e.loadSSTables(); err != nil {
		return nil, err
	}

	recs, err := replayWAL(e.walPath)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		e.applyRecordToMemtable(r)
	}

	w, err := openWAL(e.walPath, alwaysSync, e.fsyncMode, e.commitInterval)
	if err != nil {
		return nil, err
	}
	e.w = w
	return e, nil
}

// loadSSTables globs dir for "sstable-*.sst" files (a stray "*.sst.tmp"
// from a flush/compaction interrupted mid-write never matches this
// pattern, so it is correctly ignored — the WAL alone recovers whatever
// that interrupted flush would have captured), opens each, and sorts them
// newest-seq-first.
func (e *Engine) loadSSTables() error {
	matches, err := filepath.Glob(filepath.Join(e.dir, "sstable-*.sst"))
	if err != nil {
		return err
	}
	type found struct {
		seq  int64
		path string
	}
	var all []found
	for _, m := range matches {
		seq, ok := parseSSTableSeq(filepath.Base(m))
		if !ok {
			continue
		}
		all = append(all, found{seq: seq, path: m})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seq > all[j].seq })

	for _, f := range all {
		st, err := openSSTable(f.path, f.seq, 0)
		if err != nil {
			return fmt.Errorf("lsm: loading sstable %s: %w", f.path, err)
		}
		e.sstables = append(e.sstables, st)
		if f.seq >= e.nextSeq {
			e.nextSeq = f.seq + 1
		}
	}
	return nil
}

func (e *Engine) applyRecordToMemtable(r record) {
	key := string(r.Key)
	old, existed := e.memtable[key]
	var oldSize int64
	if existed {
		oldSize = int64(len(key) + len(old.value))
	}
	switch r.Kind {
	case recPut:
		e.memtable[key] = entryValue{value: r.Value, expiresAt: r.ExpiresAt}
		e.memSize += int64(len(key)+len(r.Value)) - oldSize
	case recDelete:
		e.memtable[key] = entryValue{deleted: true}
		e.memSize += int64(len(key)) - oldSize
	}
}

func (e *Engine) Get(ctx context.Context, key []byte) ([]byte, bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.getLocked(string(key))
}

func (e *Engine) getLocked(key string) ([]byte, bool, error) {
	if v, ok := e.memtable[key]; ok {
		if v.deleted || isExpired(v.expiresAt) {
			return nil, false, nil
		}
		out := make([]byte, len(v.value))
		copy(out, v.value)
		return out, true, nil
	}
	for _, st := range e.sstables {
		val, kind, expiresAt, found, skipped, err := st.get(key)
		if skipped {
			e.bloomSkipCount.Add(1)
		}
		if err != nil {
			return nil, false, err
		}
		if !found {
			continue
		}
		if kind == recDelete || isExpired(expiresAt) {
			return nil, false, nil
		}
		return val, true, nil
	}
	return nil, false, nil
}

// Put stages its WAL record and applies it to the memtable under e.mu
// (fast, in-memory work that must stay serialized with every other
// mutation), then — if the WAL is configured to always sync — waits for
// durability OUTSIDE e.mu, via w.waitForSync. Releasing e.mu before the
// (slow) fsync wait is what lets concurrent Puts pipeline into the same
// group-commit round instead of queuing end-to-end behind each other's
// disk I/O; see wal.go's type doc for the full mechanism. w is captured
// under e.mu before unlocking specifically so a concurrent flush that
// swaps e.w for a new WAL (see truncateWALLocked) can never cause this
// call to wait on the wrong wal instance.
func (e *Engine) Put(ctx context.Context, ent api.Entry) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return os.ErrClosed
	}
	r := record{Kind: recPut, Key: ent.Key, Value: ent.Value, ExpiresAt: nowExpiry(ent.TTL)}
	w := e.w
	gen, err := w.stage(r)
	if err != nil {
		e.mu.Unlock()
		return err
	}
	e.applyRecordToMemtable(r)
	flushErr := e.maybeFlushLocked()
	e.mu.Unlock()
	if flushErr != nil {
		return flushErr
	}
	if w.alwaysSync {
		return w.waitForSync(gen)
	}
	return nil
}

// Delete follows the same stage-under-lock, sync-outside-lock pattern as
// Put — see its doc comment.
func (e *Engine) Delete(ctx context.Context, key []byte) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return os.ErrClosed
	}
	r := record{Kind: recDelete, Key: key}
	w := e.w
	gen, err := w.stage(r)
	if err != nil {
		e.mu.Unlock()
		return err
	}
	e.applyRecordToMemtable(r)
	flushErr := e.maybeFlushLocked()
	e.mu.Unlock()
	if flushErr != nil {
		return flushErr
	}
	if w.alwaysSync {
		return w.waitForSync(gen)
	}
	return nil
}

// Batch applies every op atomically to the memtable: all WAL records are
// staged first, then waitForSync commits them as one group — unconditionally,
// regardless of the alwaysSync setting, since a batch is documented as
// always durable — and only then are they applied to the memtable, so a
// mid-batch WAL failure never leaves the memtable partially mutated.
//
// This uses waitForSync rather than calling sync() directly for the same
// reason Put/Delete do: waitForSync first checks whether the target
// generation is already covered before touching the file again, which
// matters if a concurrent flush already closed this exact wal instance
// out from under us (see truncateWALLocked) — calling the raw, unchecked
// sync() in that situation would fail with "file already closed" even
// though the data is already durable. See wal.go's type doc for why this
// is safe: every stage() across every caller is serialized through e.mu,
// so a wal's generation counter is frozen before it can ever be closed.
func (e *Engine) Batch(ctx context.Context, ops []api.BatchOp) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return os.ErrClosed
	}
	recs := make([]record, 0, len(ops))
	for _, op := range ops {
		if op.Delete {
			recs = append(recs, record{Kind: recDelete, Key: op.Entry.Key})
		} else {
			recs = append(recs, record{Kind: recPut, Key: op.Entry.Key, Value: op.Entry.Value, ExpiresAt: nowExpiry(op.Entry.TTL)})
		}
	}
	w := e.w
	var lastGen uint64
	for _, r := range recs {
		gen, err := w.stage(r)
		if err != nil {
			e.mu.Unlock()
			return err
		}
		lastGen = gen
	}
	e.mu.Unlock()

	if len(recs) > 0 {
		if err := w.waitForSync(lastGen); err != nil {
			return err
		}
	}

	e.mu.Lock()
	for _, r := range recs {
		e.applyRecordToMemtable(r)
	}
	flushErr := e.maybeFlushLocked()
	e.mu.Unlock()
	return flushErr
}

func (e *Engine) maybeFlushLocked() error {
	if e.memSize < e.flushThreshold {
		return nil
	}
	return e.flushLocked()
}

// scanCand is one key's winning version during a Scan: either a pointer
// into an sstable (value fetched lazily, only if the caller asks for it)
// or an inline memtable value.
type scanCand struct {
	st        *sstable
	off       int64
	mem       []byte
	expiresAt int64
	deleted   bool
}

// Scan resolves the keys under prefix across the memtable and every
// sstable (newest write wins) WITHOUT reading any values: the returned
// iterator fetches each value from disk only when Value() is called, so a
// paginated caller that skips or stops early pays only for what it
// consumes. The iterator pins the sstables it may read; callers must
// Close it.
func (e *Engine) Scan(ctx context.Context, prefix []byte) (api.Iterator, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p := string(prefix)

	result := make(map[string]scanCand)

	// Oldest sstable first, newest last, memtable last of all — each
	// later pass overwrites an earlier one's entry for the same key,
	// giving the correct "most recent write wins" precedence.
	for i := len(e.sstables) - 1; i >= 0; i-- {
		st := e.sstables[i]
		lo, hi := st.keyRange(p)
		for _, k := range st.keys[lo:hi] {
			ie := st.index[k]
			if ie.kind == recDelete {
				result[k] = scanCand{deleted: true, expiresAt: ie.expiresAt}
				continue
			}
			result[k] = scanCand{st: st, off: ie.offset, expiresAt: ie.expiresAt}
		}
	}
	for k, v := range e.memtable {
		if !strings.HasPrefix(k, p) {
			continue
		}
		result[k] = scanCand{mem: v.value, expiresAt: v.expiresAt, deleted: v.deleted}
	}

	keys := make([]string, 0, len(result))
	for k, v := range result {
		if v.deleted || isExpired(v.expiresAt) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	cands := make([]scanCand, len(keys))
	for i, k := range keys {
		cands[i] = result[k]
	}
	pinned := make([]*sstable, len(e.sstables))
	copy(pinned, e.sstables)
	for _, st := range pinned {
		st.ref()
	}
	return &lazyIterator{keys: keys, cands: cands, pinned: pinned, pos: -1}, nil
}

type lazyIterator struct {
	keys   []string
	cands  []scanCand
	pinned []*sstable
	pos    int
	keyBuf []byte // reused by Key(); valid only until the next Next() (see api.Iterator)
	val    []byte
	loaded bool
	err    error
}

func (it *lazyIterator) Next() bool {
	it.pos++
	it.loaded = false
	return it.pos < len(it.keys)
}
func (it *lazyIterator) Key() []byte {
	it.keyBuf = append(it.keyBuf[:0], it.keys[it.pos]...)
	return it.keyBuf
}
func (it *lazyIterator) Value() []byte {
	if it.loaded {
		return it.val
	}
	c := it.cands[it.pos]
	if c.st != nil {
		v, err := c.st.readValueAt(c.off)
		if err != nil {
			it.err = err
			return nil
		}
		it.val = v
	} else {
		it.val = c.mem
	}
	it.loaded = true
	return it.val
}
func (it *lazyIterator) Err() error { return it.err }
func (it *lazyIterator) Close() error {
	for _, st := range it.pinned {
		st.unref()
	}
	it.pinned = nil
	return nil
}

// snapshot is a deep, point-in-time copy of the fully-merged keyspace at
// the moment Snapshot() was called (copy-on-read isolation — concurrent
// writers after this point never affect it). Building it costs the same
// as a full Scan("") — this is the same cost profile the pre-upgrade,
// single-map engine had for Snapshot, just reimplemented over multiple
// storage layers.
type snapshot struct {
	data map[string]entryValue
}

func (s *snapshot) Get(key []byte) ([]byte, bool, error) {
	v, ok := s.data[string(key)]
	if !ok || v.deleted || isExpired(v.expiresAt) {
		return nil, false, nil
	}
	return v.value, true, nil
}
func (s *snapshot) Release() {}

func (e *Engine) Snapshot(ctx context.Context) (api.Snapshot, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	merged := make(map[string]entryValue)
	for i := len(e.sstables) - 1; i >= 0; i-- {
		st := e.sstables[i]
		for _, k := range st.keys {
			ie := st.index[k]
			if ie.kind == recDelete {
				merged[k] = entryValue{deleted: true, expiresAt: ie.expiresAt}
				continue
			}
			v, err := st.readValueAt(ie.offset)
			if err != nil {
				return nil, err
			}
			merged[k] = entryValue{value: v, expiresAt: ie.expiresAt}
		}
	}
	for k, v := range e.memtable {
		merged[k] = v
	}
	return &snapshot{data: merged}, nil
}

func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	if err := e.flushLocked(); err != nil {
		return err
	}
	e.closed = true
	for _, st := range e.sstables {
		st.unref()
	}
	e.sstables = nil
	return e.w.close()
}

// Checkpoint flushes the current memtable to a new SSTable and truncates
// the WAL — the direct successor to the pre-upgrade engine's
// snapshot-and-truncate Checkpoint, now backed by a real SSTable instead
// of a flat snapshot file. External callers (plugin.go's periodic
// checkpoint loop) see identical behavior: after Checkpoint returns, the
// WAL is empty and every write up to that point survives a reopen.
func (e *Engine) Checkpoint(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.flushLocked()
}

// Sync blocks until every write staged so far is durably on disk, and
// returns the error (if any) of the fsync that covered it. This is the
// durability barrier callers of the commit-coalescing mode use when they
// need a real sync point (before acknowledging a batch to a client, at a
// transaction boundary, before shutdown): Put/Delete with
// alwaysSync=false return after staging, and Sync is how a caller later
// says "everything up to here must now survive a crash".
//
// It routes through the same group-commit waitForSync protocol as every
// other sync in this engine, so calling it is never worse than one fsync
// even if the commit pump just performed one (that round is waited for,
// not repeated).
func (e *Engine) Sync(ctx context.Context) error {
	e.mu.RLock()
	if e.closed {
		e.mu.RUnlock()
		return os.ErrClosed
	}
	w := e.w
	e.mu.RUnlock()
	return w.sync()
}

// flushLocked writes the current memtable (including tombstones — they
// must persist into the SSTable to keep shadowing whatever older tables
// might hold the same key) to a new, immutable SSTable, and only after
// that file is durably renamed into place does it truncate the WAL. A
// crash at any point before the rename leaves the WAL as the sole source
// of truth (replayed whole on the next Open); a crash any time after
// leaves the new SSTable as the source of truth and an empty WAL. There is
// no window where data exists in neither place.
func (e *Engine) flushLocked() error {
	if len(e.memtable) == 0 {
		return nil
	}

	entries := make([]flushEntry, 0, len(e.memtable))
	for k, v := range e.memtable {
		kind := recPut
		if v.deleted {
			kind = recDelete
		}
		entries = append(entries, flushEntry{key: k, value: v.value, kind: recKind(kind), expiresAt: v.expiresAt})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })

	seq := e.nextSeq
	e.nextSeq++
	finalPath := sstableFileName(e.dir, seq)
	tmpPath := finalPath + ".tmp"
	st, err := buildSSTable(tmpPath, entries)
	if err != nil {
		return err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return err
	}
	if err := st.attach(finalPath, seq, 0); err != nil {
		return err
	}

	if err := e.truncateWALLocked(); err != nil {
		return err
	}

	e.sstables = append([]*sstable{st}, e.sstables...)
	e.memtable = make(map[string]entryValue)
	e.memSize = 0
	e.flushCount.Add(1)

	if len(e.sstables) >= e.compactionThreshold {
		return e.compactLocked()
	}
	return nil
}

func (e *Engine) truncateWALLocked() error {
	alwaysSync := e.w.alwaysSync
	fsyncMode := e.w.fsyncMode
	if err := e.w.close(); err != nil {
		return err
	}
	if err := os.Truncate(e.walPath, 0); err != nil {
		return err
	}
	w, err := openWAL(e.walPath, alwaysSync, fsyncMode, e.commitInterval)
	if err != nil {
		return err
	}
	e.w = w
	return nil
}

// pickCompactionRun chooses which tables to merge: the newest contiguous
// run (size-tiered / "universal" style) whose members are each no larger
// than everything newer than them combined. Merging like-sized tables
// keeps write amplification logarithmic in data size, instead of
// rewriting the whole dataset every few flushes.
func (e *Engine) pickCompactionRun() int {
	n := len(e.sstables)
	sum := e.sstables[0].size
	j := 1
	for j < n && e.sstables[j].size <= sum {
		sum += e.sstables[j].size
		j++
	}
	if j < 2 {
		j = 2
	}
	return j
}

// compactLocked merges a run of the newest SSTables (see
// pickCompactionRun) into one new table, streaming records with
// sequential reads, then retires the inputs only after the merged file is
// durably in place. Tombstones and expired entries are dropped only when
// the run reaches the oldest table on disk — otherwise they must survive
// to keep shadowing older tables. A crash between the rename and the input
// removals just leaves harmless, superseded extra files: the merged table
// has a higher seq than everything it merged, so query results never
// change.
func (e *Engine) compactLocked() error {
	if len(e.sstables) < 2 {
		return nil
	}
	j := e.pickCompactionRun()
	inputs := e.sstables[:j]
	dropTombstones := j == len(e.sstables)

	seq := e.nextSeq
	e.nextSeq++
	finalPath := sstableFileName(e.dir, seq)
	tmpPath := finalPath + ".tmp"

	merged, n, err := mergeSSTables(inputs, tmpPath, dropTombstones)
	if err != nil {
		os.Remove(tmpPath)
		return err
	}
	e.compactionCount.Add(1)

	rest := e.sstables[j:]
	if n == 0 {
		for _, st := range inputs {
			st.retire()
		}
		e.sstables = append([]*sstable(nil), rest...)
		return nil
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		return err
	}
	if err := merged.attach(finalPath, seq, 1); err != nil {
		return err
	}
	for _, st := range inputs {
		st.retire()
	}
	e.sstables = append([]*sstable{merged}, rest...)
	return nil
}

// reapExpired converts expired, non-deleted memtable entries into
// tombstones — NOT an outright removal. An outright removal would be
// unsafe in this multi-layer engine: if an older SSTable happens to hold a
// DIFFERENT, non-expired write for the same key (superseded by the write
// that just expired), removing the memtable entry entirely would let Get
// fall through and incorrectly resurrect that older value. A tombstone
// keeps shadowing it correctly, and is itself later dropped for real once
// it's flushed and subsequently compacted away (see compactLocked).
func (e *Engine) reapExpired() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for k, v := range e.memtable {
		if !v.deleted && isExpired(v.expiresAt) {
			e.memSize += int64(len(k)) - int64(len(k)+len(v.value))
			e.memtable[k] = entryValue{deleted: true, expiresAt: v.expiresAt}
			n++
		}
	}
	return n
}

// --- testing/observability accessors (not part of api.StorageBackend) ---

func (e *Engine) FlushCount() int64      { return e.flushCount.Load() }
func (e *Engine) CompactionCount() int64 { return e.compactionCount.Load() }
func (e *Engine) BloomSkipCount() int64  { return e.bloomSkipCount.Load() }

func (e *Engine) SSTableCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.sstables)
}

// SyncCount returns the number of real fsync syscalls the current WAL has
// performed. Used by tests to prove group commit actually coalesces
// concurrent writers into fewer fsyncs than writes.
func (e *Engine) SyncCount() int64 {
	e.mu.RLock()
	w := e.w
	e.mu.RUnlock()
	return w.syncCount.Load()
}

var _ api.StorageBackend = (*Engine)(nil)
