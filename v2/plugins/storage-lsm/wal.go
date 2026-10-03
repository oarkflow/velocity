// Package lsm implements a durable, crash-recoverable api.StorageBackend
// on top of a write-ahead log + in-memory index, checkpointed to a
// snapshot file. It is a simplified port of v1's wal.go/memtable.go/
// sstable.go durability model (append-only WAL, replay on startup,
// periodic checkpoint that compacts the WAL away) rather than a full
// multi-level SSTable engine — see the package doc in plugin.go for the
// scope note.
package lsm

import (
	"bufio"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// FsyncMode selects which durability guarantee a "durable write" actually
// buys, independent of alwaysSync (which selects WHEN a sync happens —
// every write vs never). This distinction exists because on Darwin,
// Go's os.File.Sync() does NOT call the plain POSIX fsync(2) syscall — it
// calls fcntl(F_FULLFSYNC), which forces the drive to flush its volatile
// write cache to the physical platter. That is real protection against
// power loss, but it measures at ~1.5-2.5ms per call on typical
// hardware/filesystems, because it's doing meaningfully more work than a
// plain fsync().
//
// A same-machine benchmark against SQLite's default WAL+synchronous=FULL
// configuration showed storage-lsm's Put at ~264x SQLite's — investigating
// why turned up that SQLite's default macOS VFS does NOT use F_FULLFSYNC
// (only plain fsync(), measured at ~180-220µs here), so the two were never
// actually providing the same guarantee: storage-lsm in FsyncFull mode
// survives real power loss, SQLite's default does not (data can still be
// lost from the drive's write cache on power failure, though not on an OS
// or process crash — WAL replay still recovers correctly from those).
//
// FsyncPosix trades that specific guarantee (power-loss survival) for
// matching SQLite's actual default performance/durability tradeoff — the
// one nearly every application using SQLite's defaults is actually
// running with, whether they realize it or not. Both modes fully survive
// process crashes and OS crashes (a killed process, a panic, `kill -9`) —
// the difference is strictly about a real, unexpected power interruption
// mid-write. On Linux, both modes currently behave identically (plain
// fsync(2) is Linux's only fsync mechanism at this level; Linux's
// equivalent stronger guarantee would need an explicit write-barrier /
// device-specific flush, which is out of scope here).
type FsyncMode int

const (
	// FsyncFull is the default: os.File.Sync(), which is fcntl(F_FULLFSYNC)
	// on Darwin (survives real power loss) and plain fsync(2) on Linux.
	FsyncFull FsyncMode = iota
	// FsyncPosix always issues the plain POSIX fsync(2) syscall directly
	// (via golang.org/x/sys/unix.Fsync), even on Darwin — this is strictly
	// faster and strictly weaker than FsyncFull there, and identical to it
	// on Linux. Matches SQLite's, and most other databases', actual
	// default behavior.
	FsyncPosix
)

func (m FsyncMode) String() string {
	if m == FsyncPosix {
		return "posix"
	}
	return "full"
}

// ParseFsyncMode accepts "full" (default) or "posix"/"fast" (case
// sensitive is not required — matched case-insensitively by the caller if
// desired); any other value, including "", returns FsyncFull.
func ParseFsyncMode(s string) FsyncMode {
	switch s {
	case "posix", "fast":
		return FsyncPosix
	default:
		return FsyncFull
	}
}

// recKind distinguishes a live write from a tombstone in the WAL/snapshot
// record stream.
type recKind byte

const (
	recPut recKind = iota + 1
	recDelete
)

// record is one WAL entry: kind, key, value, and an absolute expiry unix
// nano (0 = no TTL).
type record struct {
	Kind      recKind
	Key       []byte
	Value     []byte
	ExpiresAt int64
}

// writeRecord encodes one record as:
//
//	[1 byte kind][4 bytes keyLen][4 bytes valLen][8 bytes expiresAt][key][val][4 byte crc32]
//
// crc32 covers everything before it, so a torn write at the tail (a crash
// mid-append) is detected and safely truncated on replay instead of
// corrupting the in-memory index.
func writeRecord(w *bufio.Writer, r record) error {
	var buf [1 + 4 + 4 + 8]byte
	buf[0] = byte(r.Kind)
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(r.Key)))
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(r.Value)))
	binary.BigEndian.PutUint64(buf[9:17], uint64(r.ExpiresAt))

	crc := crc32.Update(0, crc32.IEEETable, buf[:])
	crc = crc32.Update(crc, crc32.IEEETable, r.Key)
	crc = crc32.Update(crc, crc32.IEEETable, r.Value)

	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	if _, err := w.Write(r.Key); err != nil {
		return err
	}
	if _, err := w.Write(r.Value); err != nil {
		return err
	}
	var crcBuf [4]byte
	binary.BigEndian.PutUint32(crcBuf[:], crc)
	_, err := w.Write(crcBuf[:])
	return err
}

// readRecord decodes one record, returning io.EOF only on a clean
// end-of-stream (zero bytes read for the header). Any partial/corrupt
// trailing record is reported as io.ErrUnexpectedEOF or a crc mismatch,
// both of which the replay loop treats as "stop here, this is a torn
// write from a crash mid-append" rather than a fatal error.
func readRecord(r io.Reader) (record, error) {
	header := make([]byte, 1+4+4+8)
	if _, err := io.ReadFull(r, header); err != nil {
		return record{}, err
	}
	kind := recKind(header[0])
	keyLen := binary.BigEndian.Uint32(header[1:5])
	valLen := binary.BigEndian.Uint32(header[5:9])
	expiresAt := int64(binary.BigEndian.Uint64(header[9:17]))

	h := crc32.NewIEEE()
	h.Write(header)

	key := make([]byte, keyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return record{}, io.ErrUnexpectedEOF
	}
	h.Write(key)

	val := make([]byte, valLen)
	if _, err := io.ReadFull(r, val); err != nil {
		return record{}, io.ErrUnexpectedEOF
	}
	h.Write(val)

	var crcBuf [4]byte
	if _, err := io.ReadFull(r, crcBuf[:]); err != nil {
		return record{}, io.ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint32(crcBuf[:]) != h.Sum32() {
		return record{}, errors.New("lsm: wal record checksum mismatch (torn write)")
	}

	return record{Kind: kind, Key: key, Value: val, ExpiresAt: expiresAt}, nil
}

// wal is an append-only log file plus the fsync policy controlling how
// often writes are flushed to disk.
//
// Writes use group commit: stage() appends a record to the in-memory
// buffer under l.mu (fast, no I/O) and returns a monotonically increasing
// generation number; waitForSync(gen) is the only call that actually
// performs an fsync, and it coalesces every caller currently waiting for
// a generation covered by an in-flight fsync into that SAME syscall
// instead of each doing its own — one physical fsync durably commits many
// logical writes. This is the same technique SQLite's WAL mode, LevelDB,
// and RocksDB use; without it, every writer serializes end-to-end through
// disk I/O even though only the fsync itself is genuinely exclusive
// hardware work.
//
// Two separate mutexes are involved, on purpose:
//   - l.mu guards the buffer (l.w) and the generation counter (l.gen). It
//     is held only for fast, in-memory operations: appending to the
//     buffer (stage) and the Flush()+Sync() pair itself
//     (flushAndSync) — never for anything that blocks on another
//     goroutine.
//   - l.syncMu (with l.cond) coordinates WHO performs a given round's
//     fsync (the "leader") versus who just waits for it (a "follower").
//     It is never held while l.mu is held or while the fsync syscall
//     itself is running, so a follower blocked in cond.Wait() never
//     blocks a concurrent stage() call from another writer.
type wal struct {
	f          *os.File
	path       string
	alwaysSync bool
	fsyncMode  FsyncMode

	mu  sync.Mutex
	w   *bufio.Writer
	gen uint64 // number of records staged so far

	syncMu    sync.Mutex
	cond      *sync.Cond // Wait/Broadcast, guarded by syncMu
	syncing   bool
	syncedGen uint64
	syncErr   error

	syncCount atomic.Int64 // real fsync syscalls performed; testing/observability only
}

func openWAL(path string, alwaysSync bool, mode FsyncMode) (*wal, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	l := &wal{f: f, w: bufio.NewWriter(f), path: path, alwaysSync: alwaysSync, fsyncMode: mode}
	l.cond = sync.NewCond(&l.syncMu)
	return l, nil
}

// doSync performs the actual durable-flush syscall according to
// l.fsyncMode — see FsyncMode's doc comment for the real tradeoff. The
// FsyncPosix path is platform-specific (see wal_unix.go/wal_windows.go):
// on Unix it's the plain fsync(2) syscall via golang.org/x/sys/unix; on
// Windows it falls back to the same call FsyncFull uses, since Windows has
// no weaker/faster alternative to FlushFileBuffers at this level — see
// platformPosixFsync's doc comment in wal_windows.go for why.
func (l *wal) doSync() error {
	if l.fsyncMode == FsyncPosix {
		return platformPosixFsync(l.f)
	}
	return l.f.Sync()
}

// stage appends r to the buffered WAL writer and returns the generation
// number that now includes it. It never performs I/O beyond the buffered
// writer (no syscall, no fsync) — callers needing durability call
// waitForSync(gen) afterward, outside whatever higher-level lock they
// used to serialize the staging step, so other stagers and any in-flight
// fsync can proceed concurrently with the wait.
func (l *wal) stage(r record) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := writeRecord(l.w, r); err != nil {
		return 0, err
	}
	l.gen++
	return l.gen, nil
}

// waitForSync blocks until the WAL has been durably fsynced through at
// least targetGen, and returns the error (if any) from whichever fsync
// covered it. Concurrent callers targeting generations covered by the
// same in-flight fsync all observe that one round's result — see the type
// doc for why this is the actual group-commit mechanism.
func (l *wal) waitForSync(targetGen uint64) error {
	l.syncMu.Lock()
	for l.syncedGen < targetGen && l.syncing {
		l.cond.Wait()
	}
	if l.syncedGen >= targetGen {
		err := l.syncErr
		l.syncMu.Unlock()
		return err
	}
	// Nobody else is currently flushing and we're not yet covered: become
	// the leader for this round. Release syncMu before doing any real
	// work — flushAndSync only touches l.mu/l.f, never syncMu, so a
	// leader never holds both at once.
	l.syncing = true
	l.syncMu.Unlock()

	doneGen, err := l.flushAndSync()

	l.syncMu.Lock()
	l.syncedGen = doneGen
	l.syncErr = err
	l.syncing = false
	l.cond.Broadcast()
	l.syncMu.Unlock()

	if targetGen <= doneGen {
		return err
	}
	// Our own generation was staged after doneGen was captured — stage()
	// and flushAndSync both serialize through l.mu, so in practice
	// doneGen (read as l.gen at the moment of the leader's Flush) already
	// includes any record staged before waitForSync was called for it.
	// This retry exists as a safety net, not an expected path.
	return l.waitForSync(targetGen)
}

// flushAndSync performs the actual Flush()+Sync() syscalls and reports the
// generation it covered (everything staged up to and including the
// moment of the flush).
//
// Only the Flush() half is guarded by l.mu — it moves buffered bytes into
// the OS file via a Write() syscall, which must not interleave with a
// concurrent stage() call's own write to the same buffer. Sync() runs
// AFTER releasing l.mu: it durably persists whatever was just flushed,
// but a concurrent Write() to the same fd from a LATER stage()/Flush() is
// safe to interleave with an in-flight Sync() at the OS level (fsync's
// guarantee is only about bytes written before it was called), so there
// is no need to block new writers for the syscall's whole (comparatively
// slow) duration.
//
// This is the entire mechanism that makes group commit actually coalesce
// fsyncs rather than just add queueing delay: while this call is blocked
// in Sync(), other goroutines can concurrently stage new records into the
// now-drained buffer and pile up behind waitForSync's leader/follower
// protocol, so the NEXT round covers all of them with one more fsync
// instead of one each. An earlier version of this function held l.mu for
// the full Flush()+Sync() duration, which serialized every writer through
// the slow syscall and measured as exactly one fsync per write under
// concurrent load — see groupcommit_test.go's coalescing test, which
// caught that regression.
func (l *wal) flushAndSync() (coveredGen uint64, err error) {
	l.mu.Lock()
	if err := l.w.Flush(); err != nil {
		coveredGen = l.gen
		l.mu.Unlock()
		return coveredGen, err
	}
	coveredGen = l.gen
	l.mu.Unlock()

	if err := l.doSync(); err != nil {
		return coveredGen, err
	}
	l.syncCount.Add(1)
	return coveredGen, nil
}

// sync ensures every record staged so far is durably fsynced, by reading
// the current generation and routing through waitForSync — the SAME
// leader/follower protocol Put/Delete/Batch use, not an independent
// flushAndSync call.
//
// This matters beyond just reusing code: close() calls sync() while
// another goroutine's group-commit round may already be in flight (that
// goroutine staged earlier, released its caller's higher-level lock, and
// is now blocked in flushAndSync's Sync() call outside of l.mu — see its
// doc comment for why that's necessary for coalescing). If sync() called
// flushAndSync directly, it could run its own Sync() concurrently with
// that in-flight one, and close() would then call l.f.Close() with no
// guarantee the OTHER goroutine's independent Sync() call had returned —
// an unsynchronized concurrent Sync()-vs-Close() on the same *os.File.
// Routing through waitForSync instead means sync() always WAITS for any
// in-flight round (rather than racing it) before either confirming that
// round already covers it or becoming the leader for one more — so by
// the time sync() returns, l.syncing is guaranteed false and no other
// Sync() call on this wal can possibly still be running, making it safe
// for close() to then close the file.
func (l *wal) sync() error {
	l.mu.Lock()
	gen := l.gen
	l.mu.Unlock()
	return l.waitForSync(gen)
}

func (l *wal) close() error {
	if err := l.sync(); err != nil {
		l.f.Close()
		return err
	}
	return l.f.Close()
}

// replay reads every well-formed record from the WAL file at path in
// order, stopping cleanly at the first torn/corrupt trailing record
// (a crash mid-append) rather than failing the whole replay.
func replayWAL(path string) ([]record, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := bufio.NewReader(f)
	var out []record
	for {
		rec, err := readRecord(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			// Torn write or checksum mismatch at the tail: stop replay
			// here, keep everything read so far. This is the same
			// crash-safety guarantee v1's WAL replay provided.
			break
		}
		out = append(out, rec)
	}
	return out, nil
}

func nowExpiry(ttl time.Duration) int64 {
	if ttl <= 0 {
		return 0
	}
	return time.Now().Add(ttl).UnixNano()
}

func isExpired(expiresAt int64) bool {
	return expiresAt != 0 && time.Now().UnixNano() >= expiresAt
}
