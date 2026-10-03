package lsm

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

// sstableMagic is written at the very end of every SSTable file so
// openSSTable can sanity-check it opened a real SSTable rather than a
// truncated/garbage file.
const sstableMagic uint64 = 0x53535441424C4531 // "SSTABLE1" in hex-ish ASCII

// flushEntry is one record destined for a new SSTable, in the sorted order
// buildSSTable expects.
type flushEntry struct {
	key       string
	value     []byte
	kind      recKind
	expiresAt int64
}

// sstIndexEntry is what an SSTable's in-memory index (loaded fully into
// memory by openSSTable — see the package doc in engine.go for why this
// isn't a truly sparse, page-granular index like v1's) records per key:
// where its record starts in the data section, and enough of the record's
// own header (kind, expiry) to answer tombstone/expiry questions without a
// disk read.
type sstIndexEntry struct {
	offset    int64
	kind      recKind
	expiresAt int64
}

// sstable is one immutable, sorted, on-disk table: a data section of
// length-prefixed records (the same format as WAL records, see wal.go's
// writeRecord/readRecord), followed by a full key index and a Bloom
// filter, followed by a fixed-size footer. seq is the monotonically
// increasing sequence number embedded in the filename
// ("sstable-<seq>.sst"); Get/Scan always prefer the highest-seq table
// among any that contain a key, since that is always the most recent
// write. level is bookkeeping only.
//
// The file stays open for the table's lifetime and values are fetched with
// pread (ReadAt), so a lookup costs one syscall instead of open+seek+close.
// Tables are reference counted: the engine holds one reference while the
// table is live, and lazy Scan iterators hold their own, so a compaction
// can retire a table without yanking its file out from under a reader.
type sstable struct {
	path    string
	seq     int64
	level   int
	index   map[string]sstIndexEntry
	keys    []string // sorted ascending; same key set as index
	bloom   *bloomFilter
	f       *os.File
	size    int64
	dataEnd int64 // end of the record section (== start of the index)

	refs     atomic.Int32
	obsolete atomic.Bool
}

func (s *sstable) ref() { s.refs.Add(1) }

// unref drops one reference; the last one closes the file and, if the
// table was retired by a compaction, deletes it from disk.
func (s *sstable) unref() {
	if s.refs.Add(-1) != 0 {
		return
	}
	if s.f != nil {
		s.f.Close()
	}
	if s.obsolete.Load() {
		os.Remove(s.path)
	}
}

// retire marks the table as superseded and releases the engine's own
// reference.
func (s *sstable) retire() {
	s.obsolete.Store(true)
	s.unref()
}

// keyRange returns the half-open [lo,hi) positions in s.keys of every key
// with the given prefix.
func (s *sstable) keyRange(prefix string) (lo, hi int) {
	lo = sort.SearchStrings(s.keys, prefix)
	hi = lo
	for hi < len(s.keys) && strings.HasPrefix(s.keys[hi], prefix) {
		hi++
	}
	return lo, hi
}

func recordEncodedLen(r record) int64 {
	return int64(1+4+4+8+len(r.Key)+len(r.Value)) + 4 // header + key + value + trailing crc32
}

// sstWriter streams sorted records into a new SSTable file. Entries must
// be added in ascending key order.
type sstWriter struct {
	f      *os.File
	w      *bufio.Writer
	offset int64
	bloom  *bloomFilter
	idx    []sstIndexEntry
	keys   []string
	err    error
}

func newSSTWriter(path string, expected int) (*sstWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &sstWriter{
		f:     f,
		w:     bufio.NewWriterSize(f, 256<<10),
		bloom: newBloomFilter(expected, 0.01),
		idx:   make([]sstIndexEntry, 0, expected),
		keys:  make([]string, 0, expected),
	}, nil
}

func (sw *sstWriter) add(key string, value []byte, kind recKind, expiresAt int64) error {
	if sw.err != nil {
		return sw.err
	}
	r := record{Kind: kind, Key: []byte(key), Value: value, ExpiresAt: expiresAt}
	if err := writeRecord(sw.w, r); err != nil {
		sw.err = err
		return err
	}
	sw.keys = append(sw.keys, key)
	sw.idx = append(sw.idx, sstIndexEntry{offset: sw.offset, kind: kind, expiresAt: expiresAt})
	sw.bloom.add(r.Key)
	sw.offset += recordEncodedLen(r)
	return nil
}

func (sw *sstWriter) abort() {
	sw.f.Close()
}

// finish writes index, bloom and footer, fsyncs and closes the file. It
// returns the table's in-memory form (without an open read handle — see
// attach) so a freshly written table never has to be re-parsed from disk.
func (sw *sstWriter) finish() (*sstable, error) {
	if sw.err != nil {
		sw.f.Close()
		return nil, sw.err
	}
	indexStart := sw.offset
	offset := sw.offset
	var hdr [21]byte
	for i, k := range sw.keys {
		ie := sw.idx[i]
		binary.BigEndian.PutUint32(hdr[0:4], uint32(len(k)))
		binary.BigEndian.PutUint64(hdr[4:12], uint64(ie.offset))
		hdr[12] = byte(ie.kind)
		binary.BigEndian.PutUint64(hdr[13:21], uint64(ie.expiresAt))
		if _, err := sw.w.Write(hdr[:]); err != nil {
			sw.f.Close()
			return nil, err
		}
		if _, err := sw.w.WriteString(k); err != nil {
			sw.f.Close()
			return nil, err
		}
		offset += int64(len(hdr) + len(k))
	}

	bloomStart := offset
	bloomBytes := sw.bloom.encode()
	if _, err := sw.w.Write(bloomBytes); err != nil {
		sw.f.Close()
		return nil, err
	}
	offset += int64(len(bloomBytes))

	footer := make([]byte, 32)
	binary.BigEndian.PutUint64(footer[0:8], uint64(indexStart))
	binary.BigEndian.PutUint64(footer[8:16], uint64(bloomStart))
	binary.BigEndian.PutUint64(footer[16:24], uint64(len(sw.keys)))
	binary.BigEndian.PutUint64(footer[24:32], sstableMagic)
	if _, err := sw.w.Write(footer); err != nil {
		sw.f.Close()
		return nil, err
	}
	offset += 32

	if err := sw.w.Flush(); err != nil {
		sw.f.Close()
		return nil, err
	}
	if err := sw.f.Sync(); err != nil {
		sw.f.Close()
		return nil, err
	}
	if err := sw.f.Close(); err != nil {
		return nil, err
	}

	index := make(map[string]sstIndexEntry, len(sw.keys))
	for i, k := range sw.keys {
		index[k] = sw.idx[i]
	}
	return &sstable{index: index, keys: sw.keys, bloom: sw.bloom, size: offset, dataEnd: indexStart}, nil
}

// attach opens the finished table at its final path for reading and gives
// it its identity. The caller owns the single initial reference.
func (s *sstable) attach(path string, seq int64, level int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	s.f, s.path, s.seq, s.level = f, path, seq, level
	s.refs.Store(1)
	return nil
}

// buildSSTable writes entries (already sorted ascending by key) to path,
// fsyncs, and closes, returning the in-memory table (not yet attached).
// The caller is responsible for writing to a .tmp path and atomically
// renaming into place, then calling attach on the final path.
func buildSSTable(path string, entries []flushEntry) (*sstable, error) {
	sw, err := newSSTWriter(path, len(entries))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if err := sw.add(e.key, e.value, e.kind, e.expiresAt); err != nil {
			sw.abort()
			return nil, err
		}
	}
	return sw.finish()
}

// openSSTable loads an existing SSTable's footer, index, and Bloom filter
// fully into memory (see the package doc note on this being a full, not
// sparse, index), leaving the data section to be read from disk on demand
// per key via readValueAt.
func openSSTable(path string, seq int64, level int) (*sstable, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	if size < 32 {
		return nil, fmt.Errorf("lsm: sstable %s too small to contain a valid footer", path)
	}

	footer := make([]byte, 32)
	if _, err := f.ReadAt(footer, size-32); err != nil {
		return nil, err
	}
	indexStart := int64(binary.BigEndian.Uint64(footer[0:8]))
	bloomStart := int64(binary.BigEndian.Uint64(footer[8:16]))
	count := binary.BigEndian.Uint64(footer[16:24])
	magic := binary.BigEndian.Uint64(footer[24:32])
	if magic != sstableMagic {
		return nil, fmt.Errorf("lsm: sstable %s has bad magic (corrupt or not an sstable)", path)
	}

	indexBuf := make([]byte, bloomStart-indexStart)
	if _, err := f.ReadAt(indexBuf, indexStart); err != nil {
		return nil, err
	}
	bloomBuf := make([]byte, (size-32)-bloomStart)
	if _, err := f.ReadAt(bloomBuf, bloomStart); err != nil {
		return nil, err
	}
	bf, err := decodeBloomFilter(bloomBuf)
	if err != nil {
		return nil, err
	}

	index := make(map[string]sstIndexEntry, count)
	keys := make([]string, 0, count)
	pos := 0
	for pos < len(indexBuf) {
		if pos+21 > len(indexBuf) {
			break
		}
		klen := int(binary.BigEndian.Uint32(indexBuf[pos : pos+4]))
		off := int64(binary.BigEndian.Uint64(indexBuf[pos+4 : pos+12]))
		kind := recKind(indexBuf[pos+12])
		expiresAt := int64(binary.BigEndian.Uint64(indexBuf[pos+13 : pos+21]))
		pos += 21
		if pos+klen > len(indexBuf) {
			break
		}
		key := string(indexBuf[pos : pos+klen])
		pos += klen
		index[key] = sstIndexEntry{offset: off, kind: kind, expiresAt: expiresAt}
		keys = append(keys, key)
	}
	if !sort.StringsAreSorted(keys) {
		sort.Strings(keys)
	}

	ok = true
	st := &sstable{path: path, seq: seq, level: level, index: index, keys: keys, bloom: bf, f: f, size: size, dataEnd: indexStart}
	st.refs.Store(1)
	return st, nil
}

// readValueAt fetches the record at offset with pread — typically a single
// syscall (the first read speculatively grabs 512 bytes, enough for small
// records) — and verifies its checksum.
func (s *sstable) readValueAt(offset int64) ([]byte, error) {
	var first [512]byte
	n, err := s.f.ReadAt(first[:], offset)
	if n < 17 {
		if err == nil || err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	klen := int(binary.BigEndian.Uint32(first[1:5]))
	vlen := int(binary.BigEndian.Uint32(first[5:9]))
	total := 17 + klen + vlen + 4
	var rec []byte
	if total <= n {
		rec = first[:total]
	} else {
		rec = make([]byte, total)
		copy(rec, first[:n])
		if _, err := s.f.ReadAt(rec[n:], offset+int64(n)); err != nil {
			return nil, io.ErrUnexpectedEOF
		}
	}
	if binary.BigEndian.Uint32(rec[total-4:]) != crc32.ChecksumIEEE(rec[:total-4]) {
		return nil, errors.New("lsm: sstable record checksum mismatch")
	}
	out := make([]byte, vlen)
	copy(out, rec[17+klen:17+klen+vlen])
	return out, nil
}

// get looks up key, consulting the Bloom filter first. bloomSkipped is
// true when the Bloom filter alone was enough to prove key is absent
// (used by the engine to count avoided disk reads).
func (s *sstable) get(key string) (value []byte, kind recKind, expiresAt int64, found bool, bloomSkipped bool, err error) {
	if s.bloom != nil && !s.bloom.mayContainString(key) {
		return nil, 0, 0, false, true, nil
	}
	ie, ok := s.index[key]
	if !ok {
		return nil, 0, 0, false, false, nil
	}
	if ie.kind == recDelete {
		return nil, recDelete, ie.expiresAt, true, false, nil
	}
	v, err := s.readValueAt(ie.offset)
	if err != nil {
		return nil, 0, 0, false, false, err
	}
	return v, ie.kind, ie.expiresAt, true, false, nil
}

// sstCursor streams a table's records in key order with large sequential
// reads (used by compaction instead of one random read per value).
type sstCursor struct {
	st  *sstable
	r   *bufio.Reader
	cur record
	ok  bool
	err error
}

func newSSTCursor(st *sstable) *sstCursor {
	c := &sstCursor{st: st, r: bufio.NewReaderSize(io.NewSectionReader(st.f, 0, st.dataEnd), 256<<10)}
	c.advance()
	return c
}

func (c *sstCursor) advance() {
	rec, err := readRecord(c.r)
	if err != nil {
		c.ok = false
		if err != io.EOF {
			c.err = err
		}
		return
	}
	c.cur, c.ok = rec, true
}

// mergeSSTables streams a k-way merge of inputs (any keys appearing in
// several resolve to the highest-seq input, i.e. the most recent write)
// into a new table at outPath. When dropTombstones is true — only safe
// when inputs include the oldest table on disk, so nothing older remains
// for a tombstone/expired entry to shadow — deleted and expired entries
// are omitted; otherwise they are carried through unchanged. Returns the
// merged table (not yet attached) and its record count; the table is nil
// when nothing survived.
func mergeSSTables(inputs []*sstable, outPath string, dropTombstones bool) (*sstable, int64, error) {
	total := 0
	curs := make([]*sstCursor, len(inputs))
	for i, st := range inputs {
		total += len(st.keys)
		curs[i] = newSSTCursor(st)
	}
	sw, err := newSSTWriter(outPath, total)
	if err != nil {
		return nil, 0, err
	}
	var n int64
	for {
		var min string
		have := false
		for _, c := range curs {
			if c.err != nil {
				sw.abort()
				return nil, 0, c.err
			}
			if c.ok {
				if k := string(c.cur.Key); !have || k < min {
					min, have = k, true
				}
			}
		}
		if !have {
			break
		}
		var best *sstCursor
		for _, c := range curs {
			if c.ok && string(c.cur.Key) == min {
				if best == nil || c.st.seq > best.st.seq {
					best = c
				}
			}
		}
		rec := best.cur
		for _, c := range curs {
			if c.ok && string(c.cur.Key) == min {
				c.advance()
			}
		}
		if dropTombstones && (rec.Kind == recDelete || isExpired(rec.ExpiresAt)) {
			continue
		}
		if err := sw.add(min, rec.Value, rec.Kind, rec.ExpiresAt); err != nil {
			sw.abort()
			return nil, 0, err
		}
		n++
	}
	if n == 0 {
		sw.abort()
		os.Remove(outPath)
		return nil, 0, nil
	}
	st, err := sw.finish()
	if err != nil {
		return nil, 0, err
	}
	return st, n, nil
}

// sstableFileName returns the canonical filename for sequence seq. The
// zero-padded decimal encoding keeps a plain lexicographic directory
// listing in sequence order too, which is convenient for debugging even
// though loadSSTables sorts numerically regardless.
func sstableFileName(dir string, seq int64) string {
	return filepath.Join(dir, fmt.Sprintf("sstable-%020d.sst", seq))
}

// parseSSTableSeq extracts the sequence number from a filename produced by
// sstableFileName, or ok=false if base doesn't match that pattern (e.g. a
// leftover ".tmp" file from an interrupted flush/compaction, which
// loadSSTables must never pick up as a real table).
func parseSSTableSeq(base string) (seq int64, ok bool) {
	const prefix, ext = "sstable-", ".sst"
	if !strings.HasPrefix(base, prefix) || !strings.HasSuffix(base, ext) {
		return 0, false
	}
	digits := base[len(prefix) : len(base)-len(ext)]
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
