package lsm

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
// write. level is bookkeeping only (0 = flushed straight from the
// memtable, 1 = produced by compaction) — see engine.go's compactLocked
// for why this engine's compaction is really "merge everything on disk
// into one table" rather than v1's multi-level leveled compaction.
type sstable struct {
	path  string
	seq   int64
	level int
	index map[string]sstIndexEntry
	bloom *bloomFilter
}

func recordEncodedLen(r record) int64 {
	return int64(1+4+4+8+len(r.Key)+len(r.Value)) + 4 // header + key + value + trailing crc32
}

// buildSSTable writes entries (already sorted ascending by key) to path,
// fsyncs, and closes. The caller is responsible for writing to a .tmp path
// and atomically renaming into place — buildSSTable itself does not know
// or care about that convention, it just writes a complete, valid SSTable
// to the given path.
func buildSSTable(path string, entries []flushEntry) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)

	type idxRec struct {
		key       string
		offset    int64
		kind      recKind
		expiresAt int64
	}
	idxRecs := make([]idxRec, 0, len(entries))
	bf := newBloomFilter(len(entries), 0.01)

	var offset int64
	for _, e := range entries {
		r := record{Kind: e.kind, Key: []byte(e.key), Value: e.value, ExpiresAt: e.expiresAt}
		if err := writeRecord(w, r); err != nil {
			f.Close()
			return err
		}
		idxRecs = append(idxRecs, idxRec{key: e.key, offset: offset, kind: e.kind, expiresAt: e.expiresAt})
		bf.add([]byte(e.key))
		offset += recordEncodedLen(r)
	}

	indexStart := offset
	for _, ir := range idxRecs {
		kbuf := []byte(ir.key)
		hdr := make([]byte, 4+8+1+8)
		binary.BigEndian.PutUint32(hdr[0:4], uint32(len(kbuf)))
		binary.BigEndian.PutUint64(hdr[4:12], uint64(ir.offset))
		hdr[12] = byte(ir.kind)
		binary.BigEndian.PutUint64(hdr[13:21], uint64(ir.expiresAt))
		if _, err := w.Write(hdr); err != nil {
			f.Close()
			return err
		}
		if _, err := w.Write(kbuf); err != nil {
			f.Close()
			return err
		}
		offset += int64(len(hdr) + len(kbuf))
	}

	bloomStart := offset
	bloomBytes := bf.encode()
	if _, err := w.Write(bloomBytes); err != nil {
		f.Close()
		return err
	}
	offset += int64(len(bloomBytes))

	footer := make([]byte, 32)
	binary.BigEndian.PutUint64(footer[0:8], uint64(indexStart))
	binary.BigEndian.PutUint64(footer[8:16], uint64(bloomStart))
	binary.BigEndian.PutUint64(footer[16:24], uint64(len(idxRecs)))
	binary.BigEndian.PutUint64(footer[24:32], sstableMagic)
	if _, err := w.Write(footer); err != nil {
		f.Close()
		return err
	}

	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
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
	defer f.Close()

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
	}

	return &sstable{path: path, seq: seq, level: level, index: index, bloom: bf}, nil
}

func (s *sstable) readValueAt(offset int64) ([]byte, error) {
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	r, err := readRecord(bufio.NewReader(f))
	if err != nil {
		return nil, err
	}
	return r.Value, nil
}

// get looks up key, consulting the Bloom filter first. bloomSkipped is
// true when the Bloom filter alone was enough to prove key is absent
// (used by the engine to count avoided disk reads).
func (s *sstable) get(key string) (value []byte, kind recKind, expiresAt int64, found bool, bloomSkipped bool, err error) {
	if s.bloom != nil && !s.bloom.mayContain([]byte(key)) {
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

// mergeSSTables k-way merges every key across inputs (picking, per key,
// the entry from whichever input has the highest seq — i.e. the most
// recent write), drops tombstones and expired entries (safe because this
// merges the FULL set of currently-known tables — there is never an
// older, unmerged table left behind that a tombstone would still need to
// shadow), and writes the result to outPath. Returns the number of live
// records written.
func mergeSSTables(inputs []*sstable, outPath string) (int64, error) {
	type candidate struct {
		ie  sstIndexEntry
		src *sstable
	}
	merged := make(map[string]candidate)
	for _, st := range inputs {
		for k, ie := range st.index {
			cur, exists := merged[k]
			if !exists || st.seq > cur.src.seq {
				merged[k] = candidate{ie: ie, src: st}
			}
		}
	}

	keys := make([]string, 0, len(merged))
	for k, c := range merged {
		if c.ie.kind == recDelete || isExpired(c.ie.expiresAt) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	entries := make([]flushEntry, 0, len(keys))
	for _, k := range keys {
		c := merged[k]
		v, err := c.src.readValueAt(c.ie.offset)
		if err != nil {
			return 0, err
		}
		entries = append(entries, flushEntry{key: k, value: v, kind: recPut, expiresAt: c.ie.expiresAt})
	}
	if err := buildSSTable(outPath, entries); err != nil {
		return 0, err
	}
	return int64(len(entries)), nil
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
