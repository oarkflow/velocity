package velocity

import (
	"encoding/json"
	"hash/crc32"
	"sort"
	"sync"
	"time"
)

// BatchWriter for high-throughput writes with minimal memory allocation
type BatchWriter struct {
	db      *DB
	entries []Entry // Value type instead of pointer to reduce GC pressure
	mutex   sync.Mutex
	maxSize int
	crcBuf  []byte // Reusable buffer for checksum computation
}

func (db *DB) NewBatchWriter(maxSize int) *BatchWriter {
	return &BatchWriter{
		db:      db,
		entries: make([]Entry, 0, maxSize),
		maxSize: maxSize,
		crcBuf:  make([]byte, 0, 4096), // Reusable buffer
	}
}

func (bw *BatchWriter) Put(key, value []byte) error {
	bw.mutex.Lock()
	defer bw.mutex.Unlock()

	// Grow slice in-place, avoid pointer allocation
	bw.entries = append(bw.entries, Entry{
		Key:       append([]byte(nil), key...),
		Value:     append([]byte(nil), value...),
		Timestamp: uint64(time.Now().UnixNano()),
		Deleted:   false,
	})

	// Compute checksum using reusable buffer
	idx := len(bw.entries) - 1
	entry := &bw.entries[idx]
	bw.crcBuf = append(bw.crcBuf[:0], entry.Key...)
	bw.crcBuf = append(bw.crcBuf, entry.Value...)
	entry.checksum = crc32.ChecksumIEEE(bw.crcBuf)

	if len(bw.entries) >= bw.maxSize {
		return bw.flushUnsafe()
	}

	return nil
}

func (bw *BatchWriter) Flush() error {
	bw.mutex.Lock()
	defer bw.mutex.Unlock()
	return bw.flushUnsafe()
}

func (bw *BatchWriter) Cancel() {
	bw.mutex.Lock()
	defer bw.mutex.Unlock()
	bw.entries = bw.entries[:0]
}

func (bw *BatchWriter) Delete(key []byte) error {
	bw.mutex.Lock()
	defer bw.mutex.Unlock()

	// Grow slice in-place, avoid pointer allocation
	bw.entries = append(bw.entries, Entry{
		Key:       append([]byte(nil), key...),
		Value:     nil,
		Timestamp: uint64(time.Now().UnixNano()),
		Deleted:   true,
	})

	// Compute checksum using reusable buffer
	idx := len(bw.entries) - 1
	entry := &bw.entries[idx]
	bw.crcBuf = append(bw.crcBuf[:0], entry.Key...)
	entry.checksum = crc32.ChecksumIEEE(bw.crcBuf)

	if len(bw.entries) >= bw.maxSize {
		return bw.flushUnsafe()
	}

	return nil
}

func (bw *BatchWriter) flushUnsafe() error {
	if len(bw.entries) == 0 {
		return nil
	}

	// Convert to pointer slice for WAL (required by interface)
	ptrs := make([]*Entry, len(bw.entries))
	for i := range bw.entries {
		ptrs[i] = &bw.entries[i]
	}

	// Batch write to WAL with single sync
	if err := bw.db.wal.WriteBatch(ptrs); err != nil {
		return err
	}

	// Batch write to memtable
	for i := range bw.entries {
		if bw.entries[i].Deleted {
			bw.db.memTable.Delete(bw.entries[i].Key)
		} else {
			bw.db.memTable.Put(bw.entries[i].Key, bw.entries[i].Value)
		}
	}

	// Update search index if enabled
	if bw.db.searchIndexEnabled {
		bw.db.mutex.Lock()
		additions := make(map[string][]uint64)
		for i := range bw.entries {
			entry := &bw.entries[i]
			if isIndexKey(entry.Key) {
				continue
			}
			prefix, schema := bw.db.schemaForKeyLocked(entry.Key)
			if schema == nil {
				continue
			}
			// Get or allocate docID
			docID, exists, err := bw.db.getDocIDLocked(entry.Key)
			if err != nil {
				bw.db.mutex.Unlock()
				return err
			}
			if exists {
				if err := bw.db.removeIndexEntriesLocked(docID); err != nil {
					bw.db.mutex.Unlock()
					return err
				}
			}

			if entry.Deleted {
				// Doc was removed from indices above, skip re-adding projections
				continue
			}

			if !exists {
				docID, err = bw.db.allocateDocIDLocked(entry.Key)
				if err != nil {
					bw.db.mutex.Unlock()
					return err
				}
			}
			terms, hashes := buildIndexProjections(entry.Value, schema)
			meta := indexMeta{Prefix: prefix, Terms: terms, Hashes: hashes}
			metaBytes, err := json.Marshal(meta)
			if err != nil {
				bw.db.mutex.Unlock()
				return err
			}
			if err := bw.db.put(indexMetaKey(docID), metaBytes); err != nil {
				bw.db.mutex.Unlock()
				return err
			}
			for _, term := range terms {
				k := string(indexTermKey(prefix, term))
				additions[k] = append(additions[k], docID)
			}
			for field, hash := range hashes {
				k := string(indexHashKey(prefix, field, hash))
				additions[k] = append(additions[k], docID)
			}
		}

		for k, ids := range additions {
			if len(ids) == 0 {
				continue
			}
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			ids = uniqueSorted(ids)
			existing, _ := bw.db.getPostingListLocked([]byte(k))
			merged := mergeSortedUnique(existing, ids)
			if err := bw.db.put([]byte(k), encodePostingList(merged)); err != nil {
				bw.db.mutex.Unlock()
				return err
			}
		}

		bw.db.mutex.Unlock()
	}

	// Reset batch - reuse underlying array
	bw.entries = bw.entries[:0]

	return nil
}

func uniqueSorted(ids []uint64) []uint64 {
	if len(ids) <= 1 {
		return ids
	}
	out := ids[:1]
	for i := 1; i < len(ids); i++ {
		if ids[i] != ids[i-1] {
			out = append(out, ids[i])
		}
	}
	return out
}

func mergeSortedUnique(a, b []uint64) []uint64 {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	out := make([]uint64, 0, len(a)+len(b))
	i, j := 0, 0
	var last uint64
	for i < len(a) && j < len(b) {
		var v uint64
		if a[i] == b[j] {
			v = a[i]
			i++
			j++
		} else if a[i] < b[j] {
			v = a[i]
			i++
		} else {
			v = b[j]
			j++
		}
		if len(out) == 0 || v != last {
			out = append(out, v)
			last = v
		}
	}
	for ; i < len(a); i++ {
		v := a[i]
		if len(out) == 0 || v != last {
			out = append(out, v)
			last = v
		}
	}
	for ; j < len(b); j++ {
		v := b[j]
		if len(out) == 0 || v != last {
			out = append(out, v)
			last = v
		}
	}
	return out
}
