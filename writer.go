package velocity

import (
	"bytes"
	"encoding/json"
	"hash/crc32"
	"sort"
	"sync"
	"time"
)

// BatchWriter for high-throughput writes with minimal memory allocation
type BatchWriter struct {
	db              *DB
	entries         []Entry // Value type instead of pointer to reduce GC pressure
	indexFieldPairs []IndexFieldValue
	indexFieldSpans []indexFieldSpan
	mutex           sync.Mutex
	maxSize         int
}

type IndexFieldValue struct {
	Name  string
	Value any
}

type indexFieldSpan struct {
	start int
	end   int
}

func (db *DB) NewBatchWriter(maxSize int) *BatchWriter {
	return &BatchWriter{
		db:              db,
		entries:         make([]Entry, 0, maxSize),
		indexFieldPairs: make([]IndexFieldValue, 0, maxSize),
		indexFieldSpans: make([]indexFieldSpan, 0, maxSize),
		maxSize:         maxSize,
	}
}

func (bw *BatchWriter) Put(key, value []byte) error {
	bw.mutex.Lock()
	defer bw.mutex.Unlock()
	return bw.putWithIndexFieldsUnsafe(key, value, nil)
}

// PutUnsafe appends to the batch without taking BatchWriter's mutex. It is for
// callers that already serialize access to the writer, such as a SQL transaction
// bound to one driver connection.
func (bw *BatchWriter) PutUnsafe(key, value []byte) error {
	return bw.putWithIndexFieldsUnsafe(key, value, nil)
}

func (bw *BatchWriter) PutWithIndexFieldsUnsafe(key, value []byte, fields map[string]any) error {
	pairs := make([]IndexFieldValue, 0, len(fields))
	for name, value := range fields {
		pairs = append(pairs, IndexFieldValue{Name: name, Value: value})
	}
	return bw.putWithIndexFieldPairsUnsafe(key, value, pairs)
}

func (bw *BatchWriter) putWithIndexFieldsUnsafe(key, value []byte, fields map[string]any) error {
	if fields != nil {
		return bw.PutWithIndexFieldsUnsafe(key, value, fields)
	}
	return bw.putWithIndexFieldPairsUnsafe(key, value, nil)
}

func (bw *BatchWriter) PutWithIndexFieldPairsUnsafe(key, value []byte, fields []IndexFieldValue) error {
	return bw.putWithIndexFieldPairsUnsafe(key, value, fields)
}

func (bw *BatchWriter) putWithIndexFieldPairsUnsafe(key, value []byte, fields []IndexFieldValue) error {
	// Grow slice in-place, avoid pointer allocation
	bw.entries = append(bw.entries, Entry{
		Key:       append([]byte(nil), key...),
		Value:     append([]byte(nil), value...),
		Timestamp: uint64(time.Now().UnixNano()),
		Deleted:   false,
	})
	start := len(bw.indexFieldPairs)
	bw.indexFieldPairs = append(bw.indexFieldPairs, fields...)
	bw.indexFieldSpans = append(bw.indexFieldSpans, indexFieldSpan{start: start, end: len(bw.indexFieldPairs)})

	idx := len(bw.entries) - 1
	entry := &bw.entries[idx]
	entry.checksum = crc32.Update(crc32.ChecksumIEEE(entry.Key), crc32.IEEETable, entry.Value)

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
	bw.indexFieldPairs = bw.indexFieldPairs[:0]
	bw.indexFieldSpans = bw.indexFieldSpans[:0]
}

func (bw *BatchWriter) Delete(key []byte) error {
	bw.mutex.Lock()
	defer bw.mutex.Unlock()
	return bw.deleteUnsafe(key)
}

// DeleteUnsafe appends a delete marker without taking BatchWriter's mutex.
func (bw *BatchWriter) DeleteUnsafe(key []byte) error {
	return bw.deleteUnsafe(key)
}

// PendingGet returns the latest queued value for key without flushing the
// batch. It is intended for serialized transaction owners.
func (bw *BatchWriter) PendingGet(key []byte) ([]byte, bool, bool) {
	for i := len(bw.entries) - 1; i >= 0; i-- {
		entry := &bw.entries[i]
		if !bytes.Equal(entry.Key, key) {
			continue
		}
		if entry.Deleted {
			return nil, true, true
		}
		return append([]byte(nil), entry.Value...), true, false
	}
	return nil, false, false
}

// PendingEntriesWithPrefix returns the latest queued mutation for each key
// matching prefix. Returned entries own their key/value buffers.
func (bw *BatchWriter) PendingEntriesWithPrefix(prefix []byte) []Entry {
	seen := make(map[string]struct{})
	entries := make([]Entry, 0)
	for i := len(bw.entries) - 1; i >= 0; i-- {
		entry := &bw.entries[i]
		if !bytes.HasPrefix(entry.Key, prefix) {
			continue
		}
		key := string(entry.Key)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		entries = append(entries, Entry{
			Key:       append([]byte(nil), entry.Key...),
			Value:     append([]byte(nil), entry.Value...),
			Timestamp: entry.Timestamp,
			ExpiresAt: entry.ExpiresAt,
			Deleted:   entry.Deleted,
			checksum:  entry.checksum,
		})
	}
	return entries
}

func (bw *BatchWriter) deleteUnsafe(key []byte) error {
	// Grow slice in-place, avoid pointer allocation
	bw.entries = append(bw.entries, Entry{
		Key:       append([]byte(nil), key...),
		Value:     nil,
		Timestamp: uint64(time.Now().UnixNano()),
		Deleted:   true,
	})
	bw.indexFieldSpans = append(bw.indexFieldSpans, indexFieldSpan{start: len(bw.indexFieldPairs), end: len(bw.indexFieldPairs)})

	idx := len(bw.entries) - 1
	entry := &bw.entries[idx]
	entry.checksum = crc32.ChecksumIEEE(entry.Key)

	if len(bw.entries) >= bw.maxSize {
		return bw.flushUnsafe()
	}

	return nil
}

func (bw *BatchWriter) flushUnsafe() error {
	if len(bw.entries) == 0 {
		return nil
	}

	// Batch write to WAL with single sync (skip if WAL disabled)
	if bw.db.wal != nil {
		// Convert to pointer slice for WAL (required by interface)
		ptrs := make([]*Entry, len(bw.entries))
		for i := range bw.entries {
			ptrs[i] = &bw.entries[i]
		}
		if err := bw.db.wal.WriteBatch(ptrs); err != nil {
			return err
		}
	}

	// Batch write to memtable
	bw.db.memTable.PutEntriesOwned(bw.entries)

	// Update search index if enabled
	if bw.db.searchIndexEnabled {
		bw.db.mutex.Lock()
		additions := make(map[string][]uint64)
		nextDocID, nextDocIDLoaded := uint64(0), false
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
				if !nextDocIDLoaded {
					nextDocID, err = bw.db.nextDocIDLocked()
					if err != nil {
						bw.db.mutex.Unlock()
						return err
					}
					nextDocIDLoaded = true
				}
				docID = nextDocID
				nextDocID++
				if err := bw.db.bindDocIDLocked(entry.Key, docID); err != nil {
					bw.db.mutex.Unlock()
					return err
				}
			}
			var terms []string
			var hashes, values map[string]string
			if i < len(bw.indexFieldSpans) {
				span := bw.indexFieldSpans[i]
				if span.end > span.start {
					terms, hashes, values = buildIndexProjectionsFromFieldPairs(bw.indexFieldPairs[span.start:span.end], schema)
				} else {
					terms, hashes, values = buildIndexProjections(entry.Value, schema)
				}
			} else {
				terms, hashes, values = buildIndexProjections(entry.Value, schema)
			}
			meta := indexMeta{Prefix: prefix, Terms: terms, Hashes: hashes, Values: values}
			var metaBytes []byte
			if !bw.db.disableIndexPersistence {
				var err error
				metaBytes, err = json.Marshal(meta)
				if err != nil {
					bw.db.mutex.Unlock()
					return err
				}
			}
			if err := bw.db.storeIndexMetaLocked(docID, meta, metaBytes); err != nil {
				bw.db.mutex.Unlock()
				return err
			}
			for _, term := range terms {
				k := string(indexTermKey(prefix, term))
				additions[k] = append(additions[k], docID)
			}
			for field, hash := range hashes {
				bw.db.rememberHashIndexPostingLocked(prefix, field, hash, docID)
				if !bw.db.disableIndexPersistence {
					k := string(indexHashKey(prefix, field, hash))
					additions[k] = append(additions[k], docID)
				}
			}
			if bw.db.canUsePlainValueIndexLocked() {
				for field, value := range valuePostingsForSchema(values, schema) {
					bw.db.rememberValueIndexPostingLocked(prefix, field, value, docID)
					if !bw.db.disableIndexPersistence {
						k := string(indexValueKey(prefix, field, value))
						additions[k] = append(additions[k], docID)
					}
				}
			}
		}

		if nextDocIDLoaded {
			if err := bw.db.storeNextDocIDLocked(nextDocID); err != nil {
				bw.db.mutex.Unlock()
				return err
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
			if err := bw.db.putIndexLocked([]byte(k), encodePostingList(merged)); err != nil {
				bw.db.mutex.Unlock()
				return err
			}
		}

		bw.db.mutex.Unlock()
	}

	// Reset batch - reuse underlying array
	bw.entries = bw.entries[:0]
	bw.indexFieldPairs = bw.indexFieldPairs[:0]
	bw.indexFieldSpans = bw.indexFieldSpans[:0]

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
