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
	skipIndex       bool
	deferFlush      bool
}

// DisableIndexMaintenance makes this writer skip online secondary-index updates.
// Callers that use it must rebuild affected indexes after the logical bulk load.
func (bw *BatchWriter) DisableIndexMaintenance() *BatchWriter {
	bw.skipIndex = true
	return bw
}

// DisableAutoFlush keeps queued entries in memory until Flush is called.
// Transactional callers need this so rollback cannot leak earlier writes.
func (bw *BatchWriter) DisableAutoFlush() *BatchWriter {
	bw.deferFlush = true
	return bw
}

// Reserve grows batch buffers up front for callers that know they will append
// many entries before flushing, such as SQL transactions.
func (bw *BatchWriter) Reserve(entries, indexFields int) *BatchWriter {
	if entries > cap(bw.entries) {
		next := make([]Entry, len(bw.entries), entries)
		copy(next, bw.entries)
		bw.entries = next
	}
	if entries > cap(bw.indexFieldSpans) {
		next := make([]indexFieldSpan, len(bw.indexFieldSpans), entries)
		copy(next, bw.indexFieldSpans)
		bw.indexFieldSpans = next
	}
	if indexFields > cap(bw.indexFieldPairs) {
		next := make([]IndexFieldValue, len(bw.indexFieldPairs), indexFields)
		copy(next, bw.indexFieldPairs)
		bw.indexFieldPairs = next
	}
	return bw
}

func (bw *BatchWriter) Len() int {
	if bw == nil {
		return 0
	}
	return len(bw.entries)
}

type IndexFieldValue struct {
	Name  string
	Value any
}

type indexFieldSpan struct {
	start     int
	end       int
	assumeNew bool
}

func (db *DB) NewBatchWriter(maxSize int) *BatchWriter {
	initialCap := maxSize
	if initialCap > 256 {
		initialCap = 256
	}
	if initialCap < 1 {
		initialCap = 1
	}
	return &BatchWriter{
		db:              db,
		entries:         make([]Entry, 0, initialCap),
		indexFieldPairs: make([]IndexFieldValue, 0, initialCap),
		indexFieldSpans: make([]indexFieldSpan, 0, initialCap),
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
	return bw.putWithIndexFieldPairsUnsafe(key, "", value, pairs, false)
}

func (bw *BatchWriter) putWithIndexFieldsUnsafe(key, value []byte, fields map[string]any) error {
	if fields != nil {
		return bw.PutWithIndexFieldsUnsafe(key, value, fields)
	}
	return bw.putWithIndexFieldPairsUnsafe(key, "", value, nil, false)
}

func (bw *BatchWriter) PutWithIndexFieldPairsUnsafe(key, value []byte, fields []IndexFieldValue) error {
	return bw.putWithIndexFieldPairsUnsafe(key, "", value, fields, false)
}

// PutNewWithIndexFieldPairsUnsafe appends a row known to be a new primary
// record. It lets Flush skip the per-row existing docID lookup.
func (bw *BatchWriter) PutNewWithIndexFieldPairsUnsafe(key, value []byte, fields []IndexFieldValue) error {
	return bw.putWithIndexFieldPairsUnsafe(key, "", value, fields, true)
}

func (bw *BatchWriter) PutNewWithIndexFieldPairsKeyStringUnsafe(key []byte, keyString string, value []byte, fields []IndexFieldValue) error {
	return bw.putWithIndexFieldPairsUnsafe(key, keyString, value, fields, true)
}

func (bw *BatchWriter) PutNewOwnedWithIndexFieldPairsKeyStringUnsafe(key []byte, keyString string, value []byte, fields []IndexFieldValue) error {
	return bw.putOwnedWithIndexFieldPairsUnsafe(key, keyString, value, fields, true)
}

func (bw *BatchWriter) putWithIndexFieldPairsUnsafe(key []byte, keyString string, value []byte, fields []IndexFieldValue, assumeNew bool) error {
	buf := make([]byte, len(key)+len(value))
	keyCopy := buf[:len(key)]
	valueCopy := buf[len(key):]
	copy(keyCopy, key)
	copy(valueCopy, value)
	// Grow slice in-place, avoid pointer allocation
	bw.entries = append(bw.entries, Entry{
		Key:       keyCopy,
		KeyString: keyString,
		Value:     valueCopy,
		Timestamp: uint64(time.Now().UnixNano()),
		Deleted:   false,
	})
	return bw.finishPutWithIndexFieldPairsUnsafe(fields, assumeNew)
}

func (bw *BatchWriter) putOwnedWithIndexFieldPairsUnsafe(key []byte, keyString string, value []byte, fields []IndexFieldValue, assumeNew bool) error {
	bw.entries = append(bw.entries, Entry{
		Key:       key,
		KeyString: keyString,
		Value:     value,
		Timestamp: uint64(time.Now().UnixNano()),
		Deleted:   false,
	})
	return bw.finishPutWithIndexFieldPairsUnsafe(fields, assumeNew)
}

func (bw *BatchWriter) finishPutWithIndexFieldPairsUnsafe(fields []IndexFieldValue, assumeNew bool) error {
	start := len(bw.indexFieldPairs)
	bw.indexFieldPairs = append(bw.indexFieldPairs, fields...)
	bw.indexFieldSpans = append(bw.indexFieldSpans, indexFieldSpan{start: start, end: len(bw.indexFieldPairs), assumeNew: assumeNew})

	idx := len(bw.entries) - 1
	entry := &bw.entries[idx]
	entry.checksum = crc32.Update(crc32.ChecksumIEEE(entry.Key), crc32.IEEETable, entry.Value)

	if !bw.deferFlush && len(bw.entries) >= bw.maxSize {
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

	if !bw.deferFlush && len(bw.entries) >= bw.maxSize {
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
	if bw.db.searchIndexEnabled && !bw.skipIndex {
		bw.db.mutex.Lock()
		additions := make(map[string][]uint64)
		valueIndexFieldKeys := make(map[valueIndexFieldKey]string, 4)
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
			assumeNew := i < len(bw.indexFieldSpans) && bw.indexFieldSpans[i].assumeNew
			docID, exists, err := uint64(0), false, error(nil)
			if !assumeNew {
				// Get or allocate docID
				docID, exists, err = bw.db.getDocIDLocked(entry.Key)
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
				if assumeNew {
					err = bw.db.bindDocIDLockedOwnedString(entry.Key, entry.KeyString, docID)
				} else {
					err = bw.db.bindDocIDLocked(entry.Key, docID)
				}
				if err != nil {
					bw.db.mutex.Unlock()
					return err
				}
			}
			if bw.db.canUseFastVolatileValueIndexLocked(schema) {
				if i < len(bw.indexFieldSpans) {
					span := bw.indexFieldSpans[i]
					if span.end > span.start {
						bw.db.addFastVolatileValuePostingsLocked(prefix, schema, bw.indexFieldPairs[span.start:span.end], docID, valueIndexFieldKeys)
						continue
					}
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

	if !bw.db.skipCloseFlush && bw.db.memTable.Size() > bw.db.memTableSize {
		if !bw.db.flushing.Load() {
			go bw.db.flushMemTable()
		}
	}

	bw.db.publishEntries(bw.entries)

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
