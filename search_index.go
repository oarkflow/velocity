package velocity

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	indexPrefix         = "__idx:"
	indexNextIDKey      = "__idx:nextid"
	indexDocIDKeyPrefix = "__idx:docid:"
	indexDocKeyPrefix   = "__idx:doc:"
	indexMetaPrefix     = "__idx:meta:"
	indexTermPrefix     = "__idx:term:"
	indexHashPrefix     = "__idx:hash:"
	indexValuePrefix    = "__idx:value:"
)

func isIndexKey(key []byte) bool {
	return bytes.HasPrefix(key, []byte(indexPrefix))
}

// SearchSchemaField describes how a field should be indexed.
// Name refers to a top-level JSON field. Use "$value" to index the full value for plain text.
type SearchSchemaField struct {
	Name       string
	Searchable bool // full-text search
	HashSearch bool // equality-only hash search
	ValueIndex bool // structured value posting index for range/equality filters
}

// SearchSchema defines indexing rules for a record.
type SearchSchema struct {
	Fields []SearchSchemaField
}

func isHighCardinalityIdentifierField(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return name == "id" || strings.HasSuffix(name, "_id")
}

// SearchFilter defines a filter for search queries.
// Op supports: "=", "==", "!=", ">", ">=", "<", "<=".
// If HashOnly is true, equality uses the hash index when available.
type SearchFilter struct {
	Field    string
	Op       string
	Value    any
	HashOnly bool
}

// SearchQuery defines a hybrid full-text + structured query.
type SearchQuery struct {
	Prefix   string
	FullText string
	Filters  []SearchFilter
	Limit    int
}

// SearchResult contains key/value pairs returned by Search().
type SearchResult struct {
	Key   []byte
	Value []byte
}

// RebuildOptions controls bulk index rebuild.
type RebuildOptions struct {
	BatchSize           int
	NoWAL               bool // skip WAL writes for index entries during rebuild
	SkipHighCardinality bool // avoid rebuilding identifier-like secondary postings
	InMemoryOnly        bool // rebuild query indexes in memory without persisting rebuildable postings
}

type indexMeta struct {
	Prefix string            `json:"prefix"`
	Terms  []string          `json:"terms"`
	Hashes map[string]string `json:"hashes"`
	Values map[string]string `json:"values,omitempty"`
}

// PutIndexed stores a value and updates the hybrid index based on schema.
// Prefer Put() with a configured SearchSchema for automatic indexing.
func (db *DB) PutIndexed(key, value []byte, schema *SearchSchema) error {
	if isIndexKey(key) {
		return fmt.Errorf("reserved index key prefix")
	}

	db.mutex.Lock()
	defer db.mutex.Unlock()
	return db.putIndexedLocked(key, value, schema)
}

func (db *DB) PutWithIndexFieldPairs(key, value []byte, fields []IndexFieldValue) error {
	if isIndexKey(key) {
		return fmt.Errorf("reserved index key prefix")
	}

	db.mutex.Lock()
	defer db.mutex.Unlock()

	prefix, schema := db.schemaForKeyLocked(key)
	if schema == nil {
		return db.put(key, value)
	}
	if err := db.put(key, value); err != nil {
		return err
	}
	return db.indexEntryWithProjectionsLocked(key, value, prefix, schema, func() ([]string, map[string]string, map[string]string) {
		return buildIndexProjectionsFromFieldPairs(fields, schema)
	})
}

// SetSearchSchema updates the default schema used by Put().
func (db *DB) SetSearchSchema(schema *SearchSchema) {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	db.searchSchema = schema
	if schema != nil {
		db.searchIndexEnabled = true
	}
}

// SetSearchSchemaForPrefix assigns a schema for a key prefix (e.g. "users").
func (db *DB) SetSearchSchemaForPrefix(prefix string, schema *SearchSchema) {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	if db.searchSchemas == nil {
		db.searchSchemas = make(map[string]*SearchSchema)
	}
	if schema == nil {
		delete(db.searchSchemas, prefix)
	} else {
		db.searchSchemas[prefix] = schema
		db.searchIndexEnabled = true
	}
}

// EnableSearchIndex toggles automatic index maintenance on Put/Delete.
func (db *DB) EnableSearchIndex(enabled bool) {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	db.searchIndexEnabled = enabled
}

// RebuildIndex rebuilds index postings for a prefix using bulk batching.
// This is the fastest way to index large datasets. Consider disabling
// online indexing before ingestion and calling this once.
// NoWAL is always true (index entries skip WAL for speed since they're rebuildable).
func (db *DB) RebuildIndex(prefix string, schema *SearchSchema, opts *RebuildOptions) error {
	if schema == nil {
		db.mutex.RLock()
		schema = db.schemaForPrefixLocked(prefix)
		db.mutex.RUnlock()
	}
	if schema == nil {
		return fmt.Errorf("search schema not found for prefix: %s", prefix)
	}

	batchSize := 2000
	noWAL := true // Always skip WAL for index rebuild - index is rebuildable
	skipHighCardinality := false
	if opts != nil && opts.BatchSize > 0 {
		batchSize = opts.BatchSize
	}
	if opts != nil && opts.SkipHighCardinality {
		skipHighCardinality = true
	}
	inMemoryOnly := opts != nil && opts.InMemoryOnly

	// Clear existing postings for this prefix
	if err := db.clearIndexForPrefix(prefix, &RebuildOptions{BatchSize: batchSize, NoWAL: noWAL, SkipHighCardinality: skipHighCardinality, InMemoryOnly: inMemoryOnly}); err != nil {
		return err
	}

	// Collect all key-value pairs in a single pass to avoid repeated locking
	type kvPair struct {
		key   []byte
		value []byte
	}
	var pairs []kvPair
	seen := make(map[string]bool)

	db.mutex.RLock()
	// Scan memtable
	db.memTable.entries.Range(func(k, v any) bool {
		e := v.(*Entry)
		if e.Deleted {
			return true
		}
		if isIndexKey(e.Key) {
			return true
		}
		if prefix != "" && !prefixMatch(string(e.Key), prefix) {
			return true
		}
		if e.ExpiresAt != 0 && time.Now().UnixNano() > int64(e.ExpiresAt) {
			return true
		}
		pairs = append(pairs, kvPair{
			key:   append([]byte{}, e.Key...),
			value: append([]byte{}, e.Value...),
		})
		seen[string(e.Key)] = true
		return true
	})
	for i := len(db.flushingMemTables) - 1; i >= 0; i-- {
		db.flushingMemTables[i].entries.Range(func(k, v any) bool {
			e := v.(*Entry)
			if e.Deleted || isIndexKey(e.Key) {
				return true
			}
			if prefix != "" && !prefixMatch(string(e.Key), prefix) {
				return true
			}
			if e.ExpiresAt != 0 && time.Now().UnixNano() > int64(e.ExpiresAt) {
				return true
			}
			keyStr := string(e.Key)
			if seen[keyStr] {
				return true
			}
			seen[keyStr] = true
			pairs = append(pairs, kvPair{
				key:   append([]byte{}, e.Key...),
				value: append([]byte{}, e.Value...),
			})
			return true
		})
	}

	// Scan SSTables (collect keys not already in newer memtables/SSTables)
	for _, level := range db.levels {
		for sstIdx := len(level) - 1; sstIdx >= 0; sstIdx-- {
			sst := level[sstIdx]
			idxPos := uint32(0)
			for i := 0; i < sst.entryCount; i++ {
				indexEntry, err := sst.readIndexEntryAt(idxPos)
				if err != nil {
					break
				}
				keyStr := string(indexEntry.Key)
				idxEntrySize := 4 + len(indexEntry.Key) + 8 + 4
				idxPos += uint32(idxEntrySize)

				if seen[keyStr] {
					continue
				}
				if isIndexKey(indexEntry.Key) {
					continue
				}
				if prefix != "" && !prefixMatch(keyStr, prefix) {
					continue
				}

				val, err := sst.readEntryAt(indexEntry.Offset, indexEntry.Size)
				if err != nil || val == nil || val.Deleted {
					continue
				}
				if val.ExpiresAt != 0 && time.Now().UnixNano() > int64(val.ExpiresAt) {
					continue
				}

				seen[keyStr] = true
				pairs = append(pairs, kvPair{
					key:   append([]byte{}, indexEntry.Key...),
					value: append([]byte{}, val.Value...),
				})
			}
		}
	}
	db.mutex.RUnlock()

	// Process in batches
	for start := 0; start < len(pairs); start += batchSize {
		end := start + batchSize
		if end > len(pairs) {
			end = len(pairs)
		}
		batch := make([]indexWorkItem, 0, end-start)
		for _, p := range pairs[start:end] {
			terms, hashes, values := buildIndexProjections(p.value, schema)
			batch = append(batch, indexWorkItem{
				key:           p.key,
				value:         p.value,
				terms:         terms,
				hashes:        hashes,
				values:        values,
				valuePostings: valuePostingsForSchema(values, schema),
			})
		}
		if err := db.applyIndexBatch(prefix, batch, &RebuildOptions{BatchSize: batchSize, NoWAL: noWAL, SkipHighCardinality: skipHighCardinality, InMemoryOnly: inMemoryOnly}); err != nil {
			return err
		}
	}

	return nil
}

// ClearIndexForPrefix removes derived search postings for prefix. Primary data
// remains untouched; queries fall back to scans until the index is rebuilt.
func (db *DB) ClearIndexForPrefix(prefix string) error {
	return db.clearIndexForPrefix(prefix, &RebuildOptions{NoWAL: true})
}

type indexWorkItem struct {
	key           []byte
	value         []byte
	terms         []string
	hashes        map[string]string
	values        map[string]string
	valuePostings map[string]string
}

func (db *DB) applyIndexBatch(prefix string, batch []indexWorkItem, opts *RebuildOptions) error {
	if len(batch) == 0 {
		return nil
	}
	additions := make(map[string][]uint64)
	noWAL := opts != nil && opts.NoWAL
	skipHighCardinality := opts != nil && opts.SkipHighCardinality
	inMemoryOnly := opts != nil && opts.InMemoryOnly
	nextDocID, nextDocIDLoaded := uint64(0), false

	db.mutex.Lock()
	defer db.mutex.Unlock()

	for _, item := range batch {
		docID, exists, err := db.getDocIDLocked(item.key)
		if err != nil {
			return err
		}
		if !exists {
			if noWAL {
				if !nextDocIDLoaded {
					nextDocID, err = db.nextDocIDLocked()
					if err != nil {
						return err
					}
					nextDocIDLoaded = true
				}
				docID = nextDocID
				nextDocID++
				if inMemoryOnly {
					db.rememberDocIDLocked(item.key, docID)
				} else {
					if err := db.bindDocIDLockedNoWAL(item.key, docID); err != nil {
						return err
					}
				}
			} else {
				docID, err = db.allocateDocIDLocked(item.key)
				if err != nil {
					return err
				}
			}
		}

		meta := indexMeta{Prefix: prefix, Terms: item.terms, Hashes: item.hashes, Values: item.values}
		var metaBytes []byte
		if !inMemoryOnly {
			var err error
			metaBytes, err = json.Marshal(meta)
			if err != nil {
				return err
			}
		}
		if inMemoryOnly {
			db.rememberIndexMetaLocked(docID, meta)
		} else {
			if err := db.storeIndexMetaLocked(docID, meta, metaBytes); err != nil {
				return err
			}
		}
		for _, term := range item.terms {
			if !inMemoryOnly {
				k := string(indexTermKey(prefix, term))
				additions[k] = append(additions[k], docID)
			}
		}
		for field, hash := range item.hashes {
			if skipHighCardinality && isHighCardinalityIdentifierField(field) {
				db.rememberHashIndexLocked(prefix, field, hash)
			} else {
				db.rememberHashIndexPostingLocked(prefix, field, hash, docID)
			}
			if !inMemoryOnly && !db.disableIndexPersistence && !(skipHighCardinality && isHighCardinalityIdentifierField(field)) {
				k := string(indexHashKey(prefix, field, hash))
				additions[k] = append(additions[k], docID)
			}
		}
		if db.canUsePlainValueIndexLocked() {
			for field, value := range item.valuePostings {
				if skipHighCardinality && isHighCardinalityIdentifierField(field) {
					db.rememberValueIndexLocked(prefix, field, value)
				} else {
					db.rememberValueIndexPostingLocked(prefix, field, value, docID)
				}
				if !inMemoryOnly && !db.disableIndexPersistence && !(skipHighCardinality && isHighCardinalityIdentifierField(field)) {
					k := string(indexValueKey(prefix, field, value))
					additions[k] = append(additions[k], docID)
				}
			}
		}
	}
	if nextDocIDLoaded && !inMemoryOnly {
		if err := db.storeNextDocIDLockedNoWAL(nextDocID); err != nil {
			return err
		}
	}

	for k, ids := range additions {
		if len(ids) == 0 {
			continue
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		ids = uniqueSorted(ids)
		existing, _ := db.getPostingListLocked([]byte(k))
		merged := mergeSortedUnique(existing, ids)
		data := encodePostingList(merged)
		if noWAL {
			if err := db.putIndexNoWALLocked([]byte(k), data); err != nil {
				return err
			}
		} else if err := db.put([]byte(k), data); err != nil {
			return err
		}
	}

	return nil
}

func (db *DB) clearIndexForPrefix(prefix string, opts *RebuildOptions) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	tag := indexPrefixTag(prefix)
	inMemoryPrefix := tag + ":"
	for k := range db.hashIndexValues {
		if strings.HasPrefix(k, inMemoryPrefix) {
			delete(db.hashIndexValues, k)
		}
	}
	for k := range db.hashIndexPostings {
		if strings.HasPrefix(k, inMemoryPrefix) {
			delete(db.hashIndexPostings, k)
		}
	}
	for k := range db.valueIndexValues {
		if strings.HasPrefix(k, inMemoryPrefix) {
			delete(db.valueIndexValues, k)
		}
	}
	for k := range db.valueIndexPostings {
		if strings.HasPrefix(k, inMemoryPrefix) {
			delete(db.valueIndexPostings, k)
		}
	}
	terms, _ := db.keysLocked(indexTermPrefix + tag + ":*")
	hashes, _ := db.keysLocked(indexHashPrefix + tag + ":*")
	values, _ := db.keysLocked(indexValuePrefix + tag + ":*")
	noWAL := opts != nil && opts.NoWAL
	for _, k := range terms {
		if noWAL {
			_ = db.deleteIndexNoWALLocked([]byte(k))
		} else {
			_ = db.deleteLocked([]byte(k))
		}
	}
	for _, k := range hashes {
		if noWAL {
			_ = db.deleteIndexNoWALLocked([]byte(k))
		} else {
			_ = db.deleteLocked([]byte(k))
		}
	}
	for _, k := range values {
		if noWAL {
			_ = db.deleteIndexNoWALLocked([]byte(k))
		} else {
			_ = db.deleteLocked([]byte(k))
		}
	}
	return nil
}

func (db *DB) schemaForKeyLocked(key []byte) (string, *SearchSchema) {
	keyStr := string(key)
	bestPrefix := ""
	var bestSchema *SearchSchema
	for prefix, schema := range db.searchSchemas {
		if schema == nil || prefix == "" {
			continue
		}
		if prefixMatch(keyStr, prefix) && len(prefix) > len(bestPrefix) {
			bestPrefix = prefix
			bestSchema = schema
		}
	}
	if bestSchema != nil {
		return bestPrefix, bestSchema
	}
	return "", db.searchSchema
}

func (db *DB) schemaForPrefixLocked(prefix string) *SearchSchema {
	if prefix == "" {
		return db.searchSchema
	}
	if db.searchSchemas != nil {
		if s, ok := db.searchSchemas[prefix]; ok {
			return s
		}
	}
	return db.searchSchema
}

func prefixMatch(key, prefix string) bool {
	if !strings.HasPrefix(key, prefix) {
		return false
	}
	if len(key) == len(prefix) {
		return true
	}
	next := key[len(prefix)]
	return next == ':' || next == '/'
}

func (db *DB) putIndexedLocked(key, value []byte, schema *SearchSchema) error {
	var prefix string
	if schema == nil {
		prefix, schema = db.schemaForKeyLocked(key)
	}
	if prefix == "" {
		prefix, _ = db.schemaForKeyLocked(key)
	}
	if schema == nil {
		return db.put(key, value)
	}
	if isIndexKey(key) {
		return fmt.Errorf("reserved index key prefix")
	}

	// Store the actual value first
	if err := db.put(key, value); err != nil {
		return err
	}

	return db.indexEntryLocked(key, value, prefix, schema)
}

// indexEntryLocked updates index structures for an existing value (no primary write).
func (db *DB) indexEntryLocked(key, value []byte, prefix string, schema *SearchSchema) error {
	if schema == nil {
		return nil
	}
	if isIndexKey(key) {
		return fmt.Errorf("reserved index key prefix")
	}
	return db.indexEntryWithProjectionsLocked(key, value, prefix, schema, func() ([]string, map[string]string, map[string]string) {
		return buildIndexProjections(value, schema)
	})
}

func (db *DB) indexEntryWithProjectionsLocked(key, value []byte, prefix string, schema *SearchSchema, projections func() ([]string, map[string]string, map[string]string)) error {
	// Get or allocate docID
	docID, exists, err := db.getDocIDLocked(key)
	if err != nil {
		return err
	}

	// Remove old index entries if this is an update
	if exists {
		if err := db.removeIndexEntriesLocked(docID); err != nil {
			return err
		}
	} else {
		docID, err = db.allocateDocIDLocked(key)
		if err != nil {
			return err
		}
	}

	// Index the new value
	terms, hashes, values := projections()
	if err := db.addIndexEntriesLocked(docID, prefix, terms, hashes, valuePostingsForSchema(values, schema)); err != nil {
		return err
	}

	meta := indexMeta{Prefix: prefix, Terms: terms, Hashes: hashes, Values: values}
	var metaBytes []byte
	if !db.disableIndexPersistence {
		metaBytes, err = json.Marshal(meta)
		if err != nil {
			return err
		}
	}
	if err := db.storeIndexMetaLocked(docID, meta, metaBytes); err != nil {
		return err
	}

	return nil
}

// DeleteIndexed removes a value and its index entries.
func (db *DB) DeleteIndexed(key []byte) error {
	if isIndexKey(key) {
		return fmt.Errorf("reserved index key prefix")
	}

	db.mutex.Lock()
	defer db.mutex.Unlock()
	return db.deleteIndexedLocked(key)
}

func (db *DB) deleteIndexedLocked(key []byte) error {
	docID, exists, err := db.getDocIDLocked(key)
	if err != nil {
		return err
	}
	if exists {
		if err := db.removeIndexEntriesLocked(docID); err != nil {
			return err
		}
		delete(db.docKeyByID, docID)
		delete(db.docIDByKey, string(key))
		delete(db.indexMetaByID, docID)
		_ = db.deleteLocked(indexDocKey(docID))
		_ = db.deleteLocked(indexDocIDKey(key))
		_ = db.deleteLocked(indexMetaKey(docID))
	}

	return db.deleteLocked(key)
}

// Search executes a hybrid full-text and structured query.
func (db *DB) Search(q SearchQuery) ([]SearchResult, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	if q.Limit <= 0 {
		q.Limit = 100
	}

	if id, ok := exactIDFilterValue(q.Filters); ok && q.Prefix != "" {
		key := []byte(q.Prefix + ":" + id)
		value, err := db.get(key)
		if err != nil {
			return nil, nil
		}
		if matchesQuery(value, q) {
			return []SearchResult{{Key: append([]byte{}, key...), Value: append([]byte{}, value...)}}, nil
		}
		return nil, nil
	}

	indexEnabled := db.searchIndexEnabled

	// Build candidate set from indexes (if possible)
	var candidates []uint64
	usedIndex := false

	if indexEnabled && strings.TrimSpace(q.FullText) != "" {
		terms := tokenize(strings.ToLower(q.FullText))
		if len(terms) == 0 {
			return nil, nil
		}
		for _, term := range terms {
			ids, err := db.getPostingListLocked(indexTermKey(q.Prefix, hashValue(term)))
			if err != nil {
				return nil, err
			}
			if ids == nil {
				return nil, nil
			}
			if candidates == nil {
				candidates = ids
			} else {
				candidates = intersectSorted(candidates, ids)
			}
			usedIndex = true
			if len(candidates) == 0 {
				return nil, nil
			}
		}
	}

	for _, f := range q.Filters {
		if f.Op == "=" || f.Op == "==" {
			if indexEnabled && f.HashOnly {
				hash := hashValue(normalizeValue(f.Value))
				ids := db.hashIndexPostingLocked(q.Prefix, f.Field, hash)
				var err error
				if ids == nil {
					ids, err = db.getPostingListLocked(indexHashKey(q.Prefix, f.Field, hash))
				}
				if err != nil {
					return nil, err
				}
				if ids == nil {
					// Hash index is not available for this field/value.
					// Fall back to scan-based evaluation instead of returning an empty result set.
					if db.hasHashIndexFieldLocked(q.Prefix, f.Field) {
						return nil, nil
					}
					continue
				}
				if candidates == nil {
					candidates = ids
				} else {
					candidates = intersectSorted(candidates, ids)
				}
				usedIndex = true
				if len(candidates) == 0 {
					return nil, nil
				}
			}
		}
	}

	if !usedIndex && indexEnabled {
		ids, ok, err := db.valueIndexCandidatesLocked(q)
		if err != nil {
			return nil, err
		}
		if ok {
			candidates = ids
			usedIndex = true
			if len(candidates) == 0 {
				return nil, nil
			}
		}
	}

	// If no usable index predicate, fall back to scanning
	results := make([]SearchResult, 0, min(q.Limit, 100))
	if !usedIndex {
		return db.scanSearchLocked(q)
	}

	// Evaluate candidates
	for _, id := range candidates {
		if len(results) >= q.Limit {
			break
		}
		meta, metaFound, metaErr := db.getIndexMetaLocked(id)
		if metaErr == nil && metaFound {
			if ok, exact := matchesQueryMeta(meta, q); exact && !ok {
				continue
			}
		}
		key, err := db.getDocKeyLocked(id)
		if err != nil || len(key) == 0 {
			continue
		}
		if q.Prefix != "" && !prefixMatch(string(key), q.Prefix) {
			continue
		}
		value, err := db.get(key)
		if err != nil {
			continue
		}
		if matchesQuery(value, q) {
			results = append(results, SearchResult{Key: append([]byte{}, key...), Value: append([]byte{}, value...)})
		}
	}

	return results, nil
}

// SearchCount executes the same query planning as Search but returns only the
// number of matching documents. It uses index metadata when possible to avoid
// decrypting primary values during encrypted/index-backed queries.
func (db *DB) SearchCount(q SearchQuery) (int, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	if q.Limit <= 0 {
		q.Limit = int(^uint(0) >> 1)
	}

	if id, ok := exactIDFilterValue(q.Filters); ok && q.Prefix != "" {
		value, err := db.get([]byte(q.Prefix + ":" + id))
		if err != nil {
			return 0, nil
		}
		if matchesQuery(value, q) {
			return 1, nil
		}
		return 0, nil
	}

	indexEnabled := db.searchIndexEnabled
	var candidates []uint64
	usedIndex := false

	if indexEnabled && strings.TrimSpace(q.FullText) != "" {
		terms := tokenize(strings.ToLower(q.FullText))
		if len(terms) == 0 {
			return 0, nil
		}
		for _, term := range terms {
			ids, err := db.getPostingListLocked(indexTermKey(q.Prefix, hashValue(term)))
			if err != nil {
				return 0, err
			}
			if ids == nil {
				return 0, nil
			}
			if candidates == nil {
				candidates = ids
			} else {
				candidates = intersectSorted(candidates, ids)
			}
			usedIndex = true
			if len(candidates) == 0 {
				return 0, nil
			}
		}
	}

	for _, f := range q.Filters {
		if (f.Op == "=" || f.Op == "==") && indexEnabled && f.HashOnly {
			hash := hashValue(normalizeValue(f.Value))
			ids := db.hashIndexPostingLocked(q.Prefix, f.Field, hash)
			var err error
			if ids == nil {
				ids, err = db.getPostingListLocked(indexHashKey(q.Prefix, f.Field, hash))
			}
			if err != nil {
				return 0, err
			}
			if ids == nil {
				if db.hasHashIndexFieldLocked(q.Prefix, f.Field) {
					return 0, nil
				}
				continue
			}
			if candidates == nil {
				candidates = ids
			} else {
				candidates = intersectSorted(candidates, ids)
			}
			usedIndex = true
			if len(candidates) == 0 {
				return 0, nil
			}
		}
	}

	if !usedIndex && indexEnabled {
		if len(q.Filters) == 1 && strings.TrimSpace(q.FullText) == "" {
			count, ok, err := db.valueIndexCountLocked(q.Prefix, q.Filters[0], q.Limit)
			if err != nil {
				return 0, err
			}
			if ok {
				return count, nil
			}
		}
		ids, ok, err := db.valueIndexCandidatesLocked(q)
		if err != nil {
			return 0, err
		}
		if ok {
			if len(q.Filters) == 1 && strings.TrimSpace(q.FullText) == "" {
				if len(ids) > q.Limit {
					return q.Limit, nil
				}
				return len(ids), nil
			}
			candidates = ids
			usedIndex = true
			if len(candidates) == 0 {
				return 0, nil
			}
		}
	}

	if !usedIndex {
		return db.scanSearchCountLocked(q)
	}

	count := 0
	for _, id := range candidates {
		if count >= q.Limit {
			break
		}
		meta, found, err := db.getIndexMetaLocked(id)
		if err == nil && found {
			if ok, exact := matchesQueryMeta(meta, q); exact {
				if ok {
					count++
				}
				continue
			}
		}

		key, err := db.getDocKeyLocked(id)
		if err != nil || len(key) == 0 {
			continue
		}
		if q.Prefix != "" && !prefixMatch(string(key), q.Prefix) {
			continue
		}
		value, err := db.get(key)
		if err != nil {
			continue
		}
		if matchesQuery(value, q) {
			count++
		}
	}

	return count, nil
}

func (db *DB) valueIndexCandidatesLocked(q SearchQuery) ([]uint64, bool, error) {
	var candidates []uint64
	used := false

	for _, f := range q.Filters {
		if f.Field == "" || f.Field == "$value" {
			continue
		}

		var ids []uint64
		var usable bool
		var err error
		switch f.Op {
		case "=", "==":
			ids = db.valueIndexPostingLocked(q.Prefix, f.Field, normalizeValue(f.Value))
			if ids == nil {
				ids, err = db.getPostingListLocked(indexValueKey(q.Prefix, f.Field, normalizeValue(f.Value)))
			}
			usable = ids != nil
			if !usable && db.hasValueIndexFieldLocked(q.Prefix, f.Field) {
				ids = []uint64{}
				usable = true
			}
		case "!=", ">", ">=", "<", "<=":
			ids, usable, err = db.rangeValueIndexCandidatesLocked(q.Prefix, f)
		default:
			continue
		}
		if err != nil {
			return nil, false, err
		}
		if !usable {
			continue
		}
		if ids == nil {
			ids = []uint64{}
		}
		if candidates == nil {
			candidates = ids
		} else {
			candidates = intersectSorted(candidates, ids)
		}
		used = true
		if len(candidates) == 0 {
			return candidates, true, nil
		}
	}

	return candidates, used, nil
}

func (db *DB) valueIndexCountLocked(prefix string, f SearchFilter, limit int) (int, bool, error) {
	if f.Field == "" || f.Field == "$value" {
		return 0, false, nil
	}
	if limit <= 0 {
		limit = int(^uint(0) >> 1)
	}

	countIDs := func(ids []uint64) (int, bool) {
		if ids == nil {
			return 0, false
		}
		if len(ids) > limit {
			return limit, true
		}
		return len(ids), true
	}

	switch f.Op {
	case "=", "==":
		value := normalizeValue(f.Value)
		if ids := db.valueIndexPostingLocked(prefix, f.Field, value); ids != nil {
			count, _ := countIDs(ids)
			return count, true, nil
		}
		ids, err := db.getPostingListLocked(indexValueKey(prefix, f.Field, value))
		if err != nil {
			return 0, false, err
		}
		count, ok := countIDs(ids)
		if !ok && db.hasValueIndexFieldLocked(prefix, f.Field) {
			return 0, true, nil
		}
		return count, ok, nil
	case "!=", ">", ">=", "<", "<=":
	default:
		return 0, false, nil
	}

	keyPrefix := string(indexValueFieldPrefix(prefix, f.Field))
	keys := db.valueIndexKeysLocked(prefix, f.Field)
	if len(keys) == 0 {
		var err error
		keys, err = db.keysLocked(keyPrefix + "*")
		if err != nil {
			return 0, false, err
		}
	}
	if len(keys) == 0 {
		return 0, false, nil
	}

	count := 0
	for _, key := range keys {
		value := strings.TrimPrefix(key, keyPrefix)
		if !compareValues(value, f.Value, f.Op) {
			continue
		}
		ids := db.valueIndexPostingLocked(prefix, f.Field, value)
		if ids == nil {
			var err error
			ids, err = db.getPostingListLocked([]byte(key))
			if err != nil {
				return 0, false, err
			}
		}
		count += len(ids)
		if count >= limit {
			return limit, true, nil
		}
	}
	return count, true, nil
}

func (db *DB) rangeValueIndexCandidatesLocked(prefix string, f SearchFilter) ([]uint64, bool, error) {
	keyPrefix := string(indexValueFieldPrefix(prefix, f.Field))
	keys := db.valueIndexKeysLocked(prefix, f.Field)
	if len(keys) == 0 {
		var err error
		keys, err = db.keysLocked(keyPrefix + "*")
		if err != nil {
			return nil, false, err
		}
	}
	if len(keys) == 0 {
		return nil, false, nil
	}

	var out []uint64
	for _, key := range keys {
		value := strings.TrimPrefix(key, keyPrefix)
		if !compareValues(value, f.Value, f.Op) {
			continue
		}
		ids := db.valueIndexPostingLocked(prefix, f.Field, value)
		if ids == nil {
			var err error
			ids, err = db.getPostingListLocked([]byte(key))
			if err != nil {
				return nil, false, err
			}
		}
		out = mergeSortedUnique(out, ids)
	}
	return out, true, nil
}

func (db *DB) scanSearchLocked(q SearchQuery) ([]SearchResult, error) {
	results := make([]SearchResult, 0, min(q.Limit, 100))

	trackSeen := db.hasOlderTablesLocked()
	var seen map[string]struct{}
	if trackSeen {
		seen = make(map[string]struct{})
	}
	now := time.Now().UnixNano()

	processEntry := func(entry *Entry, keyStr string) bool {
		if entry == nil {
			return false
		}
		key := entry.Key
		if bytes.HasPrefix(key, []byte(indexPrefix)) {
			return false
		}
		if keyStr == "" {
			keyStr = string(key)
		}
		if q.Prefix != "" && !prefixMatch(keyStr, q.Prefix) {
			return false
		}
		if trackSeen {
			if _, exists := seen[keyStr]; exists {
				return false
			}
			seen[keyStr] = struct{}{}
		}
		if entry.Deleted {
			return false
		}
		if entry.ExpiresAt != 0 && now > int64(entry.ExpiresAt) {
			return false
		}
		value := entry.Value
		if !matchesQuery(value, q) {
			return false
		}
		results = append(results, SearchResult{
			Key:   append([]byte{}, key...),
			Value: append([]byte{}, value...),
		})
		return len(results) >= q.Limit
	}

	// Scan memtable first: most recent values take precedence.
	db.memTable.entries.Range(func(k, v any) bool {
		return !processEntry(v.(*Entry), k.(string))
	})
	for i := len(db.flushingMemTables) - 1; i >= 0 && len(results) < q.Limit; i-- {
		db.flushingMemTables[i].entries.Range(func(k, v any) bool {
			return !processEntry(v.(*Entry), k.(string))
		})
	}
	if len(results) >= q.Limit {
		return results, nil
	}

	// Scan SSTables newest-to-oldest without materializing/sorting all keys.
	for _, level := range db.levels {
		for sstIdx := len(level) - 1; sstIdx >= 0; sstIdx-- {
			sst := level[sstIdx]
			idxPos := uint32(0)
			for i := 0; i < sst.entryCount; i++ {
				indexEntry, err := sst.readIndexEntryAt(idxPos)
				if err != nil {
					break
				}
				idxEntrySize := 4 + len(indexEntry.Key) + 8 + 4
				idxPos += uint32(idxEntrySize)

				keyStr := string(indexEntry.Key)
				if _, exists := seen[keyStr]; exists {
					continue
				}
				entry, err := sst.readEntryAt(indexEntry.Offset, indexEntry.Size)
				if err != nil {
					continue
				}
				if processEntry(entry, keyStr) {
					return results, nil
				}
			}
		}
	}
	return results, nil
}

func (db *DB) scanSearchCountLocked(q SearchQuery) (int, error) {
	trackSeen := db.hasOlderTablesLocked()
	var seen map[string]struct{}
	if trackSeen {
		seen = make(map[string]struct{})
	}
	now := time.Now().UnixNano()
	count := 0

	processEntry := func(entry *Entry, keyStr string) bool {
		if entry == nil {
			return false
		}
		key := entry.Key
		if bytes.HasPrefix(key, []byte(indexPrefix)) {
			return false
		}
		if keyStr == "" {
			keyStr = string(key)
		}
		if q.Prefix != "" && !prefixMatch(keyStr, q.Prefix) {
			return false
		}
		if trackSeen {
			if _, exists := seen[keyStr]; exists {
				return false
			}
			seen[keyStr] = struct{}{}
		}
		if entry.Deleted {
			return false
		}
		if entry.ExpiresAt != 0 && now > int64(entry.ExpiresAt) {
			return false
		}
		if !matchesQuery(entry.Value, q) {
			return false
		}
		count++
		return count >= q.Limit
	}

	db.memTable.entries.Range(func(k, v any) bool {
		return !processEntry(v.(*Entry), k.(string))
	})
	for i := len(db.flushingMemTables) - 1; i >= 0 && count < q.Limit; i-- {
		db.flushingMemTables[i].entries.Range(func(k, v any) bool {
			return !processEntry(v.(*Entry), k.(string))
		})
	}
	if count >= q.Limit {
		return count, nil
	}

	for _, level := range db.levels {
		for sstIdx := len(level) - 1; sstIdx >= 0; sstIdx-- {
			sst := level[sstIdx]
			idxPos := uint32(0)
			for i := 0; i < sst.entryCount; i++ {
				indexEntry, err := sst.readIndexEntryAt(idxPos)
				if err != nil {
					break
				}
				idxEntrySize := 4 + len(indexEntry.Key) + 8 + 4
				idxPos += uint32(idxEntrySize)
				keyStr := string(indexEntry.Key)
				if _, exists := seen[keyStr]; exists {
					continue
				}
				entry, err := sst.readEntryAt(indexEntry.Offset, indexEntry.Size)
				if err != nil {
					continue
				}
				if processEntry(entry, keyStr) {
					return count, nil
				}
			}
		}
	}
	return count, nil
}

func (db *DB) hasOlderTablesLocked() bool {
	if len(db.flushingMemTables) > 0 {
		return true
	}
	for _, level := range db.levels {
		if len(level) > 0 {
			return true
		}
	}
	return false
}

func matchesQuery(value []byte, q SearchQuery) bool {
	if strings.TrimSpace(q.FullText) != "" {
		terms := tokenize(strings.ToLower(q.FullText))
		if len(terms) == 0 {
			return false
		}
		valTerms := tokenize(strings.ToLower(string(value)))
		if !containsAllTerms(valTerms, terms) {
			return false
		}
	}

	if len(q.Filters) == 0 {
		return true
	}

	for _, f := range q.Filters {
		if !evaluateFilter(value, f) {
			return false
		}
	}
	return true
}

func exactIDFilterValue(filters []SearchFilter) (string, bool) {
	for _, f := range filters {
		if !strings.EqualFold(f.Field, "id") || (f.Op != "=" && f.Op != "==") {
			continue
		}
		id := normalizeValue(f.Value)
		if id == "" {
			return "", false
		}
		return id, true
	}
	return "", false
}

func evaluateFilter(raw []byte, f SearchFilter) bool {
	var val any
	if f.Field == "" || f.Field == "$value" {
		val = string(raw)
	} else {
		var ok bool
		val, ok = fastJSONScalarField(raw, f.Field)
		if !ok {
			return false
		}
	}
	if val == nil {
		return false
	}

	return compareValues(val, f.Value, f.Op)
}

func fastJSONScalarField(raw []byte, field string) (any, bool) {
	if len(raw) == 0 || field == "" {
		return nil, false
	}
	pattern := []byte(strconv.Quote(field))
	for searchFrom := 0; searchFrom < len(raw); {
		idx := bytes.Index(raw[searchFrom:], pattern)
		if idx < 0 {
			return nil, false
		}
		i := searchFrom + idx + len(pattern)
		for i < len(raw) && isJSONSpace(raw[i]) {
			i++
		}
		if i >= len(raw) || raw[i] != ':' {
			searchFrom = searchFrom + idx + 1
			continue
		}
		i++
		for i < len(raw) && isJSONSpace(raw[i]) {
			i++
		}
		if i >= len(raw) {
			return nil, false
		}
		switch raw[i] {
		case '"':
			j := i + 1
			escaped := false
			for j < len(raw) {
				if raw[j] == '\\' {
					escaped = true
					j += 2
					continue
				}
				if raw[j] == '"' {
					if !escaped {
						return string(raw[i+1 : j]), true
					}
					var s string
					if err := json.Unmarshal(raw[i:j+1], &s); err != nil {
						return nil, false
					}
					return s, true
				}
				j++
			}
			return nil, false
		case 't':
			if i+4 <= len(raw) && string(raw[i:i+4]) == "true" {
				return true, true
			}
		case 'f':
			if i+5 <= len(raw) && string(raw[i:i+5]) == "false" {
				return false, true
			}
		case 'n':
			if i+4 <= len(raw) && string(raw[i:i+4]) == "null" {
				return nil, true
			}
		default:
			j := i
			for j < len(raw) && raw[j] != ',' && raw[j] != '}' && !isJSONSpace(raw[j]) {
				j++
			}
			if j == i {
				return nil, false
			}
			if n, err := strconv.ParseFloat(string(raw[i:j]), 64); err == nil {
				return n, true
			}
			return string(raw[i:j]), true
		}
		searchFrom = searchFrom + idx + 1
	}
	return nil, false
}

func compareValues(a, b any, op string) bool {
	switch op {
	case "=", "==":
		return normalizeValue(a) == normalizeValue(b)
	case "!=":
		return normalizeValue(a) != normalizeValue(b)
	case ">", ">=", "<", "<=":
		fa, oka := toFloat(a)
		fb, okb := toFloat(b)
		if !oka || !okb {
			return false
		}
		switch op {
		case ">":
			return fa > fb
		case ">=":
			return fa >= fb
		case "<":
			return fa < fb
		case "<=":
			return fa <= fb
		}
	}
	return false
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case int32:
		return float64(t), true
	case uint64:
		return float64(t), true
	case uint32:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		if err == nil {
			return f, true
		}
		return 0, false
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		if err == nil {
			return f, true
		}
		return 0, false
	default:
		return 0, false
	}
}

func buildIndexProjections(value []byte, schema *SearchSchema) ([]string, map[string]string, map[string]string) {
	if schema == nil || len(schema.Fields) == 0 {
		// Default: full-text on entire value
		termSet := make(map[string]struct{})
		for _, t := range tokenize(strings.ToLower(string(value))) {
			termSet[hashValue(t)] = struct{}{}
		}
		terms := make([]string, 0, len(termSet))
		for t := range termSet {
			terms = append(terms, t)
		}
		sort.Strings(terms)
		return terms, map[string]string{}, map[string]string{"$value": normalizeValue(value)}
	}

	var hashes map[string]string
	var values map[string]string
	var termsSet map[string]struct{}

	var doc map[string]any
	needsJSON := false
	for _, field := range schema.Fields {
		if field.Name != "" && field.Name != "$value" {
			needsJSON = true
			break
		}
	}
	useFastScalars := needsJSON && canUseFastJSONScalars(schema)
	if needsJSON && !useFastScalars {
		_ = json.Unmarshal(value, &doc)
	}

	for _, field := range schema.Fields {
		var v any
		if field.Name == "" || field.Name == "$value" {
			v = string(value)
		} else if useFastScalars {
			scalar, ok := extractJSONScalar(value, field.Name)
			if !ok {
				continue
			}
			v = scalar
		} else if doc != nil {
			v = doc[field.Name]
		}
		if v == nil {
			continue
		}
		normalized := normalizeValue(v)
		if values == nil {
			values = make(map[string]string)
		}
		values[field.Name] = normalized
		if field.Searchable {
			if termsSet == nil {
				termsSet = make(map[string]struct{})
			}
			for _, t := range tokenize(strings.ToLower(normalized)) {
				termsSet[hashValue(t)] = struct{}{}
			}
		}
		if field.HashSearch {
			if hashes == nil {
				hashes = make(map[string]string)
			}
			hashes[field.Name] = hashValue(normalized)
		}
	}

	var terms []string
	if len(termsSet) > 0 {
		terms = make([]string, 0, len(termsSet))
		for t := range termsSet {
			terms = append(terms, t)
		}
		sort.Strings(terms)
	}
	return terms, hashes, values
}

func buildIndexProjectionsFromFields(fields map[string]any, schema *SearchSchema) ([]string, map[string]string, map[string]string) {
	pairs := make([]IndexFieldValue, 0, len(fields))
	for name, value := range fields {
		pairs = append(pairs, IndexFieldValue{Name: name, Value: value})
	}
	return buildIndexProjectionsFromFieldPairs(pairs, schema)
}

func buildIndexProjectionsFromFieldPairs(fields []IndexFieldValue, schema *SearchSchema) ([]string, map[string]string, map[string]string) {
	if schema == nil || len(schema.Fields) == 0 {
		return nil, nil, nil
	}

	var hashes map[string]string
	var values map[string]string
	var termsSet map[string]struct{}

	for _, field := range schema.Fields {
		if field.Name == "" || field.Name == "$value" {
			continue
		}
		v, ok := indexFieldPairValue(fields, field.Name)
		if !ok || v == nil {
			continue
		}
		normalized := normalizeValue(v)
		if values == nil {
			values = make(map[string]string)
		}
		values[field.Name] = normalized
		if field.Searchable {
			if termsSet == nil {
				termsSet = make(map[string]struct{})
			}
			for _, t := range tokenize(strings.ToLower(normalized)) {
				termsSet[hashValue(t)] = struct{}{}
			}
		}
		if field.HashSearch {
			if hashes == nil {
				hashes = make(map[string]string)
			}
			hashes[field.Name] = hashValue(normalized)
		}
	}

	var terms []string
	if len(termsSet) > 0 {
		terms = make([]string, 0, len(termsSet))
		for t := range termsSet {
			terms = append(terms, t)
		}
		sort.Strings(terms)
	}
	return terms, hashes, values
}

func indexFieldPairValue(fields []IndexFieldValue, name string) (any, bool) {
	for _, field := range fields {
		if field.Name == name {
			return field.Value, true
		}
	}
	return nil, false
}

func canUseFastJSONScalars(schema *SearchSchema) bool {
	for _, field := range schema.Fields {
		if field.Name == "" || field.Name == "$value" || field.Searchable {
			return false
		}
	}
	return true
}

func extractJSONScalar(raw []byte, field string) (string, bool) {
	if field == "" {
		return "", false
	}
	pattern := []byte(strconv.Quote(field))
	for searchFrom := 0; searchFrom < len(raw); {
		idx := bytes.Index(raw[searchFrom:], pattern)
		if idx < 0 {
			return "", false
		}
		i := searchFrom + idx + len(pattern)
		for i < len(raw) && isJSONSpace(raw[i]) {
			i++
		}
		if i >= len(raw) || raw[i] != ':' {
			searchFrom = searchFrom + idx + 1
			continue
		}
		i++
		for i < len(raw) && isJSONSpace(raw[i]) {
			i++
		}
		if i >= len(raw) {
			return "", false
		}
		if raw[i] == '"' {
			end := i + 1
			escaped := false
			for end < len(raw) {
				c := raw[end]
				if c == '\\' {
					escaped = true
					end += 2
					continue
				}
				if c == '"' {
					if !escaped {
						return string(raw[i+1 : end]), true
					}
					unquoted, err := strconv.Unquote(string(raw[i : end+1]))
					if err != nil {
						return "", false
					}
					return unquoted, true
				}
				end++
			}
			return "", false
		}
		end := i
		for end < len(raw) && raw[end] != ',' && raw[end] != '}' {
			end++
		}
		return strings.TrimSpace(string(raw[i:end])), true
	}
	return "", false
}

func isJSONSpace(c byte) bool {
	return c == ' ' || c == '\n' || c == '\r' || c == '\t'
}

func valuePostingsForSchema(values map[string]string, schema *SearchSchema) map[string]string {
	if len(values) == 0 || schema == nil {
		return nil
	}
	out := make(map[string]string)
	for _, field := range schema.Fields {
		if !field.ValueIndex {
			continue
		}
		value, ok := values[field.Name]
		if !ok {
			continue
		}
		out[field.Name] = value
	}
	return out
}

func (db *DB) getIndexMetaLocked(docID uint64) (indexMeta, bool, error) {
	if meta, ok := db.indexMetaByID[docID]; ok {
		return meta, true, nil
	}
	raw, err := db.get(indexMetaKey(docID))
	if err != nil {
		return indexMeta{}, false, nil
	}
	var meta indexMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return indexMeta{}, false, err
	}
	return meta, true, nil
}

func matchesQueryMeta(meta indexMeta, q SearchQuery) (bool, bool) {
	if strings.TrimSpace(q.FullText) != "" {
		if len(meta.Terms) == 0 {
			return false, false
		}
		termSet := make(map[string]struct{}, len(meta.Terms))
		for _, term := range meta.Terms {
			termSet[term] = struct{}{}
		}
		for _, term := range tokenize(strings.ToLower(q.FullText)) {
			if _, ok := termSet[hashValue(term)]; !ok {
				return false, true
			}
		}
	}

	for _, f := range q.Filters {
		if f.Field == "" || f.Field == "$value" {
			return false, false
		}
		if (f.Op == "=" || f.Op == "==") && f.HashOnly {
			hash, ok := meta.Hashes[f.Field]
			if ok {
				if hash != hashValue(normalizeValue(f.Value)) {
					return false, true
				}
				continue
			}
		}
		value, ok := meta.Values[f.Field]
		if !ok {
			return false, false
		}
		if !compareValues(value, f.Value, f.Op) {
			return false, true
		}
	}

	return true, true
}

func tokenize(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func containsAllTerms(haystack, needles []string) bool {
	if len(needles) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(haystack))
	for _, t := range haystack {
		set[t] = struct{}{}
	}
	for _, n := range needles {
		if _, ok := set[n]; !ok {
			return false
		}
	}
	return true
}

func normalizeValue(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case []byte:
		return strings.TrimSpace(string(t))
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", t))
	}
}

func hashValue(s string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(s))))
	return hex.EncodeToString(h[:])
}

func indexDocIDKey(key []byte) []byte {
	return append([]byte(indexDocIDKeyPrefix), key...)
}

func indexDocKey(docID uint64) []byte {
	return []byte(indexDocKeyPrefix + strconv.FormatUint(docID, 10))
}

func indexMetaKey(docID uint64) []byte {
	return []byte(indexMetaPrefix + strconv.FormatUint(docID, 10))
}

func indexPrefixTag(prefix string) string {
	if prefix == "" {
		return "_"
	}
	return prefix
}

func indexTermKey(prefix, term string) []byte {
	return []byte(indexTermPrefix + indexPrefixTag(prefix) + ":" + term)
}

func indexHashKey(prefix, field, hash string) []byte {
	return []byte(indexHashPrefix + indexPrefixTag(prefix) + ":" + field + ":" + hash)
}

func indexValueFieldPrefix(prefix, field string) []byte {
	return []byte(indexValuePrefix + indexPrefixTag(prefix) + ":" + field + ":")
}

func indexValueKey(prefix, field, value string) []byte {
	return append(indexValueFieldPrefix(prefix, field), value...)
}

func valueIndexValuesKey(prefix, field string) string {
	return indexPrefixTag(prefix) + ":" + field
}

func (db *DB) rememberHashIndexLocked(prefix, field, hash string) {
	if db.hashIndexValues == nil {
		db.hashIndexValues = make(map[string]map[string]struct{})
	}
	key := valueIndexValuesKey(prefix, field)
	values := db.hashIndexValues[key]
	if values == nil {
		values = make(map[string]struct{})
		db.hashIndexValues[key] = values
	}
	values[hash] = struct{}{}
}

func (db *DB) rememberHashIndexPostingLocked(prefix, field, hash string, docID uint64) {
	db.rememberHashIndexLocked(prefix, field, hash)
	if db.hashIndexPostings == nil {
		db.hashIndexPostings = make(map[string]map[string][]uint64)
	}
	key := valueIndexValuesKey(prefix, field)
	postings := db.hashIndexPostings[key]
	if postings == nil {
		postings = make(map[string][]uint64)
		db.hashIndexPostings[key] = postings
	}
	ids := postings[hash]
	idx := sort.Search(len(ids), func(i int) bool { return ids[i] >= docID })
	if idx < len(ids) && ids[idx] == docID {
		return
	}
	ids = append(ids, 0)
	copy(ids[idx+1:], ids[idx:])
	ids[idx] = docID
	postings[hash] = ids
}

func (db *DB) forgetHashIndexPostingLocked(prefix, field, hash string, docID uint64) {
	postings := db.hashIndexPostings[valueIndexValuesKey(prefix, field)]
	if len(postings) == 0 {
		return
	}
	ids := postings[hash]
	idx := sort.Search(len(ids), func(i int) bool { return ids[i] >= docID })
	if idx >= len(ids) || ids[idx] != docID {
		return
	}
	ids = append(ids[:idx], ids[idx+1:]...)
	if len(ids) == 0 {
		delete(postings, hash)
		return
	}
	postings[hash] = ids
}

func (db *DB) hashIndexPostingLocked(prefix, field, hash string) []uint64 {
	postings := db.hashIndexPostings[valueIndexValuesKey(prefix, field)]
	if len(postings) == 0 {
		return nil
	}
	ids := postings[hash]
	if len(ids) == 0 {
		return nil
	}
	return append([]uint64(nil), ids...)
}

func (db *DB) hasHashIndexFieldLocked(prefix, field string) bool {
	return len(db.hashIndexValues[valueIndexValuesKey(prefix, field)]) > 0
}

func (db *DB) canUsePlainValueIndexLocked() bool {
	return db.crypto == nil || db.crypto.noop
}

func (db *DB) rememberValueIndexLocked(prefix, field, value string) {
	if db.valueIndexValues == nil {
		db.valueIndexValues = make(map[string]map[string]struct{})
	}
	key := valueIndexValuesKey(prefix, field)
	values := db.valueIndexValues[key]
	if values == nil {
		values = make(map[string]struct{})
		db.valueIndexValues[key] = values
	}
	values[value] = struct{}{}
}

func (db *DB) rememberValueIndexPostingLocked(prefix, field, value string, docID uint64) {
	db.rememberValueIndexLocked(prefix, field, value)
	if db.valueIndexPostings == nil {
		db.valueIndexPostings = make(map[string]map[string][]uint64)
	}
	key := valueIndexValuesKey(prefix, field)
	postings := db.valueIndexPostings[key]
	if postings == nil {
		postings = make(map[string][]uint64)
		db.valueIndexPostings[key] = postings
	}
	ids := postings[value]
	idx := sort.Search(len(ids), func(i int) bool { return ids[i] >= docID })
	if idx < len(ids) && ids[idx] == docID {
		return
	}
	ids = append(ids, 0)
	copy(ids[idx+1:], ids[idx:])
	ids[idx] = docID
	postings[value] = ids
}

func (db *DB) forgetValueIndexPostingLocked(prefix, field, value string, docID uint64) {
	postings := db.valueIndexPostings[valueIndexValuesKey(prefix, field)]
	if len(postings) == 0 {
		return
	}
	ids := postings[value]
	idx := sort.Search(len(ids), func(i int) bool { return ids[i] >= docID })
	if idx >= len(ids) || ids[idx] != docID {
		return
	}
	ids = append(ids[:idx], ids[idx+1:]...)
	if len(ids) == 0 {
		delete(postings, value)
		return
	}
	postings[value] = ids
}

func (db *DB) valueIndexPostingLocked(prefix, field, value string) []uint64 {
	postings := db.valueIndexPostings[valueIndexValuesKey(prefix, field)]
	if len(postings) == 0 {
		return nil
	}
	ids := postings[value]
	if len(ids) == 0 {
		return nil
	}
	return append([]uint64(nil), ids...)
}

func (db *DB) valueIndexKeysLocked(prefix, field string) []string {
	values := db.valueIndexValues[valueIndexValuesKey(prefix, field)]
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, string(indexValueKey(prefix, field, value)))
	}
	sort.Strings(keys)
	return keys
}

func (db *DB) hasValueIndexFieldLocked(prefix, field string) bool {
	return len(db.valueIndexValues[valueIndexValuesKey(prefix, field)]) > 0
}

// putIndexNoWALLocked writes index keys to memtable without WAL.
func (db *DB) putIndexNoWALLocked(key, value []byte) error {
	e := entryPool.Get().(*Entry)
	e.Key = append(e.Key[:0], key...)
	e.Value = append(e.Value[:0], value...)
	e.Timestamp = uint64(time.Now().UnixNano())
	e.Deleted = false
	h := crc32.NewIEEE()
	h.Write(e.Key)
	h.Write(e.Value)
	e.checksum = h.Sum32()
	db.memTable.PutEntry(e)
	entryPool.Put(e)
	return nil
}

func (db *DB) putIndexLocked(key, value []byte) error {
	if db.disableIndexPersistence && isVolatileIndexKey(key) {
		return nil
	}
	if db.disableWAL {
		return db.putIndexNoWALLocked(key, value)
	}
	return db.put(key, value)
}

func isVolatileIndexKey(key []byte) bool {
	return bytes.Equal(key, []byte(indexNextIDKey)) ||
		bytes.HasPrefix(key, []byte(indexDocIDKeyPrefix)) ||
		bytes.HasPrefix(key, []byte(indexDocKeyPrefix)) ||
		bytes.HasPrefix(key, []byte(indexMetaPrefix)) ||
		bytes.HasPrefix(key, []byte(indexHashPrefix)) ||
		bytes.HasPrefix(key, []byte(indexValuePrefix))
}

func (db *DB) storeIndexMetaLocked(docID uint64, meta indexMeta, metaBytes []byte) error {
	if db.indexMetaByID == nil {
		db.indexMetaByID = make(map[uint64]indexMeta)
	}
	db.indexMetaByID[docID] = meta
	if db.disableIndexPersistence {
		return nil
	}
	return db.putIndexLocked(indexMetaKey(docID), metaBytes)
}

func (db *DB) rememberIndexMetaLocked(docID uint64, meta indexMeta) {
	if db.indexMetaByID == nil {
		db.indexMetaByID = make(map[uint64]indexMeta)
	}
	db.indexMetaByID[docID] = meta
}

// deleteIndexNoWALLocked tombstones index keys without WAL.
func (db *DB) deleteIndexNoWALLocked(key []byte) error {
	e := &Entry{
		Key:       append([]byte{}, key...),
		Value:     nil,
		Timestamp: uint64(time.Now().UnixNano()),
		Deleted:   true,
	}
	e.checksum = crc32.ChecksumIEEE(e.Key)
	db.memTable.Delete(key)
	return nil
}

func (db *DB) allocateDocIDLocked(key []byte) (uint64, error) {
	return db.allocateDocIDLockedWithWAL(key, true)
}

func (db *DB) allocateDocIDLockedNoWAL(key []byte) (uint64, error) {
	return db.allocateDocIDLockedWithWAL(key, false)
}

func (db *DB) allocateDocIDLockedWithWAL(key []byte, useWAL bool) (uint64, error) {
	nextID, err := db.nextDocIDLocked()
	if err != nil {
		return 0, err
	}

	docID := nextID
	nextID++

	if useWAL {
		if err := db.storeNextDocIDLocked(nextID); err != nil {
			return 0, err
		}
		if err := db.bindDocIDLocked(key, docID); err != nil {
			return 0, err
		}
	} else {
		if err := db.storeNextDocIDLocked(nextID); err != nil {
			return 0, err
		}
		if err := db.bindDocIDLocked(key, docID); err != nil {
			return 0, err
		}
	}

	return docID, nil
}

func (db *DB) nextDocIDLocked() (uint64, error) {
	if db.nextDocID != 0 {
		return db.nextDocID, nil
	}
	nextID := uint64(1)
	if raw, err := db.get([]byte(indexNextIDKey)); err == nil {
		nextID = decodeUint64(raw)
		if nextID == 0 {
			nextID = 1
		}
	}
	db.nextDocID = nextID
	return nextID, nil
}

func (db *DB) storeNextDocIDLocked(nextID uint64) error {
	db.nextDocID = nextID
	if db.disableIndexPersistence {
		return nil
	}
	return db.putIndexLocked([]byte(indexNextIDKey), encodeUint64(nextID))
}

func (db *DB) storeNextDocIDLockedNoWAL(nextID uint64) error {
	db.nextDocID = nextID
	if db.disableIndexPersistence {
		return nil
	}
	return db.putIndexNoWALLocked([]byte(indexNextIDKey), encodeUint64(nextID))
}

func (db *DB) bindDocIDLocked(key []byte, docID uint64) error {
	if db.docIDByKey == nil {
		db.docIDByKey = make(map[string]uint64)
	}
	if db.docKeyByID == nil {
		db.docKeyByID = make(map[uint64][]byte)
	}
	db.docIDByKey[string(key)] = docID
	db.docKeyByID[docID] = append([]byte(nil), key...)
	if db.disableIndexPersistence {
		return nil
	}
	if err := db.putIndexLocked(indexDocIDKey(key), encodeUint64(docID)); err != nil {
		return err
	}
	return db.putIndexLocked(indexDocKey(docID), key)
}

func (db *DB) rememberDocIDLocked(key []byte, docID uint64) {
	if db.docIDByKey == nil {
		db.docIDByKey = make(map[string]uint64)
	}
	if db.docKeyByID == nil {
		db.docKeyByID = make(map[uint64][]byte)
	}
	db.docIDByKey[string(key)] = docID
	db.docKeyByID[docID] = append([]byte(nil), key...)
}

func (db *DB) bindDocIDLockedNoWAL(key []byte, docID uint64) error {
	db.rememberDocIDLocked(key, docID)
	if db.disableIndexPersistence {
		return nil
	}
	if err := db.putIndexNoWALLocked(indexDocIDKey(key), encodeUint64(docID)); err != nil {
		return err
	}
	return db.putIndexNoWALLocked(indexDocKey(docID), key)
}

func (db *DB) getDocIDLocked(key []byte) (uint64, bool, error) {
	if id, ok := db.docIDByKey[string(key)]; ok && id != 0 {
		return id, true, nil
	}
	raw, err := db.get(indexDocIDKey(key))
	if err != nil {
		return 0, false, nil
	}
	id := decodeUint64(raw)
	if id == 0 {
		return 0, false, nil
	}
	return id, true, nil
}

func (db *DB) getDocKeyLocked(docID uint64) ([]byte, error) {
	if key, ok := db.docKeyByID[docID]; ok {
		return append([]byte(nil), key...), nil
	}
	raw, err := db.get(indexDocKey(docID))
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func (db *DB) getPostingListLocked(key []byte) ([]uint64, error) {
	raw, err := db.get(key)
	if err != nil {
		return nil, nil
	}
	return decodePostingList(raw), nil
}

func (db *DB) addIndexEntriesLocked(docID uint64, prefix string, terms []string, hashes map[string]string, values map[string]string) error {
	for _, term := range terms {
		if err := db.addPostingLocked(indexTermKey(prefix, term), docID); err != nil {
			return err
		}
	}
	for field, hash := range hashes {
		db.rememberHashIndexPostingLocked(prefix, field, hash, docID)
		key := indexHashKey(prefix, field, hash)
		if !db.disableIndexPersistence {
			if err := db.addPostingLocked(key, docID); err != nil {
				return err
			}
		}
	}
	if db.canUsePlainValueIndexLocked() {
		for field, value := range values {
			db.rememberValueIndexPostingLocked(prefix, field, value, docID)
			key := indexValueKey(prefix, field, value)
			if !db.disableIndexPersistence {
				if err := db.addPostingLocked(key, docID); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (db *DB) removeIndexEntriesLocked(docID uint64) error {
	meta, found, err := db.getIndexMetaLocked(docID)
	if err != nil || !found {
		return nil
	}

	for _, term := range meta.Terms {
		if err := db.removePostingLocked(indexTermKey(meta.Prefix, term), docID); err != nil {
			return err
		}
	}
	for field, hash := range meta.Hashes {
		db.forgetHashIndexPostingLocked(meta.Prefix, field, hash, docID)
		if !db.disableIndexPersistence {
			if err := db.removePostingLocked(indexHashKey(meta.Prefix, field, hash), docID); err != nil {
				return err
			}
		}
	}
	if db.canUsePlainValueIndexLocked() {
		for field, value := range meta.Values {
			db.forgetValueIndexPostingLocked(meta.Prefix, field, value, docID)
			if !db.disableIndexPersistence {
				if err := db.removePostingLocked(indexValueKey(meta.Prefix, field, value), docID); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (db *DB) addPostingLocked(key []byte, docID uint64) error {
	ids, _ := db.getPostingListLocked(key)
	if ids == nil {
		ids = []uint64{docID}
	} else {
		idx := sort.Search(len(ids), func(i int) bool { return ids[i] >= docID })
		if idx < len(ids) && ids[idx] == docID {
			return nil
		}
		ids = append(ids, 0)
		copy(ids[idx+1:], ids[idx:])
		ids[idx] = docID
	}
	return db.putIndexLocked(key, encodePostingList(ids))
}

func (db *DB) removePostingLocked(key []byte, docID uint64) error {
	ids, _ := db.getPostingListLocked(key)
	if len(ids) == 0 {
		return nil
	}
	idx := sort.Search(len(ids), func(i int) bool { return ids[i] >= docID })
	if idx >= len(ids) || ids[idx] != docID {
		return nil
	}
	ids = append(ids[:idx], ids[idx+1:]...)
	if len(ids) == 0 {
		return db.deleteLocked(key)
	}
	return db.putIndexLocked(key, encodePostingList(ids))
}

func encodePostingList(ids []uint64) []byte {
	if len(ids) == 0 {
		return nil
	}
	var buf []byte
	prev := uint64(0)
	for _, id := range ids {
		delta := id - prev
		tmp := make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(tmp, delta)
		buf = append(buf, tmp[:n]...)
		prev = id
	}
	return buf
}

func decodePostingList(b []byte) []uint64 {
	if len(b) == 0 {
		return nil
	}
	out := make([]uint64, 0, 16)
	var prev uint64
	for len(b) > 0 {
		delta, n := binary.Uvarint(b)
		if n <= 0 {
			break
		}
		id := prev + delta
		out = append(out, id)
		prev = id
		b = b[n:]
	}
	return out
}

func encodeUint64(v uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return buf[:]
}

func decodeUint64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

func intersectSorted(a, b []uint64) []uint64 {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	out := make([]uint64, 0, min(len(a), len(b)))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if a[i] == b[j] {
			out = append(out, a[i])
			i++
			j++
		} else if a[i] < b[j] {
			i++
		} else {
			j++
		}
	}
	return out
}

func (db *DB) deleteLocked(key []byte) error {
	entry := &Entry{
		Key:       append([]byte{}, key...),
		Value:     nil,
		Timestamp: uint64(time.Now().UnixNano()),
		Deleted:   true,
	}

	entry.checksum = crc32.ChecksumIEEE(entry.Key)

	if db.wal == nil {
		return fmt.Errorf("WAL is not initialized")
	}
	if err := db.wal.Write(entry); err != nil {
		return err
	}

	db.memTable.Delete(key)
	if db.cache != nil {
		db.cache.Remove(string(key))
	}
	return nil
}
