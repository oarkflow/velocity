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
}

// SearchSchema defines indexing rules for a record.
type SearchSchema struct {
    Fields []SearchSchemaField
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
    BatchSize int
    NoWAL     bool // skip WAL writes for index entries during rebuild
}

type indexMeta struct {
    Prefix string            `json:"prefix"`
    Terms  []string          `json:"terms"`
    Hashes map[string]string `json:"hashes"`
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
    if opts != nil && opts.BatchSize > 0 {
        batchSize = opts.BatchSize
    }

    // Clear existing postings for this prefix
    if err := db.clearIndexForPrefix(prefix, &RebuildOptions{BatchSize: batchSize, NoWAL: noWAL}); err != nil {
        return err
    }

    // Collect all key-value pairs in a single pass to avoid repeated locking
    type kvPair struct {
        key   []byte
        value []byte
    }
    var pairs []kvPair

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
        return true
    })

    // Scan SSTables (collect keys not already in memtable)
    seen := make(map[string]bool, len(pairs))
    for _, p := range pairs {
        seen[string(p.key)] = true
    }

    for _, level := range db.levels {
        for _, sst := range level {
            idxPos := uint32(0)
            for i := 0; i < sst.entryCount; i++ {
                entry, err := sst.readIndexEntryAt(idxPos)
                if err != nil {
                    break
                }
                keyStr := string(entry.Key)
                idxEntrySize := 4 + len(entry.Key) + 8 + 4
                idxPos += uint32(idxEntrySize)

                if seen[keyStr] {
                    continue
                }
                if isIndexKey(entry.Key) {
                    continue
                }
                if prefix != "" && !prefixMatch(keyStr, prefix) {
                    continue
                }

                // Read value from SSTable
                val, err := sst.Get(entry.Key)
                if err != nil || val == nil || val.Deleted {
                    continue
                }
                if val.ExpiresAt != 0 && time.Now().UnixNano() > int64(val.ExpiresAt) {
                    continue
                }

                seen[keyStr] = true
                pairs = append(pairs, kvPair{
                    key:   append([]byte{}, entry.Key...),
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
            terms, hashes := buildIndexProjections(p.value, schema)
            batch = append(batch, indexWorkItem{key: p.key, value: p.value, terms: terms, hashes: hashes})
        }
        if err := db.applyIndexBatch(prefix, batch, &RebuildOptions{BatchSize: batchSize, NoWAL: noWAL}); err != nil {
            return err
        }
    }

    return nil
}

type indexWorkItem struct {
    key    []byte
    value  []byte
    terms  []string
    hashes map[string]string
}

func (db *DB) applyIndexBatch(prefix string, batch []indexWorkItem, opts *RebuildOptions) error {
    if len(batch) == 0 {
        return nil
    }
    additions := make(map[string][]uint64)
    noWAL := opts != nil && opts.NoWAL

    db.mutex.Lock()
    defer db.mutex.Unlock()

    for _, item := range batch {
        docID, exists, err := db.getDocIDLocked(item.key)
        if err != nil {
            return err
        }
        if !exists {
            if noWAL {
                docID, err = db.allocateDocIDLockedNoWAL(item.key)
            } else {
                docID, err = db.allocateDocIDLocked(item.key)
            }
            if err != nil {
                return err
            }
        }

        meta := indexMeta{Prefix: prefix, Terms: item.terms, Hashes: item.hashes}
        metaBytes, err := json.Marshal(meta)
        if err != nil {
            return err
        }
        if noWAL {
            if err := db.putIndexNoWALLocked(indexMetaKey(docID), metaBytes); err != nil {
                return err
            }
        } else if err := db.put(indexMetaKey(docID), metaBytes); err != nil {
            return err
        }
        for _, term := range item.terms {
            k := string(indexTermKey(prefix, term))
            additions[k] = append(additions[k], docID)
        }
        for field, hash := range item.hashes {
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
    tag := indexPrefixTag(prefix)
    terms, _ := db.Keys(indexTermPrefix + tag + ":*")
    hashes, _ := db.Keys(indexHashPrefix + tag + ":*")
    noWAL := opts != nil && opts.NoWAL
    db.mutex.Lock()
    defer db.mutex.Unlock()
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
    terms, hashes := buildIndexProjections(value, schema)
    if err := db.addIndexEntriesLocked(docID, prefix, terms, hashes); err != nil {
        return err
    }

    meta := indexMeta{Prefix: prefix, Terms: terms, Hashes: hashes}
    metaBytes, err := json.Marshal(meta)
    if err != nil {
        return err
    }
    if err := db.put(indexMetaKey(docID), metaBytes); err != nil {
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
            ids, err := db.getPostingListLocked(indexTermKey(q.Prefix, term))
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
                ids, err := db.getPostingListLocked(indexHashKey(q.Prefix, f.Field, hash))
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

func (db *DB) scanSearchLocked(q SearchQuery) ([]SearchResult, error) {
    results := make([]SearchResult, 0, min(q.Limit, 100))
    pageSize := 256
    offset := 0
    for {
        keys, total := db.KeysPage(offset, pageSize)
        if len(keys) == 0 {
            break
        }
        for _, k := range keys {
            if bytes.HasPrefix(k, []byte(indexPrefix)) {
                continue
            }
            if q.Prefix != "" && !prefixMatch(string(k), q.Prefix) {
                continue
            }
            value, err := db.get(k)
            if err != nil {
                continue
            }
            if matchesQuery(value, q) {
                results = append(results, SearchResult{Key: append([]byte{}, k...), Value: append([]byte{}, value...)})
                if len(results) >= q.Limit {
                    return results, nil
                }
            }
        }
        offset += pageSize
        if offset >= total {
            break
        }
    }
    return results, nil
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

    var doc map[string]any
    if needsJSONForFilters(q.Filters) {
        _ = json.Unmarshal(value, &doc)
    }

    for _, f := range q.Filters {
        if !evaluateFilter(doc, value, f) {
            return false
        }
    }
    return true
}

func needsJSONForFilters(filters []SearchFilter) bool {
    for _, f := range filters {
        if f.Field != "" && f.Field != "$value" {
            return true
        }
    }
    return false
}

func evaluateFilter(doc map[string]any, raw []byte, f SearchFilter) bool {
    var val any
    if f.Field == "" || f.Field == "$value" {
        val = string(raw)
    } else if doc != nil {
        val = doc[f.Field]
    }
    if val == nil {
        return false
    }

    return compareValues(val, f.Value, f.Op)
}

func compareValues(a, b any, op string) bool {
    switch op {
    case "=", "==":
        return normalizeValue(a) == normalizeValue(b)
    case "!=":
        return normalizeValue(a) != normalizeValue(b)
    case ">", ">=", "<", "<=" :
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

func buildIndexProjections(value []byte, schema *SearchSchema) ([]string, map[string]string) {
    if schema == nil || len(schema.Fields) == 0 {
        // Default: full-text on entire value
        termSet := make(map[string]struct{})
        for _, t := range tokenize(strings.ToLower(string(value))) {
            termSet[t] = struct{}{}
        }
        terms := make([]string, 0, len(termSet))
        for t := range termSet {
            terms = append(terms, t)
        }
        sort.Strings(terms)
        return terms, map[string]string{}
    }

    hashes := make(map[string]string)
    termsSet := make(map[string]struct{})

    var doc map[string]any
    needsJSON := false
    for _, field := range schema.Fields {
        if field.Name != "" && field.Name != "$value" {
            needsJSON = true
            break
        }
    }
    if needsJSON {
        _ = json.Unmarshal(value, &doc)
    }

    for _, field := range schema.Fields {
        var v any
        if field.Name == "" || field.Name == "$value" {
            v = string(value)
        } else if doc != nil {
            v = doc[field.Name]
        }
        if v == nil {
            continue
        }
        normalized := normalizeValue(v)
        if field.Searchable {
            for _, t := range tokenize(strings.ToLower(normalized)) {
                termsSet[t] = struct{}{}
            }
        }
        if field.HashSearch {
            hashes[field.Name] = hashValue(normalized)
        }
    }

    terms := make([]string, 0, len(termsSet))
    for t := range termsSet {
        terms = append(terms, t)
    }
    sort.Strings(terms)
    return terms, hashes
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
    nextID := uint64(1)
    if raw, err := db.get([]byte(indexNextIDKey)); err == nil {
        nextID = decodeUint64(raw)
        if nextID == 0 {
            nextID = 1
        }
    }

    docID := nextID
    nextID++

    if useWAL {
        if err := db.put([]byte(indexNextIDKey), encodeUint64(nextID)); err != nil {
            return 0, err
        }
        if err := db.put(indexDocIDKey(key), encodeUint64(docID)); err != nil {
            return 0, err
        }
        if err := db.put(indexDocKey(docID), key); err != nil {
            return 0, err
        }
    } else {
        if err := db.putIndexNoWALLocked([]byte(indexNextIDKey), encodeUint64(nextID)); err != nil {
            return 0, err
        }
        if err := db.putIndexNoWALLocked(indexDocIDKey(key), encodeUint64(docID)); err != nil {
            return 0, err
        }
        if err := db.putIndexNoWALLocked(indexDocKey(docID), key); err != nil {
            return 0, err
        }
    }

    return docID, nil
}

func (db *DB) getDocIDLocked(key []byte) (uint64, bool, error) {
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

func (db *DB) addIndexEntriesLocked(docID uint64, prefix string, terms []string, hashes map[string]string) error {
    for _, term := range terms {
        if err := db.addPostingLocked(indexTermKey(prefix, term), docID); err != nil {
            return err
        }
    }
    for field, hash := range hashes {
        if err := db.addPostingLocked(indexHashKey(prefix, field, hash), docID); err != nil {
            return err
        }
    }
    return nil
}

func (db *DB) removeIndexEntriesLocked(docID uint64) error {
    raw, err := db.get(indexMetaKey(docID))
    if err != nil {
        return nil
    }

    var meta indexMeta
    if err := json.Unmarshal(raw, &meta); err != nil {
        return nil
    }

    for _, term := range meta.Terms {
        if err := db.removePostingLocked(indexTermKey(meta.Prefix, term), docID); err != nil {
            return err
        }
    }
    for field, hash := range meta.Hashes {
        if err := db.removePostingLocked(indexHashKey(meta.Prefix, field, hash), docID); err != nil {
            return err
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
    return db.put(key, encodePostingList(ids))
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
    return db.put(key, encodePostingList(ids))
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
