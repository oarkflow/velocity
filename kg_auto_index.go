package velocity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type KGResourceType string

const (
	KGResourceKV       KGResourceType = "kv"
	KGResourceObject   KGResourceType = "object"
	KGResourceSecret   KGResourceType = "secret"
	KGResourceSQLRow   KGResourceType = "sql_row"
	KGResourceEnvelope KGResourceType = "envelope"
	KGResourceEntity   KGResourceType = "entity"
)

type KnowledgeGraphAutoIndexConfig struct {
	Enabled       bool
	Resources     []KGResourceType
	SecretValues  bool
	Existing      bool
	Async         bool
	MaxValueBytes int64
}

type KnowledgeGraphSyncStatus struct {
	Enabled        bool                   `json:"enabled"`
	Running        bool                   `json:"running"`
	LastStartedAt  time.Time              `json:"last_started_at,omitempty"`
	LastFinishedAt time.Time              `json:"last_finished_at,omitempty"`
	LastError      string                 `json:"last_error,omitempty"`
	Indexed        map[KGResourceType]int `json:"indexed,omitempty"`
	Skipped        map[KGResourceType]int `json:"skipped,omitempty"`
}

type KGAutoIndexer struct {
	db     *DB
	cfg    KnowledgeGraphAutoIndexConfig
	mu     sync.RWMutex
	status KnowledgeGraphSyncStatus
}

const defaultKGAutoIndexMaxValueBytes int64 = 1 << 20

func (db *DB) EnableKnowledgeGraphAutoIndex(config KnowledgeGraphAutoIndexConfig) {
	config.Enabled = true
	config = normalizeKGAutoIndexConfig(config)
	db.kgAutoIndex = &KGAutoIndexer{
		db:  db,
		cfg: config,
		status: KnowledgeGraphSyncStatus{
			Enabled: true,
			Indexed: make(map[KGResourceType]int),
			Skipped: make(map[KGResourceType]int),
		},
	}
	if config.Existing {
		if config.Async {
			go func() { _ = db.SyncKnowledgeGraph(context.Background()) }()
		} else {
			_ = db.SyncKnowledgeGraph(context.Background())
		}
	}
}

func (db *DB) SyncKnowledgeGraph(ctx context.Context, opts ...KnowledgeGraphAutoIndexConfig) error {
	indexer := db.kgAutoIndex
	if indexer == nil {
		cfg := KnowledgeGraphAutoIndexConfig{Enabled: true, Existing: true, Async: false}
		if len(opts) > 0 {
			cfg = opts[0]
			cfg.Enabled = true
		}
		db.EnableKnowledgeGraphAutoIndex(cfg)
		indexer = db.kgAutoIndex
	}
	return indexer.Sync(ctx)
}

func (db *DB) KnowledgeGraphSyncStatus() KnowledgeGraphSyncStatus {
	if db.kgAutoIndex == nil {
		return KnowledgeGraphSyncStatus{Enabled: false}
	}
	return db.kgAutoIndex.Status()
}

func normalizeKGAutoIndexConfig(cfg KnowledgeGraphAutoIndexConfig) KnowledgeGraphAutoIndexConfig {
	if len(cfg.Resources) == 0 {
		cfg.Resources = []KGResourceType{KGResourceKV, KGResourceObject, KGResourceSecret, KGResourceSQLRow, KGResourceEnvelope, KGResourceEntity}
	}
	if cfg.MaxValueBytes <= 0 {
		cfg.MaxValueBytes = defaultKGAutoIndexMaxValueBytes
	}
	if !cfg.SecretValues {
		cfg.SecretValues = false
	}
	return cfg
}

func (idx *KGAutoIndexer) Status() KnowledgeGraphSyncStatus {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	out := idx.status
	out.Indexed = make(map[KGResourceType]int, len(idx.status.Indexed))
	for k, v := range idx.status.Indexed {
		out.Indexed[k] = v
	}
	out.Skipped = make(map[KGResourceType]int, len(idx.status.Skipped))
	for k, v := range idx.status.Skipped {
		out.Skipped[k] = v
	}
	return out
}

func (idx *KGAutoIndexer) Sync(ctx context.Context) error {
	if idx == nil || !idx.cfg.Enabled {
		return nil
	}
	idx.markStart()
	var err error
	for _, typ := range idx.cfg.Resources {
		if ctx.Err() != nil {
			err = ctx.Err()
			break
		}
		if e := idx.syncType(ctx, typ); e != nil && err == nil {
			err = e
		}
	}
	idx.markFinish(err)
	return err
}

func (idx *KGAutoIndexer) syncType(ctx context.Context, typ KGResourceType) error {
	switch typ {
	case KGResourceKV:
		return idx.syncKV(ctx)
	case KGResourceObject:
		return idx.syncObjects(ctx)
	case KGResourceSecret:
		return idx.syncSecrets(ctx)
	case KGResourceSQLRow:
		return idx.syncSQLRows(ctx)
	case KGResourceEnvelope:
		return idx.syncEnvelopes(ctx)
	case KGResourceEntity:
		return idx.syncEntities(ctx)
	default:
		return nil
	}
}

func (idx *KGAutoIndexer) markStart() {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.status.Enabled = true
	idx.status.Running = true
	idx.status.LastStartedAt = time.Now().UTC()
	idx.status.LastError = ""
	idx.status.Indexed = make(map[KGResourceType]int)
	idx.status.Skipped = make(map[KGResourceType]int)
}

func (idx *KGAutoIndexer) markFinish(err error) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.status.Running = false
	idx.status.LastFinishedAt = time.Now().UTC()
	if err != nil {
		idx.status.LastError = err.Error()
	}
}

func (idx *KGAutoIndexer) count(typ KGResourceType, indexed bool) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	if indexed {
		idx.status.Indexed[typ]++
	} else {
		idx.status.Skipped[typ]++
	}
}

func (idx *KGAutoIndexer) enabled(typ KGResourceType) bool {
	if idx == nil || !idx.cfg.Enabled {
		return false
	}
	for _, t := range idx.cfg.Resources {
		if t == typ {
			return true
		}
	}
	return false
}

func (db *DB) kgAutoIndexResource(ctx context.Context, typ KGResourceType, req *KGIngestRequest) {
	idx := db.kgAutoIndex
	if idx == nil || !idx.enabled(typ) || req == nil {
		return
	}
	run := func() {
		if err := idx.indexRequest(ctx, typ, req); err != nil {
			log.Printf("velocity: KG auto-index %s %s failed: %v", typ, req.Source, err)
		}
	}
	if idx.cfg.Async {
		go run()
	} else {
		run()
	}
}

func (idx *KGAutoIndexer) indexRequest(ctx context.Context, typ KGResourceType, req *KGIngestRequest) error {
	if req == nil || req.Source == "" {
		idx.count(typ, false)
		return nil
	}
	if len(req.Content) == 0 {
		req.Content = []byte(metadataText(req.Metadata))
	}
	if len(req.Content) == 0 {
		idx.count(typ, false)
		return nil
	}
	kg := idx.db.KnowledgeGraph()
	if kg == nil {
		idx.count(typ, false)
		return fmt.Errorf("knowledge graph unavailable")
	}
	_ = kg.DeleteSource(req.Source)
	_, err := kg.Ingest(ctx, req)
	if err != nil {
		idx.count(typ, false)
		return err
	}
	idx.count(typ, true)
	return nil
}

func (db *DB) kgAutoDeleteSource(source string) {
	if db.kgAutoIndex == nil || source == "" {
		return
	}
	run := func() {
		if kg := db.KnowledgeGraph(); kg != nil {
			_ = kg.DeleteSource(source)
		}
	}
	if db.kgAutoIndex.cfg.Async {
		go run()
	} else {
		run()
	}
}

func (db *DB) kgAutoIndexKV(key, value []byte) {
	if !db.kgShouldIndexKVKey(string(key)) {
		return
	}
	content, meta := db.kgContentForBytes(KGResourceKV, string(key), value, nil)
	meta["key"] = string(key)
	db.kgAutoIndexResource(context.Background(), KGResourceKV, &KGIngestRequest{
		Source:    "kv:" + string(key),
		MediaType: "text/plain",
		Title:     "KV " + string(key),
		Content:   content,
		Metadata:  meta,
	})
}

func (db *DB) kgAutoDeleteKV(key []byte) {
	if db.kgShouldIndexKVKey(string(key)) {
		db.kgAutoDeleteSource("kv:" + string(key))
	}
}

func (db *DB) kgAutoIndexObjectRecord(rec *ObjectRecord, content []byte) {
	if rec == nil {
		return
	}
	if content == nil && rec.Size > 0 && rec.Size <= db.kgAutoMaxBytes() {
		if data, _, err := db.GetObjectInternal(rec.Path, rec.CreatedBy); err == nil {
			content = data
		}
	}
	meta := map[string]string{
		"resource_type": string(KGResourceObject),
		"path":          rec.Path,
		"bucket":        rec.Bucket,
		"key":           rec.Key,
		"content_type":  rec.ContentType,
		"object_id":     rec.ObjectID,
		"version_id":    rec.VersionID,
	}
	for k, v := range rec.Tags {
		meta["tag_"+k] = v
	}
	for k, v := range rec.CustomMetadata {
		meta["meta_"+k] = v
	}
	body, extra := db.kgContentForBytes(KGResourceObject, rec.Path, content, meta)
	for k, v := range extra {
		meta[k] = v
	}
	db.kgAutoIndexResource(context.Background(), KGResourceObject, &KGIngestRequest{
		Source:    "object:" + rec.Path,
		MediaType: rec.ContentType,
		Title:     rec.Path,
		Content:   body,
		Metadata:  meta,
	})
}

func (db *DB) kgAutoDeleteObject(path string) {
	db.kgAutoDeleteSource("object:" + normalizePath(path))
}

func (db *DB) kgAutoIndexSecretValue(rec *SecretRecord, value []byte) {
	if rec == nil {
		return
	}
	meta := map[string]string{
		"resource_type": string(KGResourceSecret),
		"name":          rec.Name,
		"version":       rec.Version,
		"secret_id":     rec.SecretID,
		"owner":         rec.Owner,
	}
	for k, v := range rec.Tags {
		meta["tag_"+k] = v
	}
	content := []byte(metadataText(meta))
	if db.kgAutoIndex != nil && db.kgAutoIndex.cfg.SecretValues {
		content, meta = db.kgContentForBytes(KGResourceSecret, rec.Name, value, meta)
	}
	db.kgAutoIndexResource(context.Background(), KGResourceSecret, &KGIngestRequest{
		Source:    "secret:" + rec.Name + ":" + rec.Version,
		MediaType: "text/plain",
		Title:     "Secret " + rec.Name,
		Content:   content,
		Metadata:  meta,
	})
}

func (db *DB) kgAutoIndexSQLRow(table, key string, value []byte) {
	if table == "" || key == "" {
		return
	}
	meta := map[string]string{"resource_type": string(KGResourceSQLRow), "table": table, "row_key": key}
	content, meta := db.kgContentForBytes(KGResourceSQLRow, table+"/"+key, value, meta)
	db.kgAutoIndexResource(context.Background(), KGResourceSQLRow, &KGIngestRequest{
		Source:    "sql:" + table + ":" + key,
		MediaType: "application/json",
		Title:     "SQL " + table + " " + key,
		Content:   content,
		Metadata:  meta,
	})
}

func (db *DB) KGAutoIndexSQLRow(table string, key, value []byte) {
	if db.kgAutoIndex != nil && db.kgAutoIndex.enabled(KGResourceSQLRow) {
		db.kgAutoIndexSQLRow(table, string(key), value)
	}
}

func (db *DB) KGAutoDeleteSQLRow(table string, key []byte) {
	if db.kgAutoIndex != nil && db.kgAutoIndex.enabled(KGResourceSQLRow) {
		db.kgAutoDeleteSource("sql:" + table + ":" + string(key))
	}
}

func (db *DB) kgAutoIndexEnvelope(env *Envelope) {
	if env == nil {
		return
	}
	meta := map[string]string{
		"resource_type": string(KGResourceEnvelope),
		"envelope_id":   env.EnvelopeID,
		"type":          string(env.Type),
		"status":        env.Status,
		"created_by":    env.CreatedBy,
		"payload_kind":  env.Payload.Kind,
	}
	for k, v := range env.Tags {
		meta["tag_"+k] = v
	}
	content := envelopeKGText(env)
	db.kgAutoIndexResource(context.Background(), KGResourceEnvelope, &KGIngestRequest{
		Source:    "envelope:" + env.EnvelopeID,
		MediaType: "text/plain",
		Title:     env.Label,
		Content:   []byte(content),
		Metadata:  meta,
	})
}

func (db *DB) kgAutoIndexEntity(entity *Entity) {
	if entity == nil {
		return
	}
	if entity.CreatedBy == "kg-pipeline" {
		return
	}
	if entity.Tags != nil && entity.Tags["kg_type"] != "" {
		return
	}
	meta := map[string]string{
		"resource_type": string(KGResourceEntity),
		"entity_id":     entity.EntityID,
		"type":          entity.Type,
		"name":          entity.Name,
	}
	for k, v := range entity.Tags {
		meta["tag_"+k] = v
	}
	for k, v := range entity.Metadata {
		meta["meta_"+k] = v
	}
	content := entity.Name + "\n" + entity.Description + "\n" + string(entity.Data) + "\n" + metadataText(entity.Tags) + "\n" + metadataText(entity.Metadata)
	db.kgAutoIndexResource(context.Background(), KGResourceEntity, &KGIngestRequest{
		Source:    "entity:" + entity.EntityID,
		MediaType: "text/plain",
		Title:     entity.Name,
		Content:   []byte(content),
		Metadata:  meta,
	})
}

func (db *DB) kgAutoDeleteEntity(entityID string) {
	db.kgAutoDeleteSource("entity:" + entityID)
}

func (db *DB) kgShouldIndexKVKey(key string) bool {
	if key == "" || isIndexKey([]byte(key)) || strings.HasPrefix(key, kgPrefix) || strings.HasPrefix(key, "__kgm:") {
		return false
	}
	skipPrefixes := []string{
		"compliance:", "audit:", "obj:", "secret:", "entity:", "relation:",
		"velocity:", "sql:schema:", "schema:", "_schema:", "__idx", "__search",
	}
	for _, prefix := range skipPrefixes {
		if strings.HasPrefix(key, prefix) {
			return false
		}
	}
	return true
}

func (db *DB) kgContentForBytes(typ KGResourceType, name string, value []byte, meta map[string]string) ([]byte, map[string]string) {
	if meta == nil {
		meta = make(map[string]string)
	}
	meta["resource_type"] = string(typ)
	if int64(len(value)) > db.kgAutoMaxBytes() {
		meta["kg_content_mode"] = "metadata_only"
		meta["kg_skip_reason"] = "too_large"
		return []byte(metadataText(meta)), meta
	}
	if !looksTextual(value, meta["content_type"]) {
		meta["kg_content_mode"] = "metadata_only"
		meta["kg_skip_reason"] = "binary"
		return []byte(name + "\n" + metadataText(meta)), meta
	}
	meta["kg_content_mode"] = "content"
	return value, meta
}

func (db *DB) kgAutoMaxBytes() int64 {
	if db.kgAutoIndex == nil || db.kgAutoIndex.cfg.MaxValueBytes <= 0 {
		return defaultKGAutoIndexMaxValueBytes
	}
	return db.kgAutoIndex.cfg.MaxValueBytes
}

func looksTextual(data []byte, contentType string) bool {
	if len(data) == 0 {
		return false
	}
	if contentType != "" {
		if mediaType, _, err := mime.ParseMediaType(contentType); err == nil {
			if strings.HasPrefix(mediaType, "text/") || strings.Contains(mediaType, "json") || strings.Contains(mediaType, "xml") || strings.Contains(mediaType, "yaml") {
				return true
			}
			if strings.HasPrefix(mediaType, "image/") || strings.HasPrefix(mediaType, "audio/") || strings.HasPrefix(mediaType, "video/") || strings.HasPrefix(mediaType, "application/octet-stream") {
				return false
			}
		}
	}
	if !utf8.Valid(data) {
		return false
	}
	sample := data
	if len(sample) > 512 {
		sample = sample[:512]
	}
	detected := http.DetectContentType(sample)
	return strings.HasPrefix(detected, "text/") || strings.Contains(detected, "json") || bytes.IndexByte(sample, 0) < 0
}

func metadataText(meta map[string]string) string {
	if len(meta) == 0 {
		return ""
	}
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sortStrings(keys)
	var b strings.Builder
	for _, k := range keys {
		if meta[k] != "" {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(meta[k])
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func envelopeKGText(env *Envelope) string {
	var b strings.Builder
	b.WriteString(env.Label)
	b.WriteByte('\n')
	b.WriteString(env.Notes)
	b.WriteByte('\n')
	b.WriteString(env.CaseReference)
	b.WriteByte('\n')
	b.WriteString(env.Payload.Kind)
	b.WriteByte('\n')
	b.WriteString(env.Payload.ObjectPath)
	b.WriteByte('\n')
	b.Write(env.Payload.InlineData)
	b.WriteByte('\n')
	b.Write(env.Payload.Value)
	b.WriteByte('\n')
	b.WriteString(env.Payload.SecretReference)
	b.WriteByte('\n')
	b.WriteString(metadataText(env.Payload.Metadata))
	for _, res := range env.Payload.Resources {
		b.WriteString(res.Name)
		b.WriteByte('\n')
		b.WriteString(res.Type)
		b.WriteByte('\n')
		b.WriteString(res.Path)
		b.WriteByte('\n')
		b.Write(res.Content)
		b.Write(res.Value)
		b.WriteString(metadataText(res.Metadata))
	}
	return b.String()
}

func (idx *KGAutoIndexer) syncKV(ctx context.Context) error {
	keys, err := idx.db.Keys("*")
	if err != nil {
		return err
	}
	for _, key := range keys {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !idx.db.kgShouldIndexKVKey(key) {
			continue
		}
		value, err := idx.db.Get([]byte(key))
		if err != nil {
			idx.count(KGResourceKV, false)
			continue
		}
		idx.db.kgAutoIndexKV([]byte(key), value)
	}
	return nil
}

func (idx *KGAutoIndexer) syncObjects(ctx context.Context) error {
	keys, err := idx.db.Keys(ObjectRecordPrefix + "*")
	if err != nil {
		return err
	}
	for _, key := range keys {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		path := strings.TrimPrefix(key, ObjectRecordPrefix)
		rec, err := idx.db.getObjectRecord(path)
		if err != nil || rec.State == ObjectStateDeleted {
			idx.count(KGResourceObject, false)
			continue
		}
		var content []byte
		if data, _, err := idx.db.GetObjectInternal(path, rec.CreatedBy); err == nil {
			content = data
		}
		idx.db.kgAutoIndexObjectRecord(rec, content)
	}
	return nil
}

func (idx *KGAutoIndexer) syncSecrets(ctx context.Context) error {
	keys, err := idx.db.Keys(SecretRecordPrefix + "*")
	if err != nil {
		return err
	}
	for _, key := range keys {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		raw, err := idx.db.Get([]byte(key))
		if err != nil {
			continue
		}
		var rec SecretRecord
		if json.Unmarshal(raw, &rec) != nil {
			idx.count(KGResourceSecret, false)
			continue
		}
		var value []byte
		if idx.cfg.SecretValues {
			value, err = idx.db.openSecretRecord(&rec)
			if err != nil {
				idx.count(KGResourceSecret, false)
				continue
			}
		}
		idx.db.kgAutoIndexSecretValue(&rec, value)
	}
	return nil
}

func (idx *KGAutoIndexer) syncSQLRows(ctx context.Context) error {
	keys, err := idx.db.Keys("*")
	if err != nil {
		return err
	}
	for _, key := range keys {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !looksLikeSQLRowKey(key) {
			continue
		}
		value, err := idx.db.Get([]byte(key))
		if err != nil || !json.Valid(value) {
			continue
		}
		table := strings.SplitN(key, ":", 2)[0]
		idx.db.kgAutoIndexSQLRow(table, key, value)
	}
	return nil
}

func looksLikeSQLRowKey(key string) bool {
	if key == "" || strings.HasPrefix(key, "__") || strings.Contains(key, "::") {
		return false
	}
	if strings.HasPrefix(key, "obj:") || strings.HasPrefix(key, "secret:") || strings.HasPrefix(key, "entity:") || strings.HasPrefix(key, "compliance:") {
		return false
	}
	return strings.Contains(key, ":")
}

func (idx *KGAutoIndexer) syncEnvelopes(ctx context.Context) error {
	if idx.db.envelopeDir == "" {
		return nil
	}
	entries, err := os.ReadDir(idx.db.envelopeDir)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != envelopeSecureExtension {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), envelopeSecureExtension)
		env, err := idx.db.loadEnvelope(id)
		if err != nil {
			idx.count(KGResourceEnvelope, false)
			continue
		}
		idx.db.kgAutoIndexEnvelope(env)
	}
	return nil
}

func (idx *KGAutoIndexer) syncEntities(ctx context.Context) error {
	keys, err := idx.db.Keys(entityKeyPrefix + "*")
	if err != nil {
		return err
	}
	for _, key := range keys {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		entityID := strings.TrimPrefix(key, entityKeyPrefix)
		entity, err := idx.db.EntityManager().GetEntity(ctx, entityID, false)
		if err != nil || entity == nil || entity.Entity == nil {
			idx.count(KGResourceEntity, false)
			continue
		}
		idx.db.kgAutoIndexEntity(entity.Entity)
	}
	return nil
}
