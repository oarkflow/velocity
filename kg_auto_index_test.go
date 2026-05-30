package velocity

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func newAutoKGTestDB(t *testing.T, resources ...KGResourceType) *DB {
	t.Helper()
	db, err := NewWithConfig(Config{Path: t.TempDir(), DisableEncryption: true, DisableIndexPersistence: true})
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	db.EnableKnowledgeGraphAutoIndex(KnowledgeGraphAutoIndexConfig{
		Enabled:       true,
		Resources:     resources,
		SecretValues:  true,
		Existing:      false,
		Async:         false,
		MaxValueBytes: 1024,
	})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func requireKGHits(t *testing.T, db *DB, query string, want int) *KGSearchResponse {
	t.Helper()
	var resp *KGSearchResponse
	var err error
	for i := 0; i < 100; i++ {
		resp, err = db.KnowledgeGraph().Search(context.Background(), &KGSearchRequest{Query: query, Limit: 10})
		if err == nil && resp.TotalHits >= want {
			return resp
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("kg search %q: %v", query, err)
	}
	t.Fatalf("kg search %q got %d hits, want at least %d", query, resp.TotalHits, want)
	return resp
}

func TestKnowledgeGraphAutoIndex_DisabledByDefault(t *testing.T) {
	db, err := NewWithConfig(Config{Path: t.TempDir(), DisableEncryption: true, DisableIndexPersistence: true})
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()
	if st := db.KnowledgeGraphSyncStatus(); st.Enabled {
		t.Fatalf("auto index should be disabled by default")
	}
	if err := db.Put([]byte("note:1"), []byte("alpha beta gamma")); err != nil {
		t.Fatalf("put: %v", err)
	}
	resp, err := db.KnowledgeGraph().Search(context.Background(), &KGSearchRequest{Query: "alpha", Limit: 10})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if resp.TotalHits != 0 {
		t.Fatalf("unexpected auto indexed hit when disabled: %d", resp.TotalHits)
	}
}

func TestKnowledgeGraphAutoIndex_KVExistingNewDeleteAndRecursion(t *testing.T) {
	db := newAutoKGTestDB(t, KGResourceKV)
	if err := db.Put([]byte("note:existing"), []byte("existing compliance evidence")); err != nil {
		t.Fatalf("put existing: %v", err)
	}
	if err := db.SyncKnowledgeGraph(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}
	requireKGHits(t, db, "existing compliance", 1)

	if err := db.Put([]byte("note:new"), []byte("new audit trail")); err != nil {
		t.Fatalf("put new: %v", err)
	}
	requireKGHits(t, db, "audit trail", 1)
	if err := db.Delete([]byte("note:new")); err != nil {
		t.Fatalf("delete: %v", err)
	}
	resp, err := db.KnowledgeGraph().Search(context.Background(), &KGSearchRequest{Query: "audit trail", Limit: 10})
	if err != nil {
		t.Fatalf("search after delete: %v", err)
	}
	if resp.TotalHits != 0 {
		t.Fatalf("expected deleted kv to leave no KG hits, got %d", resp.TotalHits)
	}

	if err := db.Put([]byte(kgDocPrefix+"manual"), []byte("recursive should not index")); err != nil {
		t.Fatalf("put kg key: %v", err)
	}
	resp, err = db.KnowledgeGraph().Search(context.Background(), &KGSearchRequest{Query: "recursive", Limit: 10})
	if err != nil {
		t.Fatalf("search recursive: %v", err)
	}
	if resp.TotalHits != 0 {
		t.Fatalf("KG internal key was recursively indexed")
	}
}

func TestKnowledgeGraphAutoIndex_ObjectSecretEnvelopeEntity(t *testing.T) {
	ctx := context.Background()
	db := newAutoKGTestDB(t, KGResourceObject, KGResourceSecret, KGResourceEnvelope, KGResourceEntity)

	if _, err := db.StoreObject("docs/kg.txt", "text/plain", "alice", []byte("object knowledge graph content"), nil); err != nil {
		t.Fatalf("store object: %v", err)
	}
	requireKGHits(t, db, "object knowledge", 1)

	secret, err := db.CreateSecret(ctx, SecretRequest{Name: "api-key", Value: []byte("secret searchable token"), Owner: "alice"})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	requireKGHits(t, db, "searchable token", 1)
	if secret.Version == "" {
		t.Fatalf("expected secret version")
	}

	env, err := db.CreateEnvelope(ctx, &EnvelopeRequest{
		Label:     "KG Envelope",
		Type:      EnvelopeTypeInvestigationRecord,
		CreatedBy: "alice",
		Payload: EnvelopePayload{
			Kind:       "file",
			InlineData: []byte("envelope searchable content"),
		},
	})
	if err != nil {
		t.Fatalf("create envelope: %v", err)
	}
	requireKGHits(t, db, "envelope searchable", 1)
	env.Notes = "updated envelope note"
	if err := db.UpdateEnvelope(ctx, env); err != nil {
		t.Fatalf("update envelope: %v", err)
	}
	requireKGHits(t, db, "updated envelope", 1)

	entity, err := db.CreateEntity(ctx, &EntityRequest{
		Type:      EntityTypeJSON,
		Name:      "Acme KG Entity",
		Data:      json.RawMessage(`{"summary":"entity searchable content"}`),
		CreatedBy: "alice",
	})
	if err != nil {
		t.Fatalf("create entity: %v", err)
	}
	requireKGHits(t, db, "entity searchable", 1)
	if err := db.DeleteEntity(ctx, entity.EntityID); err != nil {
		t.Fatalf("delete entity: %v", err)
	}
	resp, err := db.KnowledgeGraph().Search(ctx, &KGSearchRequest{Query: "entity searchable", Limit: 10})
	if err != nil {
		t.Fatalf("search deleted entity: %v", err)
	}
	if resp.TotalHits != 0 {
		t.Fatalf("expected deleted entity to leave no hits, got %d", resp.TotalHits)
	}
}

func TestKnowledgeGraphAutoIndex_SecretMetadataOnlyMode(t *testing.T) {
	ctx := context.Background()
	db, err := NewWithConfig(Config{Path: t.TempDir(), DisableEncryption: true, DisableIndexPersistence: true})
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()
	db.EnableKnowledgeGraphAutoIndex(KnowledgeGraphAutoIndexConfig{
		Enabled:       true,
		Resources:     []KGResourceType{KGResourceSecret},
		SecretValues:  false,
		Existing:      false,
		Async:         false,
		MaxValueBytes: 1024,
	})
	if _, err := db.CreateSecret(ctx, SecretRequest{Name: "metadata-only-key", Value: []byte("do-not-index-secret-value"), Owner: "alice"}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	requireKGHits(t, db, "metadata-only-key", 1)
	resp, err := db.KnowledgeGraph().Search(ctx, &KGSearchRequest{Query: "do-not-index-secret-value", Limit: 10})
	if err != nil {
		t.Fatalf("search secret value: %v", err)
	}
	if resp.TotalHits != 0 {
		t.Fatalf("secret value was indexed in metadata-only mode")
	}
}

func TestKnowledgeGraphResourceGraph_SearchConnectsResources(t *testing.T) {
	db := newAutoKGTestDB(t, KGResourceKV, KGResourceObject)
	if err := db.Put([]byte("case/acme"), []byte("Acme Corp opened a compliance review for renewal.")); err != nil {
		t.Fatalf("put case: %v", err)
	}
	if _, err := db.StoreObject("reports/acme.txt", "text/plain", "alice", []byte("Acme Corp remediation report is attached to the review."), nil); err != nil {
		t.Fatalf("store object: %v", err)
	}
	graph, err := db.KnowledgeGraph().SearchResourceGraph(context.Background(), &KGResourceGraphRequest{
		Query: "Acme Corp review",
		Limit: 5,
	})
	if err != nil {
		t.Fatalf("resource graph: %v", err)
	}
	if len(graph.Nodes) < 2 {
		t.Fatalf("expected at least 2 graph nodes, got %d", len(graph.Nodes))
	}
	if len(graph.Edges) == 0 {
		t.Fatalf("expected an inferred relation edge between matching resources")
	}
	if graph.Edges[0].RelationType != "mentions_same_entity" {
		t.Fatalf("unexpected edge relation: %s", graph.Edges[0].RelationType)
	}
}

func TestKnowledgeGraphAutoIndex_BackgroundConfigAndResourceFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	db, err := NewWithConfig(Config{Path: path, DisableEncryption: true, DisableIndexPersistence: true})
	if err != nil {
		t.Fatalf("new seed db: %v", err)
	}
	if err := db.Put([]byte("keep:1"), []byte("background sync record")); err != nil {
		t.Fatalf("put seed: %v", err)
	}
	if _, err := db.StoreObject("docs/skip.txt", "text/plain", "alice", []byte("object should not sync"), nil); err != nil {
		t.Fatalf("store seed object: %v", err)
	}
	_ = db.Close()

	reopened, err := NewWithConfig(Config{
		Path:                             path,
		DisableEncryption:                true,
		DisableIndexPersistence:          true,
		KnowledgeGraphAutoIndexEnabled:   true,
		KnowledgeGraphAutoIndexResources: []KGResourceType{KGResourceKV},
	})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	requireKGHits(t, reopened, "background sync", 1)
	resp, err := reopened.KnowledgeGraph().Search(context.Background(), &KGSearchRequest{Query: "object should not sync", Limit: 10})
	if err != nil {
		t.Fatalf("search filtered object: %v", err)
	}
	if resp.TotalHits != 0 {
		t.Fatalf("resource filter indexed object unexpectedly")
	}
}
