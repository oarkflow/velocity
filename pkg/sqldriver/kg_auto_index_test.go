package sqldriver

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/kg"
)

func openAutoKGSQLDB(t *testing.T, name string) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	cfg := velocity.Config{Path: path, DisableEncryption: true, DisableIndexPersistence: true}
	DSNConfigs[path] = cfg
	t.Cleanup(func() { delete(DSNConfigs, path) })
	sdb, err := sql.Open(DriverName, path)
	if err != nil {
		t.Fatalf("sql open: %v", err)
	}
	if err := sdb.Ping(); err != nil {
		t.Fatalf("sql ping: %v", err)
	}
	t.Cleanup(func() { _ = sdb.Close() })
	engineDBForPath(t, path).EnableKnowledgeGraphAutoIndex(velocity.KnowledgeGraphAutoIndexConfig{
		Enabled:       true,
		Resources:     []kg.ResourceType{kg.ResourceSQLRow},
		SecretValues:  true,
		Existing:      false,
		Async:         false,
		MaxValueBytes: 1024,
	})
	return sdb, path
}

func engineDBForPath(t *testing.T, path string) *velocity.DB {
	t.Helper()
	enginesMu.Lock()
	defer enginesMu.Unlock()
	state := engines[path]
	if state == nil || state.db == nil {
		t.Fatalf("engine db not open for %s", path)
	}
	return state.db
}

func waitSQLKGHits(t *testing.T, db *velocity.DB, query string, want int) *kg.KGSearchResponse {
	t.Helper()
	var resp *kg.KGSearchResponse
	var err error
	for i := 0; i < 30; i++ {
		resp, err = db.KnowledgeGraph().Search(context.Background(), &kg.KGSearchRequest{Query: query, Limit: 10})
		if err == nil && resp.TotalHits >= want {
			return resp
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("kg search %q: %v", query, err)
	}
	t.Fatalf("kg search %q got %d hits, want %d", query, resp.TotalHits, want)
	return resp
}

func TestSQLKnowledgeGraphAutoIndex_InsertUpdateDelete(t *testing.T) {
	sdb, path := openAutoKGSQLDB(t, "insert_update_delete")
	if _, err := sdb.Exec(`CREATE TABLE patients (id BIGINT PRIMARY KEY, note TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	vdb := engineDBForPath(t, path)
	if _, err := sdb.Exec(`INSERT INTO patients (id, note) VALUES (?, ?)`, 1, "initial kg row"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	waitSQLKGHits(t, vdb, "initial kg", 1)
	if _, err := sdb.Exec(`UPDATE patients SET note = ? WHERE id = ?`, "updated kg row", 1); err != nil {
		t.Fatalf("update: %v", err)
	}
	waitSQLKGHits(t, vdb, "updated kg", 1)
	if _, err := sdb.Exec(`DELETE FROM patients WHERE id = ?`, 1); err != nil {
		t.Fatalf("delete: %v", err)
	}
	resp, err := vdb.KnowledgeGraph().Search(context.Background(), &kg.KGSearchRequest{Query: "updated kg", Limit: 10})
	if err != nil {
		t.Fatalf("search after delete: %v", err)
	}
	if resp.TotalHits != 0 {
		t.Fatalf("deleted SQL row still indexed: %d hits", resp.TotalHits)
	}
}

func TestSQLKnowledgeGraphAutoIndex_RollbackDoesNotIndex(t *testing.T) {
	sdb, path := openAutoKGSQLDB(t, "rollback")
	if _, err := sdb.Exec(`CREATE TABLE notes (id BIGINT PRIMARY KEY, body TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	vdb := engineDBForPath(t, path)
	tx, err := sdb.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO notes (id, body) VALUES (?, ?)`, 1, "rollback kg token"); err != nil {
		t.Fatalf("tx insert: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	resp, err := vdb.KnowledgeGraph().Search(context.Background(), &kg.KGSearchRequest{Query: "rollback kg token", Limit: 10})
	if err != nil {
		t.Fatalf("search rollback: %v", err)
	}
	if resp.TotalHits != 0 {
		t.Fatalf("rolled back SQL row indexed: %d hits", resp.TotalHits)
	}
}
