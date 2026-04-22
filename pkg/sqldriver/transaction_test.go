package sqldriver

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/oarkflow/velocity"
)

func TestSQLDriver_Transactions(t *testing.T) {
	os.RemoveAll("./testdb_tx")
	defer os.RemoveAll("./testdb_tx")

	schemaEvents := &velocity.SearchSchema{
		Fields: []velocity.SearchSchemaField{
			{Name: "id", Searchable: true, HashSearch: true},
			{Name: "event", Searchable: true},
		},
	}

	DSNConfigs["./testdb_tx"] = velocity.Config{
		SearchSchemas: map[string]*velocity.SearchSchema{
			"logs": schemaEvents,
		},
	}

	db, err := sql.Open("velocity", "./testdb_tx")
	if err != nil {
		t.Fatalf("Failed to open driver: %v", err)
	}
	defer db.Close()

	// Run initial insert natively outside tx
	_, err = db.Exec("INSERT INTO logs (id, event) VALUES (?, ?)", 1, "Startup")
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Test 1: Rollback
	tx1, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}

	_, err = tx1.Exec("INSERT INTO logs (id, event) VALUES (?, ?)", 2, "Failure Log")
	if err != nil {
		t.Fatalf("Tx Insert failed: %v", err)
	}
	_, err = tx1.Exec("DELETE FROM logs WHERE id = 1")
	if err != nil {
		t.Fatalf("Tx Delete failed: %v", err)
	}

	err = tx1.Rollback()
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	// Verify rollback success: Log 1 should exist, Log 2 should not
	time.Sleep(200 * time.Millisecond)
	var count int
	err = db.QueryRow("SELECT count(*) FROM logs").Scan(&count)
	if err != nil {
		t.Fatalf("Count query error: %v", err)
	}
	if count != 1 {
		t.Fatalf("Expected 1 log after rollback, got %d", count)
	}

	// Test 2: Commit
	tx2, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin 2 failed: %v", err)
	}

	_, err = tx2.Exec("INSERT INTO logs (id, event) VALUES (?, ?)", 3, "Success Log")
	_, err = tx2.Exec("UPDATE logs SET event = 'Updated Startup' WHERE id = 1")

	err = tx2.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Verify commit success
	err = db.QueryRow("SELECT count(*) FROM logs").Scan(&count)
	if count != 2 {
		t.Fatalf("Expected 2 logs after commit, got %d", count)
	}

	var eventName string
	err = db.QueryRow("SELECT event FROM logs WHERE id = 1").Scan(&eventName)
	if eventName != "Updated Startup" {
		t.Fatalf("Expected updated event name, got %s", eventName)
	}
}
