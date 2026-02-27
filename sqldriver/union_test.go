package sqldriver

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/oarkflow/velocity"
)

func TestSQLDriver_Union(t *testing.T) {
	os.RemoveAll("./testdb_union")
	defer os.RemoveAll("./testdb_union")

	schemaEvents := &velocity.SearchSchema{
		Fields: []velocity.SearchSchemaField{
			{Name: "id", Searchable: true, HashSearch: true},
			{Name: "source", Searchable: true},
		},
	}

	DSNConfigs["./testdb_union"] = velocity.Config{
		SearchSchemas: map[string]*velocity.SearchSchema{
			"mobile_events": schemaEvents,
			"web_events":    schemaEvents,
		},
	}

	db, err := sql.Open("velocity", "./testdb_union")
	if err != nil {
		t.Fatalf("Failed to open driver: %v", err)
	}
	defer db.Close()

	// 1. Insert Mobile
	_, _ = db.Exec("INSERT INTO mobile_events (id, source) VALUES (?, ?)", 1, "iOS")
	_, _ = db.Exec("INSERT INTO mobile_events (id, source) VALUES (?, ?)", 2, "Android")

	// 2. Insert Web
	_, _ = db.Exec("INSERT INTO web_events (id, source) VALUES (?, ?)", 3, "Chrome")
	// Insert duplicate to test UNION DISTINCT
	_, _ = db.Exec("INSERT INTO web_events (id, source) VALUES (?, ?)", 1, "iOS")

	time.Sleep(500 * time.Millisecond) // await index

	// 3. Execute UNION ALL
	queryAll := `
		SELECT source FROM mobile_events
		UNION ALL
		SELECT source FROM web_events
	`
	rowsAll, err := db.Query(queryAll)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	defer rowsAll.Close()

	countAll := 0
	for rowsAll.Next() {
		countAll++
	}

	if countAll != 4 {
		t.Errorf("Expected 4 total events for UNION ALL, got %d", countAll) // 2 mobile, 2 web
	}

	// 4. Execute UNION (DISTINCT)
	queryDistinct := `
		SELECT source FROM mobile_events
		UNION
		SELECT source FROM web_events
	`
	rowsDistinct, err := db.Query(queryDistinct)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	defer rowsDistinct.Close()

	countDistinct := 0
	for rowsDistinct.Next() {
		countDistinct++
	}

	if countDistinct != 3 {
		t.Errorf("Expected 3 distinct events for UNION, got %d", countDistinct) // "iOS" matches!
	}
}
