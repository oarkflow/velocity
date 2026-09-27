package configio

import (
	"context"
	"encoding/json"
	"testing"
)

func TestExportJSON_ProducesFlatValidJSON(t *testing.T) {
	ctx := context.Background()
	p, kv := newTestPlugin()
	kv.data["cfg/db.host"] = []byte("localhost")
	kv.data["cfg/db.port"] = []byte("5432")

	out, err := p.ExportJSON(ctx, "cfg/")
	if err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("ExportJSON output is not valid JSON: %v", err)
	}
	want := map[string]string{"db.host": "localhost", "db.port": "5432"}
	if len(got) != len(want) || got["db.host"] != want["db.host"] || got["db.port"] != want["db.port"] {
		t.Fatalf("ExportJSON = %v, want %v", got, want)
	}
}

func TestImportJSON_FlattensNestedObjectWithMixedLeafTypes(t *testing.T) {
	ctx := context.Background()
	p, kv := newTestPlugin()

	doc := []byte(`{
		"db": {
			"host": "localhost",
			"port": 5432,
			"ssl": true
		},
		"tags": ["prod", "east"],
		"description": null,
		"name": "myapp"
	}`)

	n, err := p.ImportJSON(ctx, "app/", doc)
	if err != nil {
		t.Fatalf("ImportJSON: %v", err)
	}
	// 6 leaves: db.host, db.port, db.ssl, tags.0, tags.1, name — "description"
	// is null and must be SKIPPED, not written as an empty string.
	if n != 6 {
		t.Fatalf("imported = %d, want 6", n)
	}

	checks := map[string]string{
		"app/db.host": "localhost",
		"app/db.port": "5432", // not "5432.000000" — json.Number preserves integer formatting
		"app/db.ssl":  "true",
		"app/tags.0":  "prod",
		"app/tags.1":  "east",
		"app/name":    "myapp",
	}
	for k, want := range checks {
		got, ok := kv.data[k]
		if !ok {
			t.Fatalf("%s not imported", k)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if _, ok := kv.data["app/description"]; ok {
		t.Errorf("app/description should have been skipped (null leaf), but was written")
	}
}

func TestImportJSON_LargeIntegerPreservesExactDigits(t *testing.T) {
	ctx := context.Background()
	p, kv := newTestPlugin()

	// A value large enough that float64 round-tripping would lose
	// precision or render in scientific notation — json.Number must
	// preserve the exact source digits.
	doc := []byte(`{"big_id": 9007199254740993}`)
	if _, err := p.ImportJSON(ctx, "x/", doc); err != nil {
		t.Fatalf("ImportJSON: %v", err)
	}
	got := string(kv.data["x/big_id"])
	want := "9007199254740993"
	if got != want {
		t.Fatalf("big_id = %q, want %q (float64 precision loss or scientific notation leaking through)", got, want)
	}
}

func TestImportJSON_InvalidJSONErrors(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPlugin()
	if _, err := p.ImportJSON(ctx, "x/", []byte("{not valid json")); err == nil {
		t.Fatal("expected an error for invalid JSON, got nil")
	}
}
