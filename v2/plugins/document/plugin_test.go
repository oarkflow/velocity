package document

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	storagemem "github.com/oarkflow/velocity/v2/plugins/storage-mem"
)

func newTestPlugin() *Plugin {
	p := NewPlugin("storage-mem")
	p.storage = storagemem.NewEngine()
	return p
}

func TestSetJSONGetJSONRoundTrip(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	doc := json.RawMessage(`{"name":"alice","age":30}`)
	if err := p.SetJSON(ctx, "user1", doc); err != nil {
		t.Fatalf("SetJSON: %v", err)
	}

	got, ok, err := p.GetJSON(ctx, "user1")
	if err != nil || !ok {
		t.Fatalf("GetJSON: ok=%v err=%v", ok, err)
	}
	var want, have map[string]any
	json.Unmarshal(doc, &want)
	json.Unmarshal(got, &have)
	if have["name"] != want["name"] {
		t.Fatalf("got %v, want %v", have, want)
	}

	if _, ok, err := p.GetJSON(ctx, "missing"); err != nil || ok {
		t.Fatalf("GetJSON(missing): ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

func TestSetOnNewKeyCreatesDocumentAndPath(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	if err := p.Set(ctx, "newdoc", "name", "bob"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	v, ok, err := p.Get(ctx, "newdoc", "name")
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if v != "bob" {
		t.Fatalf("got %v, want bob", v)
	}
}

func TestSetCreatesIntermediateObjects(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	if err := p.Set(ctx, "cfg", "database.connection.host", "localhost"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	raw, ok, err := p.GetJSON(ctx, "cfg")
	if err != nil || !ok {
		t.Fatalf("GetJSON: ok=%v err=%v", ok, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	db, ok := doc["database"].(map[string]any)
	if !ok {
		t.Fatalf("expected database to be an object, got %#v", doc["database"])
	}
	conn, ok := db["connection"].(map[string]any)
	if !ok {
		t.Fatalf("expected connection to be an object, got %#v", db["connection"])
	}
	if conn["host"] != "localhost" {
		t.Fatalf("got host=%v, want localhost", conn["host"])
	}

	// Also verify via Get with the full dot path.
	v, ok, err := p.Get(ctx, "cfg", "database.connection.host")
	if err != nil || !ok || v != "localhost" {
		t.Fatalf("Get(database.connection.host): v=%v ok=%v err=%v", v, ok, err)
	}
}

func TestGetMissingPathReturnsNotFoundNotError(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	must(t, p.SetJSON(ctx, "doc", json.RawMessage(`{"a":{"b":1}}`)))

	v, ok, err := p.Get(ctx, "doc", "a.c")
	if err != nil {
		t.Fatalf("expected no error for missing path, got %v", err)
	}
	if ok {
		t.Fatalf("expected ok=false for missing path, got true (value=%v)", v)
	}

	// Missing document entirely.
	v, ok, err = p.Get(ctx, "nope", "a.b")
	if err != nil || ok {
		t.Fatalf("Get on missing document: v=%v ok=%v err=%v", v, ok, err)
	}
}

func TestArrayIndexGetAndSet(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	must(t, p.SetJSON(ctx, "doc", json.RawMessage(`{"tags":["a","b","c"]}`)))

	v, ok, err := p.Get(ctx, "doc", "tags.1")
	if err != nil || !ok || v != "b" {
		t.Fatalf("Get(tags.1): v=%v ok=%v err=%v", v, ok, err)
	}

	if err := p.Set(ctx, "doc", "tags.1", "B"); err != nil {
		t.Fatalf("Set(tags.1): %v", err)
	}
	v, ok, err = p.Get(ctx, "doc", "tags.1")
	if err != nil || !ok || v != "B" {
		t.Fatalf("Get(tags.1) after set: v=%v ok=%v err=%v", v, ok, err)
	}

	// Out-of-range Set must error, not silently pad.
	err = p.Set(ctx, "doc", "tags.10", "x")
	if err == nil {
		t.Fatalf("expected error setting out-of-range array index, got nil")
	}

	// Out-of-range Get returns not-found, no error.
	gv, gok, gerr := p.Get(ctx, "doc", "tags.10")
	if gerr != nil || gok {
		t.Fatalf("Get out-of-range: v=%v ok=%v err=%v, want ok=false err=nil", gv, gok, gerr)
	}

	// Negative index Get -> not found.
	gv, gok, gerr = p.Get(ctx, "doc", "tags.-1")
	if gerr != nil || gok {
		t.Fatalf("Get negative index: v=%v ok=%v err=%v, want ok=false err=nil", gv, gok, gerr)
	}
}

func TestTypeMismatchErrorDistinguishedFromNotFound(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	must(t, p.SetJSON(ctx, "doc", json.RawMessage(`{"name":"leaf-string","obj":{"a":1}}`)))

	// Path continues past a leaf (string) value.
	_, _, err := p.Get(ctx, "doc", "name.sub")
	if err == nil {
		t.Fatalf("expected type-mismatch error continuing past a leaf value, got nil")
	}
	if !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("expected ErrTypeMismatch, got %v", err)
	}

	// Treats an object as an array.
	_, _, err = p.Get(ctx, "doc", "obj.0")
	if err == nil {
		t.Fatalf("expected type-mismatch error treating object as array, got nil")
	}
	if !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("expected ErrTypeMismatch, got %v", err)
	}

	// Set: treats a leaf as an object (adding a nested field to a string value).
	err = p.Set(ctx, "doc", "name.sub", "x")
	if err == nil || !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("expected ErrTypeMismatch on Set past a leaf, got %v", err)
	}

	// Contrast: a genuinely missing path is NOT a type mismatch.
	_, ok, err := p.Get(ctx, "doc", "does.not.exist")
	if err != nil {
		t.Fatalf("missing path should not error, got %v", err)
	}
	if ok {
		t.Fatalf("expected ok=false for missing path")
	}
}

func TestDeleteRemovesFieldAndIsIdempotentOnMissing(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()
	must(t, p.SetJSON(ctx, "doc", json.RawMessage(`{"a":{"b":1,"c":2}}`)))

	if err := p.Delete(ctx, "doc", "a.b"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, ok, err := p.Get(ctx, "doc", "a.b")
	if err != nil || ok {
		t.Fatalf("expected a.b gone: ok=%v err=%v", ok, err)
	}
	// Sibling untouched.
	v, ok, err := p.Get(ctx, "doc", "a.c")
	if err != nil || !ok || v.(json.Number).String() != "2" {
		t.Fatalf("expected a.c=2 untouched: v=%v ok=%v err=%v", v, ok, err)
	}

	// Deleting a nonexistent path is a no-op, not an error.
	if err := p.Delete(ctx, "doc", "a.b"); err != nil {
		t.Fatalf("Delete on already-missing path should be a no-op, got %v", err)
	}
	if err := p.Delete(ctx, "doc", "x.y.z"); err != nil {
		t.Fatalf("Delete on never-existed path should be a no-op, got %v", err)
	}
	// Deleting from a document that doesn't exist at all is also a no-op.
	if err := p.Delete(ctx, "nosuchdoc", "a.b"); err != nil {
		t.Fatalf("Delete on missing document should be a no-op, got %v", err)
	}
}

func TestRealisticMultiLevelDocumentSequence(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	base := json.RawMessage(`{
		"service": "velocity",
		"config": {
			"replicas": 3,
			"tags": ["prod", "primary"],
			"limits": {"cpu": "500m", "memory": "512Mi"}
		}
	}`)
	must(t, p.SetJSON(ctx, "app", base))

	// Update a nested scalar.
	must(t, p.Set(ctx, "app", "config.limits.cpu", "1000m"))
	// Update an array element.
	must(t, p.Set(ctx, "app", "config.tags.1", "secondary"))
	// Add a brand-new nested field.
	must(t, p.Set(ctx, "app", "config.limits.gpu", "1"))
	// Delete a field.
	must(t, p.Delete(ctx, "app", "config.replicas"))

	raw, ok, err := p.GetJSON(ctx, "app")
	if err != nil || !ok {
		t.Fatalf("GetJSON: ok=%v err=%v", ok, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, exists := doc["config"].(map[string]any)["replicas"]; exists {
		t.Fatalf("expected replicas deleted")
	}
	cfg := doc["config"].(map[string]any)
	if cfg["limits"].(map[string]any)["cpu"] != "1000m" {
		t.Fatalf("cpu not updated: %v", cfg["limits"])
	}
	if cfg["limits"].(map[string]any)["gpu"] != "1" {
		t.Fatalf("gpu not added: %v", cfg["limits"])
	}
	tags := cfg["tags"].([]any)
	if tags[0] != "prod" || tags[1] != "secondary" {
		t.Fatalf("tags not as expected: %v", tags)
	}
	if doc["service"] != "velocity" {
		t.Fatalf("untouched field service changed: %v", doc["service"])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
