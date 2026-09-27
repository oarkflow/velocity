package configio

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func newTestPlugin() (*Plugin, *memKV) {
	kv := newMemKV()
	return &Plugin{kvDep: "kv", kv: kv}, kv
}

func TestExportEnv_PlainValuesSortedAndCased(t *testing.T) {
	ctx := context.Background()
	p, kv := newTestPlugin()
	kv.data["app/db.host"] = []byte("localhost")
	kv.data["app/db-port"] = []byte("5432")
	kv.data["app/already_upper"] = []byte("x")

	out, err := p.ExportEnv(ctx, "app/")
	if err != nil {
		t.Fatalf("ExportEnv: %v", err)
	}
	got := string(out)
	want := "ALREADY_UPPER=x\nDB_HOST=localhost\nDB_PORT=5432\n"
	if got != want {
		t.Fatalf("ExportEnv output mismatch:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestExportEnv_QuotesSpecialValues(t *testing.T) {
	ctx := context.Background()
	p, kv := newTestPlugin()
	kv.data["cfg/greeting"] = []byte("hello world")
	kv.data["cfg/note"] = []byte(`has "quotes" and \backslash and
newline`)
	kv.data["cfg/plain"] = []byte("noquotesneeded")

	out, err := p.ExportEnv(ctx, "cfg/")
	if err != nil {
		t.Fatalf("ExportEnv: %v", err)
	}
	got := string(out)

	if !strings.Contains(got, `GREETING="hello world"`) {
		t.Errorf("expected quoted GREETING line, got:\n%s", got)
	}
	if !strings.Contains(got, `NOTE="has \"quotes\" and \\backslash and\nnewline"`) {
		t.Errorf("expected correctly escaped NOTE line, got:\n%s", got)
	}
	if !strings.Contains(got, "PLAIN=noquotesneeded\n") {
		t.Errorf("expected unquoted PLAIN line, got:\n%s", got)
	}
}

func TestRoundTrip_ExportEnvThenImportEnv(t *testing.T) {
	ctx := context.Background()
	p, kv := newTestPlugin()
	// Keys already in UPPER_SNAKE_CASE so envKeyName is a no-op — this is
	// what makes an exact key-name round trip meaningful (ExportEnv's
	// casing conversion is one-directional by design, see env.go).
	kv.data["src/DB_HOST"] = []byte("localhost")
	kv.data["src/API_KEY"] = []byte(`value with spaces, a "quote", and\backslash`)
	kv.data["src/EMPTY"] = []byte("")

	exported, err := p.ExportEnv(ctx, "src/")
	if err != nil {
		t.Fatalf("ExportEnv: %v", err)
	}

	n, err := p.ImportEnv(ctx, "dst/", exported)
	if err != nil {
		t.Fatalf("ImportEnv: %v", err)
	}
	if n != 3 {
		t.Fatalf("ImportEnv count = %d, want 3", n)
	}

	for _, key := range []string{"DB_HOST", "API_KEY", "EMPTY"} {
		orig := kv.data["src/"+key]
		got, ok := kv.data["dst/"+key]
		if !ok {
			t.Fatalf("dst/%s missing after round trip", key)
		}
		if string(got) != string(orig) {
			t.Errorf("round-trip mismatch for %s: got %q, want %q", key, got, orig)
		}
	}
}

func TestImportEnv_CommentsBlankLinesAndBothQuoteStyles(t *testing.T) {
	ctx := context.Background()
	p, kv := newTestPlugin()

	data := []byte(`# this is a comment
PLAIN=value1

QUOTED="value with spaces"
SINGLE='literal $no expansion'
# another comment
TRAILING_WS = value2
`)
	n, err := p.ImportEnv(ctx, "p/", data)
	if err != nil {
		t.Fatalf("ImportEnv: %v", err)
	}
	if n != 4 {
		t.Fatalf("imported = %d, want 4", n)
	}
	checks := map[string]string{
		"p/PLAIN":       "value1",
		"p/QUOTED":      "value with spaces",
		"p/SINGLE":      "literal $no expansion",
		"p/TRAILING_WS": "value2",
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
}

func TestExportEnv_MultiPageScanCapturesEveryKey(t *testing.T) {
	ctx := context.Background()
	p, kv := newTestPlugin()

	// scanPageSize is 50 — 130 keys forces at least 3 Scan pages.
	const n = 130
	for i := 0; i < n; i++ {
		kv.data["many/"+padKey(i)] = []byte("v")
	}

	out, err := p.ExportEnv(ctx, "many/")
	if err != nil {
		t.Fatalf("ExportEnv: %v", err)
	}
	lines := strings.Count(string(out), "\n")
	if lines != n {
		t.Fatalf("exported %d lines, want %d (pagination must not drop keys)", lines, n)
	}
}

func padKey(i int) string {
	return fmt.Sprintf("KEY_%04d", i)
}
