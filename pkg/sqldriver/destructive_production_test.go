//go:build destructive

package sqldriver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/oarkflow/velocity"
)

type destructiveSQLManifest struct {
	Rows       map[int]string `json:"rows"`
	RolledBack []int          `json:"rolled_back"`
}

func TestDestructiveSQLChildProcess(t *testing.T) {
	if os.Getenv("VELOCITY_SQL_DESTRUCTIVE_CHILD") != "1" {
		t.Skip("helper process only")
	}
	mode := os.Getenv("VELOCITY_SQL_DESTRUCTIVE_MODE")
	path := os.Getenv("VELOCITY_SQL_DESTRUCTIVE_PATH")
	manifest := os.Getenv("VELOCITY_SQL_DESTRUCTIVE_MANIFEST")
	iterations := sqlDestructiveIterations(120)
	DSNConfigs[path] = velocity.Config{Path: path, DisableEncryption: true}
	db, err := sql.Open(DriverName, path)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (id BIGINT PRIMARY KEY, email TEXT UNIQUE, name TEXT NOT NULL)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	switch mode {
	case "transactions":
		runSQLTransactionChild(t, db, manifest, iterations)
	case "bulk":
		runSQLBulkChild(t, db, manifest, iterations)
	default:
		t.Fatalf("unknown SQL destructive mode %q", mode)
	}
	select {}
}

func TestDestructiveSQLTransactionCrashMatrix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sql_tx")
	manifest := filepath.Join(path, "manifest.json")
	runAndKillSQLDestructiveChild(t, path, manifest, "transactions", 30)
	verifySQLManifest(t, path, manifest)
}

func TestDestructiveSQLBulkInsertCrashMatrix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sql_bulk")
	manifest := filepath.Join(path, "manifest.json")
	runAndKillSQLDestructiveChild(t, path, manifest, "bulk", 40)
	verifySQLManifest(t, path, manifest)
}

func runSQLTransactionChild(t *testing.T, db *sql.DB, manifestPath string, iterations int) {
	t.Helper()
	m := destructiveSQLManifest{Rows: make(map[int]string)}
	for i := 0; i < iterations; i++ {
		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("begin failed: %v", err)
		}
		name := fmt.Sprintf("user-%04d", i)
		_, err = tx.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, i, fmt.Sprintf("u%04d@example.test", i), name)
		if err != nil {
			_ = tx.Rollback()
			t.Fatalf("insert failed: %v", err)
		}
		if i%5 == 0 {
			if err := tx.Rollback(); err != nil {
				t.Fatalf("rollback failed: %v", err)
			}
			m.RolledBack = append(m.RolledBack, i)
		} else {
			if err := tx.Commit(); err != nil {
				t.Fatalf("commit failed: %v", err)
			}
			m.Rows[i] = name
		}
		writeSQLManifest(t, manifestPath, m)
		time.Sleep(5 * time.Millisecond)
	}
}

func runSQLBulkChild(t *testing.T, db *sql.DB, manifestPath string, iterations int) {
	t.Helper()
	m := destructiveSQLManifest{Rows: make(map[int]string)}
	nextID := 0
	for nextID < iterations {
		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("begin failed: %v", err)
		}
		for j := 0; j < 8 && nextID < iterations; j++ {
			name := fmt.Sprintf("bulk-%04d", nextID)
			if _, err := tx.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, nextID, fmt.Sprintf("b%04d@example.test", nextID), name); err != nil {
				_ = tx.Rollback()
				t.Fatalf("bulk insert failed: %v", err)
			}
			m.Rows[nextID] = name
			nextID++
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("bulk commit failed: %v", err)
		}
		writeSQLManifest(t, manifestPath, m)
		time.Sleep(5 * time.Millisecond)
	}
}

func runAndKillSQLDestructiveChild(t *testing.T, path, manifest, mode string, minRows int) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestDestructiveSQLChildProcess$", "-test.v")
	cmd.Env = append(os.Environ(),
		"VELOCITY_SQL_DESTRUCTIVE_CHILD=1",
		"VELOCITY_SQL_DESTRUCTIVE_PATH="+path,
		"VELOCITY_SQL_DESTRUCTIVE_MANIFEST="+manifest,
		"VELOCITY_SQL_DESTRUCTIVE_MODE="+mode,
		"VELOCITY_SQL_DESTRUCTIVE_ITER="+strconv.Itoa(sqlDestructiveIterations(160)),
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child failed: %v", err)
	}
	waitForSQLManifestRows(t, ctx, manifest, minRows)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill child failed: %v", err)
	}
	_ = cmd.Wait()
}

func verifySQLManifest(t *testing.T, path, manifestPath string) {
	t.Helper()
	m := readSQLManifest(t, manifestPath)
	DSNConfigs[path] = velocity.Config{Path: path, DisableEncryption: true}
	db, err := sql.Open(DriverName, path)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer db.Close()
	for id, wantName := range m.Rows {
		var got string
		if err := db.QueryRow(`SELECT name FROM users WHERE id = ?`, id).Scan(&got); err != nil {
			t.Fatalf("committed row %d missing: %v", id, err)
		}
		if got != wantName {
			t.Fatalf("row %d name = %q, want %q", id, got, wantName)
		}
	}
	for _, id := range m.RolledBack {
		var count int
		err := db.QueryRow(`SELECT count(*) FROM users WHERE id = ?`, id).Scan(&count)
		if err == sql.ErrNoRows {
			count = 0
		} else if err != nil {
			t.Fatalf("rollback check failed: %v", err)
		}
		if count != 0 {
			t.Fatalf("rolled-back row %d became visible", id)
		}
	}
	var total int
	if err := db.QueryRow(`SELECT count(*) FROM users`).Scan(&total); err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if total < len(m.Rows) {
		t.Fatalf("row count %d below committed manifest count %d", total, len(m.Rows))
	}
}

func writeSQLManifest(t *testing.T, path string, m destructiveSQLManifest) {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatalf("write manifest failed: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename manifest failed: %v", err)
	}
}

func readSQLManifest(t *testing.T, path string) destructiveSQLManifest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest failed: %v", err)
	}
	var m destructiveSQLManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal manifest failed: %v", err)
	}
	if len(m.Rows) == 0 {
		t.Fatalf("manifest has no committed rows")
	}
	return m
}

func waitForSQLManifestRows(t *testing.T, ctx context.Context, path string, minRows int) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for SQL manifest: %v", ctx.Err())
		case <-ticker.C:
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var m destructiveSQLManifest
			if json.Unmarshal(data, &m) == nil && len(m.Rows) >= minRows {
				return
			}
		}
	}
}

func sqlDestructiveIterations(defaultValue int) int {
	if raw := os.Getenv("VELOCITY_DESTRUCTIVE_SOAK_ITERS"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			return n
		}
	}
	return defaultValue
}
