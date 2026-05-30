package sqldriver

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func openTypedTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := filepath.Join(os.TempDir(), "velocity_sqldriver_types_"+uuid.NewString())
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	db, err := sql.Open("velocity", dir)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestSQLDriver_TypedDefaultsAndPrimaryKey(t *testing.T) {
	db := openTypedTestDB(t)
	_, err := db.Exec(`CREATE TABLE users (
		uuid string PRIMARY KEY DEFAULT uuid(),
		id int INDEX,
		name string NOT NULL,
		bio string FULLTEXT,
		price money DEFAULT 'USD 0.00',
		payload json,
		created_at timestampz DEFAULT now(),
		score decimal VALUEINDEX
	)`)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	_, err = db.Exec(`INSERT INTO users (id, name, bio, payload, score) VALUES (?, ?, ?, ?, ?)`,
		7, "Ada", "Analytical engine notes", `{"tier":"gold","limits":[1,2]}`, "1234567890.123456789")
	if err != nil {
		t.Fatalf("insert failed: %v", err)
	}
	var id int64
	var generated string
	var price any
	var payload any
	var created string
	var score string
	err = db.QueryRow(`SELECT id, uuid, price, payload, created_at, score FROM users WHERE id = ?`, 7).
		Scan(&id, &generated, &price, &payload, &created, &score)
	if err != nil {
		t.Fatalf("select failed: %v", err)
	}
	if id != 7 {
		t.Fatalf("expected typed integer id, got %d", id)
	}
	if _, err := uuid.Parse(generated); err != nil {
		t.Fatalf("default uuid() produced invalid uuid %q: %v", generated, err)
	}
	priceMap, ok := price.(map[string]any)
	if !ok || priceMap["currency"] != "USD" || priceMap["amount"] != "0.00" {
		t.Fatalf("unexpected money default: %#v", price)
	}
	payloadMap, ok := payload.(map[string]any)
	if !ok || payloadMap["tier"] != "gold" {
		t.Fatalf("unexpected json payload: %#v", payload)
	}
	if _, err := time.Parse(time.RFC3339Nano, created); err != nil {
		t.Fatalf("default now() produced invalid timestamp %q: %v", created, err)
	}
	if score != "1234567890.123456789" {
		t.Fatalf("decimal precision was not preserved: %q", score)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE bio LIKE '%engine%' AND score >= '1000'`).Scan(&count); err != nil {
		t.Fatalf("fulltext/range query failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one indexed fulltext row, got %d", count)
	}
}

func TestSQLDriver_TypeValidationRejectsInvalidValues(t *testing.T) {
	db := openTypedTestDB(t)
	_, err := db.Exec(`CREATE TABLE typed (
		pk string PRIMARY KEY DEFAULT uuid(),
		i8 int8,
		i16 int16,
		i32 int32,
		js json,
		event_date date,
		event_ts timestampz,
		price money
	)`)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	cases := []struct {
		name string
		sql  string
		args []any
	}{
		{"int8 range", `INSERT INTO typed (i8) VALUES (?)`, []any{128}},
		{"int16 range", `INSERT INTO typed (i16) VALUES (?)`, []any{32768}},
		{"int32 range", `INSERT INTO typed (i32) VALUES (?)`, []any{int64(2147483648)}},
		{"json validation", `INSERT INTO typed (js) VALUES (?)`, []any{`{"broken"`}},
		{"date validation", `INSERT INTO typed (event_date) VALUES (?)`, []any{"2026-40-99"}},
		{"timestampz validation", `INSERT INTO typed (event_ts) VALUES (?)`, []any{"2026-05-30 10:00:00"}},
		{"money validation", `INSERT INTO typed (price) VALUES (?)`, []any{"100.50"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.Exec(tc.sql, tc.args...); err == nil {
				t.Fatalf("expected insert to fail")
			}
		})
	}
}

func TestSQLDriver_SupportedTypeFamilies(t *testing.T) {
	db := openTypedTestDB(t)
	_, err := db.Exec(`CREATE TABLE type_family (
		pk string PRIMARY KEY DEFAULT uuid(),
		txt text,
		varchar_name varchar,
		i int,
		i64 int64,
		f32 float32,
		f64 float64,
		dec decimal,
		ok bool,
		doc jsonb,
		d date,
		dt datetime,
		ts timestamp,
		tz timestampz,
		tm time,
		external_id uuid,
		price money
	)`)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	externalID := uuid.NewString()
	_, err = db.Exec(`INSERT INTO type_family (
		txt, varchar_name, i, i64, f32, f64, dec, ok, doc, d, dt, ts, tz, tm, external_id, price
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"hello", "world", "42", int64(900), float32(1.5), "2.25", "999999999999999999.01", true,
		`[{"a":1}]`, "2026-05-30", "2026-05-30 10:11:12", "2026-05-30T10:11:12Z", "2026-05-30T10:11:12+05:45", "10:11",
		externalID, "USD 100.50")
	if err != nil {
		t.Fatalf("insert failed: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM type_family WHERE i = 42 AND d >= '2026-05-01' AND tz >= '2026-05-01T00:00:00Z'`).Scan(&count); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one typed row, got %d", count)
	}
}

func TestSQLDriver_DeclaredPrimaryKeyNotID(t *testing.T) {
	db := openTypedTestDB(t)
	if _, err := db.Exec(`CREATE TABLE accounts (
		account_key string PRIMARY KEY,
		id int INDEX,
		email string UNIQUE
	)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO accounts (account_key, id, email) VALUES (?, ?, ?)`, "acct-1", 1, "a@example.com"); err != nil {
		t.Fatalf("insert failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO accounts (account_key, id, email) VALUES (?, ?, ?)`, "acct-1", 2, "b@example.com"); err == nil {
		t.Fatalf("expected duplicate declared primary key to fail")
	}
	var id int
	if err := db.QueryRow(`SELECT id FROM accounts WHERE account_key = ?`, "acct-1").Scan(&id); err != nil {
		t.Fatalf("query by declared primary key failed: %v", err)
	}
	if id != 1 {
		t.Fatalf("unexpected id: %d", id)
	}
}

func TestSQLDriver_TypeFlagsRemainColumnModifiers(t *testing.T) {
	db := openTypedTestDB(t)
	if _, err := db.Exec(`CREATE TABLE docs (
		pk string PRIMARY KEY DEFAULT uuid(),
		id int INDEX,
		bio string FULLTEXT,
		views int VALUEINDEX
	)`); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	for i := 1; i <= 3; i++ {
		_, err := db.Exec(`INSERT INTO docs (id, bio, views) VALUES (?, ?, ?)`, i, fmt.Sprintf("record %d velocity search", i), i*10)
		if err != nil {
			t.Fatalf("insert %d failed: %v", i, err)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM docs WHERE id = 2 AND bio LIKE '%velocity%' AND views >= 20`).Scan(&count); err != nil {
		t.Fatalf("flag query failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one matching flagged row, got %d", count)
	}
}
