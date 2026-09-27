package comparison

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteEngine wraps a real database/sql + mattn/go-sqlite3 connection as
// a plain key-value store (a single "kv" table), so it can be compared
// directly against VelocityEngine/BoltEngine through the same KVEngine
// interface. WAL journal mode + synchronous=FULL is set explicitly so
// SQLite is fsync'ing on every commit here, matching the durability level
// the other two providers run at — this is a durability-vs-durability
// comparison, not SQLite's fastest unsafe mode against everyone else's
// safest mode.
type SQLiteEngine struct {
	db *sql.DB
}

func NewSQLiteEngine(path string) (*SQLiteEngine, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_synchronous=FULL")
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	db.SetMaxOpenConns(1) // avoid SQLITE_BUSY under this package's sequential benchmark access pattern
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v BLOB)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: create table: %w", err)
	}
	return &SQLiteEngine{db: db}, nil
}

func (e *SQLiteEngine) Put(key, value []byte) error {
	_, err := e.db.Exec(`INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, string(key), value)
	return err
}

func (e *SQLiteEngine) Get(key []byte) ([]byte, bool, error) {
	var v []byte
	err := e.db.QueryRow(`SELECT v FROM kv WHERE k = ?`, string(key)).Scan(&v)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return v, true, nil
}

func (e *SQLiteEngine) Close() error {
	return e.db.Close()
}

var _ KVEngine = (*SQLiteEngine)(nil)
