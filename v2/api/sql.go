package api

import "context"

// Row is a single result row keyed by column name.
type Row map[string]any

// SQLEngine is the surface plugins/sql exposes, backing a database/sql
// driver (ported from v1's pkg/sqldriver) that runs atop KVService instead
// of the root DB type directly — decoupling the SQL layer from any one
// storage implementation.
type SQLEngine interface {
	Exec(ctx context.Context, query string, args ...any) (rowsAffected int64, err error)
	Query(ctx context.Context, query string, args ...any) (rows []Row, err error)
	Begin(ctx context.Context) (Tx, error)
}

// Tx is a SQL transaction.
type Tx interface {
	Exec(ctx context.Context, query string, args ...any) (int64, error)
	Query(ctx context.Context, query string, args ...any) ([]Row, error)
	Commit() error
	Rollback() error
}
