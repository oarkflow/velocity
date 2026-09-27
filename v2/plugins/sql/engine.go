package sql

import (
	"context"
	"fmt"
	"sync"

	sqlparser "github.com/oarkflow/sqlparser"
	"github.com/oarkflow/sqlparser/ast"

	"github.com/oarkflow/velocity/v2/api"
)

// parseMu serializes every parse-then-execute call in this package
// (Engine.Exec/Query, tx.Exec/Query, and stddriver.go's resultColumnOrder
// helper — every direct caller of sqlparser.ParseStatement).
//
// This exists because github.com/oarkflow/sqlparser's ParseStatement pulls
// a *Parser from a sync.Pool, allocates the returned AST from that
// Parser's own arena, and returns the Parser to the pool IMMEDIATELY —
// before the caller has read anything from the returned ast.Statement (see
// parser.ParseStatement in that module: `parserPool.Put(p)` runs before
// `return stmt, err`). A concurrent ParseStatement call on another
// goroutine can then draw that exact same pooled Parser and reset its
// arena while this goroutine is still reading the first call's AST —
// silently corrupting it. This was confirmed directly, not theorized: a
// concurrency stress test produced a corrupted INSERT VALUES slice header
// on one goroutine and a slice-index panic on another, both while
// concurrently calling Engine.Exec/Query, with no other shared mutable
// state in this package that could explain it.
//
// The unsafe window spans the ENTIRE time an AST is being read — for a
// SELECT, that's the whole selectRows/selectRowsOne walk, including every
// subquery it evaluates (subqueries reuse the same already-parsed AST
// tree, so they don't call ParseStatement again — only the five call
// sites above do) — not just the parse call itself, so only serializing
// ParseStatement itself would NOT be sufficient; each guarded section
// below covers parse-through-execute as one atomic unit. This is a real
// upstream correctness bug in the parser library, not a design choice —
// remove this mutex if that's ever fixed upstream (e.g. by returning the
// Parser to the pool only after the caller is done with the AST, or by
// giving each call its own unpooled Parser).
var parseMu sync.Mutex

// Engine implements api.SQLEngine atop an api.KVService. It has no
// dependency on any concrete storage engine — only on the KVService
// interface — so it runs unmodified against any KV plugin a manifest
// wires it to.
type Engine struct {
	kv api.KVService
}

// NewEngine constructs an Engine backed by kv.
func NewEngine(kv api.KVService) *Engine {
	return &Engine{kv: kv}
}

var _ api.SQLEngine = (*Engine)(nil)

func (e *Engine) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	parseMu.Lock()
	defer parseMu.Unlock()
	stmt, err := sqlparser.ParseStatement(query)
	if err != nil {
		return 0, fmt.Errorf("sql: parse error: %w", err)
	}
	n, _, err := execStatement(ctx, e.kv, stmt, args)
	return n, err
}

func (e *Engine) Query(ctx context.Context, query string, args ...any) ([]api.Row, error) {
	parseMu.Lock()
	defer parseMu.Unlock()
	stmt, err := sqlparser.ParseStatement(query)
	if err != nil {
		return nil, fmt.Errorf("sql: parse error: %w", err)
	}
	sel, ok := stmt.(*ast.SelectStmt)
	if !ok {
		return nil, fmt.Errorf("sql: Query only accepts SELECT statements, got %T", stmt)
	}
	return selectRows(ctx, e.kv, sel, args, nil)
}

func (e *Engine) Begin(_ context.Context) (api.Tx, error) {
	return newTx(e), nil
}

// execStatement dispatches one non-SELECT statement to its handler and
// normalizes the per-row-count undo functions each handler returns into a
// single slice, so both Engine.Exec (which discards undo) and Tx.Exec
// (which records it) share one code path.
func execStatement(ctx context.Context, kv api.KVService, stmt ast.Statement, args []any) (int64, []undoFn, error) {
	switch s := stmt.(type) {
	case *ast.CreateTableStmt:
		n, undo, err := execCreateTable(ctx, kv, s)
		if err != nil {
			return 0, nil, err
		}
		return n, []undoFn{undo}, nil
	case *ast.InsertStmt:
		return exec3(execInsert(ctx, kv, s, args))
	case *ast.UpdateStmt:
		return exec3(execUpdate(ctx, kv, s, args))
	case *ast.DeleteStmt:
		return exec3(execDelete(ctx, kv, s, args))
	case *ast.SelectStmt:
		return 0, nil, fmt.Errorf("sql: use Query, not Exec, for SELECT statements")
	default:
		return 0, nil, fmt.Errorf("sql: unsupported statement type %T in this first pass", stmt)
	}
}

func exec3(n int64, undos []undoFn, err error) (int64, []undoFn, error) {
	return n, undos, err
}
