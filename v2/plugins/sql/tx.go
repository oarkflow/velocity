package sql

import (
	"context"
	"errors"
	"fmt"
	"sync"

	sqlparser "github.com/oarkflow/sqlparser"
	"github.com/oarkflow/sqlparser/ast"

	"github.com/oarkflow/velocity/v2/api"
)

// tx implements api.Tx. Writes made through Exec are applied to the
// underlying KVService immediately (so Query within the same Tx sees its
// own uncommitted writes "for free," since it reads the same store), while
// a compensating undo log is recorded for every mutation. Commit simply
// discards that log (the writes are already durable); Rollback replays it
// in reverse to restore prior state.
//
// This gives real, testable commit/rollback semantics, but — because
// writes land in the shared KVService immediately rather than being
// buffered until Commit — it does NOT provide isolation from concurrent
// readers/writers outside this Tx: another caller can observe a change
// before this transaction commits, and two concurrent Tx mutating the same
// rows are not serialized against each other. That is an explicit,
// documented limitation of this first pass, not an oversight.
type tx struct {
	mu   sync.Mutex
	eng  *Engine
	undo []undoFn
	done bool
}

func newTx(eng *Engine) *tx {
	return &tx{eng: eng}
}

var _ api.Tx = (*tx)(nil)

func (t *tx) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return 0, errors.New("sql: transaction already committed or rolled back")
	}
	parseMu.Lock()
	stmt, err := sqlparser.ParseStatement(query)
	if err != nil {
		parseMu.Unlock()
		return 0, fmt.Errorf("sql: parse error: %w", err)
	}
	n, undos, err := execStatement(ctx, t.eng.kv, stmt, args)
	parseMu.Unlock()
	if err != nil {
		return 0, err
	}
	t.undo = append(t.undo, undos...)
	return n, nil
}

func (t *tx) Query(ctx context.Context, query string, args ...any) ([]api.Row, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return nil, errors.New("sql: transaction already committed or rolled back")
	}
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
	return selectRows(ctx, t.eng.kv, sel, args, nil)
}

func (t *tx) Commit() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return errors.New("sql: transaction already committed or rolled back")
	}
	t.done = true
	t.undo = nil
	return nil
}

func (t *tx) Rollback() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return errors.New("sql: transaction already committed or rolled back")
	}
	t.done = true
	ctx := context.Background()
	var firstErr error
	for i := len(t.undo) - 1; i >= 0; i-- {
		if t.undo[i] == nil {
			continue
		}
		if err := t.undo[i](ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	t.undo = nil
	return firstErr
}
