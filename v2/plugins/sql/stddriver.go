package sql

import (
	"context"
	stdsql "database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"sort"

	sqlparser "github.com/oarkflow/sqlparser"
	"github.com/oarkflow/sqlparser/ast"
	"github.com/oarkflow/velocity/v2/api"
)

// Open returns a *sql.DB backed by engine, so callers get the full
// stdlib database/sql API (Query/Exec/Prepare/QueryRow/Scan, connection
// pooling, etc.) atop the SAME Engine used elsewhere — no SQL execution
// logic is duplicated here, this file only translates driver.* calls into
// calls on the existing Engine.
//
// This deliberately does NOT use sql.Register/sql.Open("velocity", dsn):
// database/sql's global registry maps one driver NAME to one
// driver.Driver value, but each velocity deployment has its own *Engine
// instance (there is no DSN string that could identify "which Engine" —
// it's an in-process Go value, not a network address). sql.OpenDB with a
// driver.Connector that captures engine by closure is the standard,
// documented way to adapt a driver that needs a runtime-constructed
// dependency instead of a DSN — see database/sql/driver's Connector doc.
func Open(engine *Engine) (*stdsql.DB, error) {
	if engine == nil {
		return nil, fmt.Errorf("sql: Open requires a non-nil Engine")
	}
	return stdsql.OpenDB(&velocityConnector{engine: engine}), nil
}

type velocityConnector struct{ engine *Engine }

func (c *velocityConnector) Connect(context.Context) (driver.Conn, error) {
	return &velocityConn{engine: c.engine}, nil
}

// Driver satisfies driver.Connector; the returned driver.Driver's Open
// only works because it closes over the same engine — it is not
// separately usable via sql.Open("velocity", ...), which has no way to
// supply an *Engine through a DSN string. Use Open(engine) instead.
func (c *velocityConnector) Driver() driver.Driver {
	return &velocityDriver{engine: c.engine}
}

var _ driver.Connector = (*velocityConnector)(nil)

type velocityDriver struct{ engine *Engine }

func (d *velocityDriver) Open(string) (driver.Conn, error) {
	if d.engine == nil {
		return nil, fmt.Errorf("sql: this driver has no bound Engine; use plugins/sql.Open(engine) instead of database/sql.Open with a DSN")
	}
	return &velocityConn{engine: d.engine}, nil
}

var _ driver.Driver = (*velocityDriver)(nil)

// velocityConn adapts one Engine (there is no real "connection" to open —
// the Engine is already an in-process handle — so every Conn just shares
// it) to driver.Conn, plus ExecerContext/QueryerContext so database/sql
// can skip the Prepare round-trip for one-shot calls.
//
// database/sql routes ExecContext/QueryContext calls made on a *sql.Tx
// through this SAME driver.Conn (not through the driver.Tx returned by
// Begin — driver.Tx is Commit/Rollback ONLY, per its doc comment). So
// currentTx tracks whether a transaction is active on this connection;
// when set, Exec/Query below run against it (giving real per-Tx
// commit/rollback semantics) instead of against the engine directly.
// database/sql serializes all use of one driver.Conn to a single
// goroutine at a time, so this field needs no locking of its own.
type velocityConn struct {
	engine    *Engine
	currentTx api.Tx
}

func (c *velocityConn) Prepare(query string) (driver.Stmt, error) {
	return &velocityStmt{conn: c, query: query}, nil
}

func (c *velocityConn) Close() error { return nil }

func (c *velocityConn) Begin() (driver.Tx, error) {
	if c.currentTx != nil {
		return nil, fmt.Errorf("sql: a transaction is already active on this connection")
	}
	tx, err := c.engine.Begin(context.Background())
	if err != nil {
		return nil, err
	}
	c.currentTx = tx
	return &velocityTx{conn: c, tx: tx}, nil
}

func (c *velocityConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if c.currentTx != nil {
		n, err := c.currentTx.Exec(ctx, query, namedValuesToArgs(args)...)
		if err != nil {
			return nil, err
		}
		return execResult{rows: n}, nil
	}
	return execWithEngine(ctx, c.engine, query, namedValuesToArgs(args))
}

func (c *velocityConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if c.currentTx != nil {
		rows, err := c.currentTx.Query(ctx, query, namedValuesToArgs(args)...)
		if err != nil {
			return nil, err
		}
		return &velocityRows{cols: columnOrder(rows), rows: rows}, nil
	}
	return queryWithEngine(ctx, c.engine, query, namedValuesToArgs(args))
}

var (
	_ driver.Conn           = (*velocityConn)(nil)
	_ driver.ExecerContext  = (*velocityConn)(nil)
	_ driver.QueryerContext = (*velocityConn)(nil)
)

// velocityStmt is a deferred-execution wrapper: Prepare doesn't actually
// validate or plan anything ahead of time (Engine has no separate
// prepare step), it just remembers the query text. Exec/Query route
// through the owning conn so an active transaction (see velocityConn) is
// respected the same way ExecContext/QueryContext respect it.
type velocityStmt struct {
	conn  *velocityConn
	query string
}

func (s *velocityStmt) Close() error { return nil }

// NumInput returns -1 (unknown) rather than parsing the query for '?'
// count — database/sql then skips its own arg-count validation and lets
// Engine.Exec/Query's binder report a clear "more placeholders than
// supplied arguments" error itself if the caller gets it wrong.
func (s *velocityStmt) NumInput() int { return -1 }

func (s *velocityStmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.conn.ExecContext(context.Background(), s.query, valuesToNamedValues(args))
}

func (s *velocityStmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.conn.QueryContext(context.Background(), s.query, valuesToNamedValues(args))
}

var _ driver.Stmt = (*velocityStmt)(nil)

func namedValuesToArgs(nv []driver.NamedValue) []any {
	out := make([]any, len(nv))
	for i, v := range nv {
		out[i] = v.Value
	}
	return out
}

func valuesToArgs(v []driver.Value) []any {
	out := make([]any, len(v))
	for i, x := range v {
		out[i] = x
	}
	return out
}

func valuesToNamedValues(v []driver.Value) []driver.NamedValue {
	out := make([]driver.NamedValue, len(v))
	for i, x := range v {
		out[i] = driver.NamedValue{Ordinal: i + 1, Value: x}
	}
	return out
}

func execWithEngine(ctx context.Context, engine *Engine, query string, args []any) (driver.Result, error) {
	n, err := engine.Exec(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return execResult{rows: n}, nil
}

type execResult struct{ rows int64 }

// LastInsertId is not supported: Engine's auto-increment path (see
// execInsert in exec.go) writes the generated value into the inserted
// row itself rather than returning it out-of-band, and composite/
// multi-row inserts have no single well-defined "last" id anyway. Callers
// needing the generated key should SELECT it back by whatever column(s)
// they inserted, or use a RETURNING-style follow-up query once/if that's
// added to the parser.
func (r execResult) LastInsertId() (int64, error) {
	return 0, fmt.Errorf("sql: LastInsertId is not supported by this driver — read the generated key back via a query instead")
}

func (r execResult) RowsAffected() (int64, error) { return r.rows, nil }

func queryWithEngine(ctx context.Context, engine *Engine, query string, args []any) (driver.Rows, error) {
	rows, err := engine.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return &velocityRows{cols: resultColumnOrder(query, rows), rows: rows}, nil
}

// resultColumnOrder determines the column order database/sql callers see
// via Columns()/Scan(). SQL semantics require this to match the SELECT
// clause's declared order (e.g. "SELECT id, name" must yield id before
// name) — api.Row is a plain map[string]any with no order of its own, so
// deriving column order from it directly (as an earlier version of this
// file did via columnOrder below) is a real bug: Go map iteration order
// is randomized per-run, so which column landed at index 0 was
// nondeterministic and could silently transpose values into the wrong
// Scan() targets.
//
// For an explicit (non-"*") column list, re-parsing the query with the
// same parser the engine itself uses gives the authoritative order. For
// "SELECT *" (or if re-parsing fails for any reason — it never should,
// since engine.Query just parsed the same string successfully), this
// falls back to columnOrder's map-derived order, made deterministic by
// sorting alphabetically — not necessarily the table's schema-defined
// order, but at least stable across calls, which map iteration was not.
func resultColumnOrder(query string, rows []api.Row) []string {
	parseMu.Lock()
	stmt, parseErr := sqlparser.ParseStatement(query)
	parseMu.Unlock()
	if parseErr == nil {
		if sel, ok := stmt.(*ast.SelectStmt); ok {
			if cols, ok := explicitColumnNames(sel.Columns); ok {
				return cols
			}
		}
	}
	return columnOrder(rows)
}

// explicitColumnNames returns the output column names for a fully
// explicit (no "*") SELECT column list, in declared order, mirroring how
// projectColumns (exec.go) names each projected column — an alias
// overrides the expression's own name. ok is false if any column is "*"
// or has an unsupported expression shape, so the caller falls back.
func explicitColumnNames(cols []ast.SelectColumn) ([]string, bool) {
	names := make([]string, 0, len(cols))
	for _, sc := range cols {
		if sc.Star {
			return nil, false
		}
		name, ok := columnName(sc.Expr)
		if !ok {
			return nil, false
		}
		if sc.Alias != nil {
			name = sc.Alias.Unquoted
		}
		names = append(names, name)
	}
	return names, true
}

// columnOrder derives a column order from a []api.Row (a plain map has
// none of its own) by taking the union of keys, sorted alphabetically for
// determinism, across all rows — correct as long as every row in one
// result set has the same columns, which is always true for this
// engine's SELECT execution (projectColumns/groupAndAggregate apply one
// column list to every row). Used only as the "SELECT *" fallback —
// prefer resultColumnOrder, which returns the SQL-semantics-correct order
// for an explicit column list.
func columnOrder(rows []api.Row) []string {
	seen := make(map[string]bool)
	var cols []string
	for _, r := range rows {
		for k := range r {
			if !seen[k] {
				seen[k] = true
				cols = append(cols, k)
			}
		}
	}
	sort.Strings(cols)
	return cols
}

type velocityRows struct {
	cols []string
	rows []api.Row
	idx  int
}

func (r *velocityRows) Columns() []string { return r.cols }
func (r *velocityRows) Close() error      { return nil }

func (r *velocityRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	row := r.rows[r.idx]
	r.idx++
	for i, c := range r.cols {
		dest[i] = normalizeDriverValue(row[c])
	}
	return nil
}

// normalizeDriverValue coerces an api.Row value into one of the limited
// set of types database/sql/driver.Value accepts (int64, float64, bool,
// []byte, string, time.Time, or nil) — e.g. a bare Go `int` (as opposed
// to int64) would otherwise make database/sql reject the value at Scan
// time with a type error, even though it's a perfectly ordinary integer.
func normalizeDriverValue(v any) driver.Value {
	switch n := v.(type) {
	case int:
		return int64(n)
	case nil, int64, float64, bool, []byte, string:
		return v
	default:
		return fmt.Sprint(n)
	}
}

var _ driver.Rows = (*velocityRows)(nil)

// velocityTx clears conn.currentTx on Commit/Rollback so a later
// Begin/ExecContext on the same *sql.Conn (database/sql pools and reuses
// driver.Conn values across transactions) doesn't keep routing into a
// finished transaction.
type velocityTx struct {
	conn *velocityConn
	tx   api.Tx
}

func (t *velocityTx) Commit() error {
	t.conn.currentTx = nil
	return t.tx.Commit()
}

func (t *velocityTx) Rollback() error {
	t.conn.currentTx = nil
	return t.tx.Rollback()
}

var _ driver.Tx = (*velocityTx)(nil)
