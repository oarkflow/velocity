package sqldriver

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"github.com/oarkflow/velocity"
	"github.com/xwb1989/sqlparser"
)

// StmtV2 is a prepared statement that implements driver.Stmt
// bridging sqlparser.Statement to Execution engine nodes.
type StmtV2 struct {
	conn  *Conn
	query string
	stmt  sqlparser.Statement
}

// Close closes the statement.
func (s *StmtV2) Close() error {
	return nil
}

// NumInput returns the number of bind parameters.
func (s *StmtV2) NumInput() int {
	return -1 // Return -1 to allow the sql package to figure it out by passing all args
}

// Exec executes a query that doesn't return rows.
func (s *StmtV2) Exec(args []driver.Value) (driver.Result, error) {
	namedArgs := make([]driver.NamedValue, len(args))
	for i, arg := range args {
		namedArgs[i] = driver.NamedValue{Ordinal: i + 1, Value: arg}
	}
	return s.ExecContext(context.Background(), namedArgs)
}

// Query executes a query that may return rows.
func (s *StmtV2) Query(args []driver.Value) (driver.Rows, error) {
	namedArgs := make([]driver.NamedValue, len(args))
	for i, arg := range args {
		namedArgs[i] = driver.NamedValue{Ordinal: i + 1, Value: arg}
	}
	return s.QueryContext(context.Background(), namedArgs)
}

func (s *StmtV2) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	executor := &ExecutorV2{conn: s.conn}
	return executor.Execute(ctx, s.stmt, args)
}

func (s *StmtV2) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	executor := &ExecutorV2{conn: s.conn}
	return executor.ExecuteSelect(ctx, s.stmt, args)
}

// Result implements driver.Result
type Result struct {
	lastInsertId int64
	rowsAffected int64
}

func (r *Result) LastInsertId() (int64, error) {
	return r.lastInsertId, nil
}

func (r *Result) RowsAffected() (int64, error) {
	return r.rowsAffected, nil
}

// Rows implements driver.Rows
type Rows struct {
	columns []string
	results []velocity.SearchResult
	cursor  int
}

func (r *Rows) Columns() []string {
	if len(r.columns) == 1 && r.columns[0] == "*" {
		if len(r.results) > 0 {
			var data map[string]interface{}
			if err := json.Unmarshal(r.results[0].Value, &data); err == nil {
				var cols []string
				for k := range data {
					cols = append(cols, k)
				}
				r.columns = cols
			} else {
				r.columns = []string{"id", "value"}
			}
		} else {
			r.columns = []string{"id"}
		}
	}
	return r.columns
}

func (r *Rows) Close() error {
	r.cursor = len(r.results)
	return nil
}

func (r *Rows) Next(dest []driver.Value) error {
	if r.cursor >= len(r.results) {
		return fmt.Errorf("EOF")
	}

	res := r.results[r.cursor]
	r.cursor++

	var data map[string]interface{}
	err := json.Unmarshal(res.Value, &data)
	if err != nil {
		data = map[string]interface{}{
			"id":    string(res.Key),
			"value": string(res.Value),
		}
	} else {
		data["_key"] = string(res.Key)
	}

	for i, col := range r.columns {
		val, ok := data[col]
		if !ok {
			dest[i] = nil
		} else {
			dest[i] = val
		}
	}

	return nil
}
