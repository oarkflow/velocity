package sqldriver

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/oarkflow/sqlparser"
	"github.com/oarkflow/velocity"
)

// StmtV2 is a prepared statement that implements driver.Stmt
// bridging sqlparser.Statement to Execution engine nodes.
type StmtV2 struct {
	conn       *Conn
	query      string
	cacheSQL   string
	stmt       sqlparser.Statement
	parser     *sqlparser.Parser
	paramOrder map[int32]int
	fastInsert *simpleInsertPlan
	ddlFlags   map[string]velocityColumnFlags
}

// Close closes the statement.
func (s *StmtV2) Close() error {
	return nil
}

// NumInput returns the number of bind parameters.
func (s *StmtV2) NumInput() int {
	if s.fastInsert != nil {
		return len(s.fastInsert.paramOrdinals)
	}
	if s.paramOrder != nil {
		return len(s.paramOrder)
	}
	return -1 // Return -1 to allow the sql package to figure it out by passing all args
}

func (s *StmtV2) CheckNamedValue(nv *driver.NamedValue) error {
	return checkCommonNamedValue(nv.Value)
}

func checkCommonNamedValue(value any) error {
	switch value.(type) {
	case nil,
		bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64,
		string,
		[]byte,
		time.Time:
		return nil
	default:
		return driver.ErrSkip
	}
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
	if s.fastInsert != nil {
		return s.fastInsert.Exec(ctx, s.conn, args)
	}
	executor := &ExecutorV2{conn: s.conn, paramOrder: s.paramOrder, rawSQL: s.query, cacheSQL: s.cacheSQL, ddlFlags: s.ddlFlags}
	return executor.Execute(ctx, s.stmt, args)
}

func (s *StmtV2) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	executor := &ExecutorV2{conn: s.conn, paramOrder: s.paramOrder, rawSQL: s.query, cacheSQL: s.cacheSQL, ddlFlags: s.ddlFlags}
	return executor.ExecuteSelect(ctx, s.stmt, args)
}

// Result implements driver.Result
type Result struct {
	lastInsertId int64
	rowsAffected int64
}

type singleInsertResult int64

func (r singleInsertResult) LastInsertId() (int64, error) {
	return int64(r), nil
}

func (r singleInsertResult) RowsAffected() (int64, error) {
	return 1, nil
}

func (r Result) LastInsertId() (int64, error) {
	return r.lastInsertId, nil
}

func (r Result) RowsAffected() (int64, error) {
	return r.rowsAffected, nil
}

// Rows implements driver.Rows
type Rows struct {
	columns    []string
	schemaCols []string
	results    []velocity.SearchResult
	rowMaps    []Row
	cursor     int
}

func (r *Rows) Clone() *Rows {
	if r == nil {
		return nil
	}
	out := &Rows{
		columns:    append([]string(nil), r.columns...),
		schemaCols: append([]string(nil), r.schemaCols...),
		results:    make([]velocity.SearchResult, 0, len(r.results)),
		rowMaps:    make([]Row, 0, len(r.rowMaps)),
	}
	for _, res := range r.results {
		highlights := make(map[string][]string, len(res.Highlights))
		for field, snippets := range res.Highlights {
			highlights[field] = append([]string(nil), snippets...)
		}
		out.results = append(out.results, velocity.SearchResult{
			Key:        append([]byte(nil), res.Key...),
			Value:      append([]byte(nil), res.Value...),
			Score:      res.Score,
			Highlights: highlights,
		})
	}
	for _, row := range r.rowMaps {
		next := make(Row, len(row))
		for k, v := range row {
			next[k] = v
		}
		out.rowMaps = append(out.rowMaps, next)
	}
	return out
}

func (r *Rows) CacheView() *Rows {
	if r == nil {
		return nil
	}
	return &Rows{
		columns:    r.columns,
		schemaCols: r.schemaCols,
		results:    r.results,
		rowMaps:    r.rowMaps,
	}
}

func (r *Rows) RowCount() int {
	if r == nil {
		return 0
	}
	if len(r.rowMaps) > 0 {
		return len(r.rowMaps)
	}
	return len(r.results)
}

func (r *Rows) EstimatedSize() int64 {
	if r == nil {
		return 0
	}
	size := int64(64 + len(r.columns)*16 + len(r.schemaCols)*16)
	for _, col := range r.columns {
		size += int64(len(col))
	}
	for _, col := range r.schemaCols {
		size += int64(len(col))
	}
	for _, res := range r.results {
		size += int64(len(res.Key) + len(res.Value) + 32)
	}
	for _, row := range r.rowMaps {
		size += int64(32 + len(row)*24)
		for k, v := range row {
			size += int64(len(k) + len(fmt.Sprint(v)))
		}
	}
	return size
}

func (r *Rows) Columns() []string {
	if len(r.columns) == 1 && r.columns[0] == "*" {
		if len(r.rowMaps) > 0 {
			var cols []string
			for k := range r.rowMaps[0] {
				cols = append(cols, k)
			}
			sort.Strings(cols)
			r.columns = cols
			return r.columns
		}
		if len(r.schemaCols) > 0 {
			r.columns = append([]string(nil), r.schemaCols...)
			return r.columns
		}
		if len(r.results) > 0 {
			var data map[string]interface{}
			if err := json.Unmarshal(r.results[0].Value, &data); err == nil {
				var cols []string
				for k := range data {
					cols = append(cols, k)
				}
				sort.Strings(cols)
				r.columns = cols
			} else {
				r.columns = []string{"id", "value"}
			}
		} else {
			r.columns = nil
		}
	}
	return r.columns
}

func (r *Rows) Close() error {
	r.cursor = len(r.rowMaps)
	if len(r.results) > r.cursor {
		r.cursor = len(r.results)
	}
	return nil
}

func (r *Rows) Next(dest []driver.Value) error {
	if len(r.rowMaps) > 0 {
		if r.cursor >= len(r.rowMaps) {
			return io.EOF
		}
		row := r.rowMaps[r.cursor]
		r.cursor++
		for i, col := range r.columns {
			val, ok := row[col]
			if !ok {
				dest[i] = nil
			} else {
				dest[i] = val
			}
		}
		return nil
	}

	if r.cursor >= len(r.results) {
		return io.EOF
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
