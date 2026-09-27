package sql

import (
	"fmt"
	"strings"

	"github.com/oarkflow/sqlparser/ast"

	"github.com/oarkflow/velocity/v2/api"
)

// isAggregateFunc reports whether name is one of the supported aggregate
// functions.
func isAggregateFunc(name string) bool {
	switch strings.ToUpper(name) {
	case "COUNT", "SUM", "AVG", "MIN", "MAX":
		return true
	}
	return false
}

// selectHasAggregate reports whether stmt's column list references any
// aggregate function call, which triggers grouped/aggregate evaluation
// even without an explicit GROUP BY (a single implicit group over all
// rows, matching standard SQL behavior for e.g. `SELECT COUNT(*) FROM t`).
func selectHasAggregate(stmt *ast.SelectStmt) bool {
	for _, c := range stmt.Columns {
		if fc, ok := c.Expr.(*ast.FuncCall); ok && isAggregateFunc(qualifiedName(fc.Name)) {
			return true
		}
	}
	return false
}

// groupAndAggregate groups rows by groupCols (in first-seen order) and
// projects cols against each group, evaluating any aggregate function
// calls over that group's rows and any plain column reference against the
// group's representative (first) row.
func groupAndAggregate(rows []api.Row, groupCols []string, cols []ast.SelectColumn) ([]api.Row, error) {
	type group struct {
		rep  api.Row
		rows []api.Row
	}
	groups := make(map[string]*group)
	var order []string

	for _, row := range rows {
		parts := make([]string, len(groupCols))
		for i, gc := range groupCols {
			parts[i] = fmt.Sprint(row[gc])
		}
		key := strings.Join(parts, "\x1f")
		g, ok := groups[key]
		if !ok {
			g = &group{rep: row}
			groups[key] = g
			order = append(order, key)
		}
		g.rows = append(g.rows, row)
	}
	// No rows at all: COUNT(*) etc still need to report over the (empty)
	// implicit single group when there's no GROUP BY clause, matching
	// standard SQL (`SELECT COUNT(*) FROM empty_table` returns one row
	// with 0, not zero rows).
	if len(rows) == 0 && len(groupCols) == 0 {
		groups[""] = &group{rep: api.Row{}}
		order = append(order, "")
	}

	out := make([]api.Row, 0, len(order))
	for _, key := range order {
		g := groups[key]
		outRow := api.Row{}
		for _, gc := range groupCols {
			outRow[gc] = g.rep[gc]
		}
		for _, sc := range cols {
			if sc.Star {
				return nil, fmt.Errorf("sql: SELECT * is not supported together with GROUP BY/aggregates")
			}
			fc, ok := sc.Expr.(*ast.FuncCall)
			if !ok {
				name, ok2 := columnName(sc.Expr)
				if !ok2 {
					return nil, fmt.Errorf("sql: unsupported expression %T in GROUP BY/aggregate SELECT list", sc.Expr)
				}
				outName := name
				if sc.Alias != nil {
					outName = sc.Alias.Unquoted
				}
				outRow[outName] = g.rep[name]
				continue
			}
			fname := qualifiedName(fc.Name)
			if !isAggregateFunc(fname) {
				return nil, fmt.Errorf("sql: unsupported function %q in SELECT list", fname)
			}
			val, err := computeAggregate(fname, fc, g.rows)
			if err != nil {
				return nil, err
			}
			outName := defaultAggName(fname, fc)
			if sc.Alias != nil {
				outName = sc.Alias.Unquoted
			}
			outRow[outName] = val
		}
		out = append(out, outRow)
	}
	return out, nil
}

func defaultAggName(fn string, fc *ast.FuncCall) string {
	inner := "*"
	if !fc.Star && len(fc.Args) == 1 {
		if n, ok := columnName(fc.Args[0]); ok {
			inner = n
		}
	}
	return strings.ToUpper(fn) + "(" + inner + ")"
}

func computeAggregate(fn string, fc *ast.FuncCall, rows []api.Row) (any, error) {
	switch strings.ToUpper(fn) {
	case "COUNT":
		if fc.Star {
			return int64(len(rows)), nil
		}
		if len(fc.Args) != 1 {
			return nil, fmt.Errorf("sql: COUNT expects exactly one argument or *")
		}
		name, ok := columnName(fc.Args[0])
		if !ok {
			return nil, fmt.Errorf("sql: unsupported COUNT argument")
		}
		var n int64
		for _, r := range rows {
			if r[name] != nil {
				n++
			}
		}
		return n, nil

	case "SUM", "AVG", "MIN", "MAX":
		if len(fc.Args) != 1 {
			return nil, fmt.Errorf("sql: %s expects exactly one argument", fn)
		}
		name, ok := columnName(fc.Args[0])
		if !ok {
			return nil, fmt.Errorf("sql: unsupported %s argument", fn)
		}
		var vals []float64
		for _, r := range rows {
			if v, ok := numeric(r[name]); ok {
				vals = append(vals, v)
			}
		}
		switch strings.ToUpper(fn) {
		case "SUM":
			var s float64
			for _, v := range vals {
				s += v
			}
			return s, nil
		case "AVG":
			if len(vals) == 0 {
				return nil, nil
			}
			var s float64
			for _, v := range vals {
				s += v
			}
			return s / float64(len(vals)), nil
		case "MIN":
			if len(vals) == 0 {
				return nil, nil
			}
			m := vals[0]
			for _, v := range vals[1:] {
				if v < m {
					m = v
				}
			}
			return m, nil
		case "MAX":
			if len(vals) == 0 {
				return nil, nil
			}
			m := vals[0]
			for _, v := range vals[1:] {
				if v > m {
					m = v
				}
			}
			return m, nil
		}
	}
	return nil, fmt.Errorf("sql: unsupported aggregate function %s", fn)
}
