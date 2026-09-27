package sql

import (
	"fmt"
	"sort"

	"github.com/oarkflow/sqlparser/ast"

	"github.com/oarkflow/velocity/v2/api"
)

// applyOrderBy stable-sorts rows by items in order (first item is the
// primary sort key, subsequent items break ties). Rows are compared
// numerically when both sides are numeric and as strings otherwise (see
// compareValues in values.go); a key that isn't comparable between two
// rows (nil vs. non-nil, or incompatible types) is treated as equal at
// that key, deferring to the next ORDER BY item.
func applyOrderBy(rows []api.Row, items []ast.OrderByItem) ([]api.Row, error) {
	if len(items) == 0 {
		return rows, nil
	}
	names := make([]string, len(items))
	for i, it := range items {
		name, ok := columnName(it.Expr)
		if !ok {
			return nil, fmt.Errorf("sql: unsupported ORDER BY expression %T", it.Expr)
		}
		names[i] = name
	}
	sort.SliceStable(rows, func(i, j int) bool {
		for k, it := range items {
			cmp, ok := compareValues(rows[i][names[k]], rows[j][names[k]])
			if !ok || cmp == 0 {
				continue
			}
			if it.Desc {
				return cmp > 0
			}
			return cmp < 0
		}
		return false
	})
	return rows, nil
}

// applyLimit applies LIMIT [OFFSET] to an already-ordered/filtered row
// set.
func applyLimit(rows []api.Row, lim *ast.LimitClause, b *binder) ([]api.Row, error) {
	if lim == nil {
		return rows, nil
	}
	count := int64(len(rows))
	var offset int64
	if lim.Count != nil {
		v, err := valueFromExpr(lim.Count, b)
		if err != nil {
			return nil, err
		}
		n, ok := numeric(v)
		if !ok {
			return nil, fmt.Errorf("sql: LIMIT value must be numeric")
		}
		count = int64(n)
	}
	if lim.Offset != nil {
		v, err := valueFromExpr(lim.Offset, b)
		if err != nil {
			return nil, err
		}
		n, ok := numeric(v)
		if !ok {
			return nil, fmt.Errorf("sql: OFFSET value must be numeric")
		}
		offset = int64(n)
	}
	if offset < 0 {
		offset = 0
	}
	if offset >= int64(len(rows)) {
		return []api.Row{}, nil
	}
	end := offset + count
	if count < 0 || end > int64(len(rows)) {
		end = int64(len(rows))
	}
	return rows[offset:end], nil
}
