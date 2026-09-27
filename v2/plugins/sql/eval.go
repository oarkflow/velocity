package sql

import (
	"context"
	"fmt"
	"strings"

	"github.com/oarkflow/sqlparser/ast"
	"github.com/oarkflow/sqlparser/lexer"

	"github.com/oarkflow/velocity/v2/api"
)

// columnRef reports whether expr is a column reference, returning its bare
// name (e.g. "id") and, for a qualified reference (e.g. "a.id"), the
// "table.col" form as well. Used by resolve to prefer an unambiguous
// qualified lookup on joined rows (see resolveFrom/qualifyRow in join.go)
// while still falling back to the bare name for single-table queries,
// where rows never carry a "table.col" key at all.
func columnRef(expr ast.Expr) (bare, qualified string, ok bool) {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Unquoted, "", true
	case *ast.QualifiedIdent:
		if len(e.Parts) == 0 {
			return "", "", false
		}
		bare = e.Parts[len(e.Parts)-1].Unquoted
		if len(e.Parts) >= 2 {
			qualified = e.Parts[len(e.Parts)-2].Unquoted + "." + bare
		}
		return bare, qualified, true
	default:
		return "", "", false
	}
}

// resolve evaluates expr to a Go value given a row for column lookups and
// ctx/kv for scalar-subquery evaluation. row may be nil when evaluating an
// expression with no column references (e.g. inside INSERT ... VALUES).
//
// Subqueries (SubqueryExpr, InExpr.Subq, ExistsExpr) are evaluated with a
// nil args slice — subqueries cannot themselves contain "?" placeholders
// in this pass. Subqueries ARE correlated: the current row is passed as
// the inner query's outer context (see selectRows' outer parameter), so
// an inner WHERE clause referencing a column not present in its own row
// falls back to the enclosing row (see the b.outer fallback below) —
// this is what makes `WHERE EXISTS (SELECT 1 FROM b WHERE b.x = a.y)`
// correct instead of merely non-erroring. This re-evaluates the subquery
// once per outer row: O(outer_rows * inner_query_cost), same documented
// cost as evalIn's subquery form.
func resolve(ctx context.Context, kv api.KVService, expr ast.Expr, row api.Row, b *binder) (any, error) {
	if sq, ok := expr.(*ast.SubqueryExpr); ok {
		rows, err := selectRows(ctx, kv, sq.Subq, nil, row)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			return nil, nil
		}
		for _, v := range rows[0] {
			return v, nil // scalar subquery: first column of first row
		}
		return nil, nil
	}
	if bare, qualified, ok := columnRef(expr); ok {
		if row == nil {
			return nil, fmt.Errorf("sql: column reference %q not valid in this context", bare)
		}
		// A QUALIFIED reference (e.g. "o.id") is checked against the inner
		// row and then the outer row BEFORE either one's bare fallback —
		// otherwise a qualified reference to an outer alias could
		// wrongly match an inner row's own same-named bare column (e.g.
		// both the outer and inner tables happen to have a column
		// literally named "id"): `i.x = o.id` must never silently
		// resolve "o.id" to the inner row's own "id" just because the
		// inner row happens to have one.
		if qualified != "" {
			if v, present := row[qualified]; present {
				return v, nil
			}
			if b != nil && b.outer != nil {
				if v, present := b.outer[qualified]; present {
					return v, nil
				}
			}
		}
		if v, present := row[bare]; present {
			return v, nil
		}
		// Not found in the current (inner) row at all — fall back to the
		// enclosing query's row, if this is a correlated subquery
		// evaluation. This only applies to a genuinely UNqualified bare
		// reference that isn't in the inner row; a qualified reference
		// was already fully resolved (or not) above.
		if b != nil && b.outer != nil {
			if v, present := b.outer[bare]; present {
				return v, nil
			}
		}
		return nil, nil
	}
	return valueFromExpr(expr, b)
}

// evalExpr evaluates a boolean WHERE-clause expression against row.
// Supports: comparison operators (=, !=/<>, <, >, <=, >=), AND/OR, NOT,
// IS [NOT] NULL, [NOT] LIKE, [NOT] IN (literal list or non-correlated
// subquery), [NOT] BETWEEN. Anything else (function calls, EXISTS)
// returns an error — documented as out of scope for this pass.
func evalExpr(ctx context.Context, kv api.KVService, expr ast.Expr, row api.Row, b *binder) (bool, error) {
	switch e := expr.(type) {
	case *ast.BinaryExpr:
		return evalBinary(ctx, kv, e, row, b)
	case *ast.UnaryExpr:
		if e.Op == lexer.NOT {
			v, err := evalExpr(ctx, kv, e.Expr, row, b)
			if err != nil {
				return false, err
			}
			return !v, nil
		}
		return false, fmt.Errorf("sql: unsupported unary boolean operator %v", e.Op)
	case *ast.IsNullExpr:
		v, err := resolve(ctx, kv, e.Expr, row, b)
		if err != nil {
			return false, err
		}
		isNull := v == nil
		if e.Not {
			return !isNull, nil
		}
		return isNull, nil
	case *ast.LikeExpr:
		return evalLike(ctx, kv, e, row, b)
	case *ast.InExpr:
		return evalIn(ctx, kv, e, row, b)
	case *ast.BetweenExpr:
		return evalBetween(ctx, kv, e, row, b)
	case *ast.ExistsExpr:
		return evalExists(ctx, kv, e, row)
	default:
		return false, fmt.Errorf("sql: unsupported WHERE expression %T", expr)
	}
}

// evalExists evaluates `[NOT] EXISTS (subquery)`, correlated against row
// (the enclosing query's current row) via selectRows' outer parameter —
// see resolve's b.outer fallback for how an inner WHERE clause reaches
// back to row. O(outer_rows * inner_query_cost), same as evalIn's
// subquery form and for the same reason: a real query planner could
// short-circuit on the first matching inner row (this implementation
// does, via selectRows returning as soon as it has any rows — it just
// doesn't hoist the whole subquery out of the row loop when it happens
// to be non-correlated).
func evalExists(ctx context.Context, kv api.KVService, e *ast.ExistsExpr, row api.Row) (bool, error) {
	rows, err := selectRows(ctx, kv, e.Subq, nil, row)
	if err != nil {
		return false, err
	}
	exists := len(rows) > 0
	if e.Not {
		return !exists, nil
	}
	return exists, nil
}

func evalBinary(ctx context.Context, kv api.KVService, e *ast.BinaryExpr, row api.Row, b *binder) (bool, error) {
	switch e.Op {
	case lexer.AND:
		l, err := evalExpr(ctx, kv, e.Left, row, b)
		if err != nil {
			return false, err
		}
		if !l {
			return false, nil
		}
		return evalExpr(ctx, kv, e.Right, row, b)
	case lexer.OR:
		l, err := evalExpr(ctx, kv, e.Left, row, b)
		if err != nil {
			return false, err
		}
		if l {
			return true, nil
		}
		return evalExpr(ctx, kv, e.Right, row, b)
	case lexer.EQ, lexer.NEQ, lexer.LT, lexer.GT, lexer.LTE, lexer.GTE:
		lv, err := resolve(ctx, kv, e.Left, row, b)
		if err != nil {
			return false, err
		}
		rv, err := resolve(ctx, kv, e.Right, row, b)
		if err != nil {
			return false, err
		}
		return compareOp(e.Op, lv, rv), nil
	default:
		return false, fmt.Errorf("sql: unsupported comparison operator %v", e.Op)
	}
}

func compareOp(op lexer.TokenType, lv, rv any) bool {
	if op == lexer.EQ || op == lexer.NEQ {
		eq := valuesEqual(lv, rv)
		if op == lexer.EQ {
			return eq
		}
		return !eq
	}
	cmp, ok := compareValues(lv, rv)
	if !ok {
		return false
	}
	switch op {
	case lexer.LT:
		return cmp < 0
	case lexer.GT:
		return cmp > 0
	case lexer.LTE:
		return cmp <= 0
	case lexer.GTE:
		return cmp >= 0
	}
	return false
}

func valuesEqual(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if fa, aok := numeric(a); aok {
		if fb, bok := numeric(b); bok {
			return fa == fb
		}
	}
	return fmt.Sprint(a) == fmt.Sprint(b)
}

func evalLike(ctx context.Context, kv api.KVService, e *ast.LikeExpr, row api.Row, b *binder) (bool, error) {
	v, err := resolve(ctx, kv, e.Expr, row, b)
	if err != nil {
		return false, err
	}
	p, err := resolve(ctx, kv, e.Pattern, row, b)
	if err != nil {
		return false, err
	}
	s, sok := v.(string)
	pat, pok := p.(string)
	if !sok || !pok {
		return false, nil
	}
	matched := sqlLikeMatch(s, pat)
	if e.Not {
		return !matched, nil
	}
	return matched, nil
}

// sqlLikeMatch implements SQL LIKE semantics: % matches any run of
// characters, _ matches exactly one character. No ESCAPE clause support
// in this first pass.
func sqlLikeMatch(s, pattern string) bool {
	// Convert to a simple regex-free matcher via dynamic programming.
	sr, pr := []rune(s), []rune(pattern)
	n, m := len(sr), len(pr)
	dp := make([][]bool, n+1)
	for i := range dp {
		dp[i] = make([]bool, m+1)
	}
	dp[0][0] = true
	for j := 1; j <= m; j++ {
		if pr[j-1] == '%' {
			dp[0][j] = dp[0][j-1]
		}
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			switch pr[j-1] {
			case '%':
				dp[i][j] = dp[i-1][j] || dp[i][j-1]
			case '_':
				dp[i][j] = dp[i-1][j-1]
			default:
				dp[i][j] = dp[i-1][j-1] && sr[i-1] == pr[j-1]
			}
		}
	}
	return dp[n][m]
}

// evalIn evaluates `expr [NOT] IN (list)` or `expr [NOT] IN (subquery)`.
// The subquery form executes the inner SELECT once per call (i.e. once
// per outer row, since evalIn is invoked from the per-row WHERE
// evaluation) and IS correlated (row is passed as the inner query's outer
// context, see resolve's b.outer fallback) — but not optimized; a real
// query planner would hoist a non-correlated subquery out of the row loop
// and evaluate it once. Documented as a known Big-O cost, not hidden:
// this is O(outer_rows * inner_query_cost) regardless of whether the
// particular subquery is actually correlated.
func evalIn(ctx context.Context, kv api.KVService, e *ast.InExpr, row api.Row, b *binder) (bool, error) {
	v, err := resolve(ctx, kv, e.Expr, row, b)
	if err != nil {
		return false, err
	}
	var list []any
	if e.Subq != nil {
		subRows, err := selectRows(ctx, kv, e.Subq, nil, row)
		if err != nil {
			return false, err
		}
		for _, r := range subRows {
			for _, val := range r {
				list = append(list, val)
				break // IN (subquery) requires exactly one projected column; take it
			}
		}
	} else {
		for _, item := range e.List {
			iv, err := resolve(ctx, kv, item, row, b)
			if err != nil {
				return false, err
			}
			list = append(list, iv)
		}
	}
	found := false
	for _, iv := range list {
		if valuesEqual(v, iv) {
			found = true
			break
		}
	}
	if e.Not {
		return !found, nil
	}
	return found, nil
}

func evalBetween(ctx context.Context, kv api.KVService, e *ast.BetweenExpr, row api.Row, b *binder) (bool, error) {
	v, err := resolve(ctx, kv, e.Expr, row, b)
	if err != nil {
		return false, err
	}
	lo, err := resolve(ctx, kv, e.Lo, row, b)
	if err != nil {
		return false, err
	}
	hi, err := resolve(ctx, kv, e.Hi, row, b)
	if err != nil {
		return false, err
	}
	cmpLo, ok1 := compareValues(v, lo)
	cmpHi, ok2 := compareValues(v, hi)
	between := ok1 && ok2 && cmpLo >= 0 && cmpHi <= 0
	if e.Not {
		return !between, nil
	}
	return between, nil
}

// simpleEqualityOnColumn reports whether expr is exactly `<col> = <value>`
// (in either operand order) for col, letting callers fast-path a
// primary-key point lookup instead of a full table scan.
func simpleEqualityOnColumn(ctx context.Context, kv api.KVService, expr ast.Expr, col string, row api.Row, b *binder) (value any, matched bool, err error) {
	be, ok := expr.(*ast.BinaryExpr)
	if !ok || be.Op != lexer.EQ {
		return nil, false, nil
	}
	if name, ok := columnName(be.Left); ok && strings.EqualFold(name, col) {
		v, err := resolve(ctx, kv, be.Right, row, b)
		return v, err == nil, err
	}
	if name, ok := columnName(be.Right); ok && strings.EqualFold(name, col) {
		v, err := resolve(ctx, kv, be.Left, row, b)
		return v, err == nil, err
	}
	return nil, false, nil
}
