package sql

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/oarkflow/sqlparser/ast"
	"github.com/oarkflow/sqlparser/lexer"

	"github.com/oarkflow/velocity/v2/api"
)

// binder tracks the next positional `?` argument to consume while walking
// an expression tree. Only positional placeholders are supported in this
// first pass — named placeholders (:name, @name, $N) are rejected with a
// clear error rather than silently mis-binding.
//
// outer, when set, is the current row of an ENCLOSING query that a
// correlated subquery's own WHERE/SELECT evaluation may reference (e.g.
// `WHERE EXISTS (SELECT 1 FROM items i WHERE i.order_id = o.id)` — while
// evaluating the inner query's WHERE, `o.id` resolves via outer, not via
// the inner row). It is nil for any non-subquery evaluation and for
// non-correlated subquery evaluation (see selectRows' outer parameter).
type binder struct {
	args  []any
	next  int
	outer api.Row
}

func newBinder(args []any) *binder { return &binder{args: args} }

// withOuter returns b with outer set to row, for evaluating a correlated
// subquery's inner expressions against the enclosing query's current row.
func (b *binder) withOuter(row api.Row) *binder {
	b.outer = row
	return b
}

func (b *binder) nextArg() (any, error) {
	if b.next >= len(b.args) {
		return nil, fmt.Errorf("sql: query has more placeholders than supplied arguments")
	}
	v := b.args[b.next]
	b.next++
	return v, nil
}

// qualifiedName returns the last (rightmost) identifier of a possibly
// dotted name, e.g. "schema.table" -> "table". Table/column qualifiers
// beyond the final segment are ignored in this single-schema engine.
func qualifiedName(q *ast.QualifiedIdent) string {
	if q == nil || len(q.Parts) == 0 {
		return ""
	}
	return q.Parts[len(q.Parts)-1].Unquoted
}

func columnName(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Unquoted, true
	case *ast.QualifiedIdent:
		return qualifiedName(e), true
	default:
		return "", false
	}
}

// literalValue converts a parsed literal token into a Go value.
func literalValue(lit *ast.Literal) (any, error) {
	raw := string(lit.Raw)
	switch lit.Kind {
	case lexer.STRING:
		return unquoteSQLString(raw), nil
	case lexer.INT:
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("sql: invalid integer literal %q: %w", raw, err)
		}
		return n, nil
	case lexer.FLOAT:
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, fmt.Errorf("sql: invalid float literal %q: %w", raw, err)
		}
		return f, nil
	default:
		return raw, nil
	}
}

// unquoteSQLString strips the surrounding single quotes from a STRING
// token's raw bytes and un-escapes doubled quotes (” -> ').
func unquoteSQLString(raw string) string {
	if len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		raw = raw[1 : len(raw)-1]
	}
	return strings.ReplaceAll(raw, "''", "'")
}

// valueFromExpr evaluates a literal/param/simple-unary expression to a Go
// value. It does not resolve column references — callers needing those
// (WHERE evaluation) use evalExpr in eval.go instead.
func valueFromExpr(expr ast.Expr, b *binder) (any, error) {
	switch e := expr.(type) {
	case *ast.Literal:
		return literalValue(e)
	case *ast.NullLit:
		return nil, nil
	case *ast.Param:
		if string(e.Raw) != "?" {
			return nil, fmt.Errorf("sql: only positional '?' placeholders are supported, got %q", string(e.Raw))
		}
		return b.nextArg()
	case *ast.UnaryExpr:
		inner, err := valueFromExpr(e.Expr, b)
		if err != nil {
			return nil, err
		}
		if e.Op == lexer.MINUS {
			return negate(inner)
		}
		return inner, nil
	default:
		return nil, fmt.Errorf("sql: unsupported expression %T in this position", expr)
	}
}

func negate(v any) (any, error) {
	switch n := v.(type) {
	case int64:
		return -n, nil
	case float64:
		return -n, nil
	default:
		return nil, fmt.Errorf("sql: cannot negate non-numeric value %T", v)
	}
}

// numeric coerces an int64/float64 value to float64 for comparison. ok is
// false for non-numeric values.
func numeric(v any) (float64, bool) {
	switch n := v.(type) {
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	case float64:
		return n, true
	default:
		return 0, false
	}
}

// compareValues returns -1/0/1 like strings.Compare, comparing
// numerically when both sides are numeric and as strings otherwise.
// ok is false when the two values are not comparable at all (e.g. nil
// vs. non-nil, or incompatible types) — callers treat "not comparable"
// as "the comparison is false" per standard SQL NULL semantics.
func compareValues(a, b any) (cmp int, ok bool) {
	if a == nil || b == nil {
		return 0, false
	}
	if fa, aok := numeric(a); aok {
		if fb, bok := numeric(b); bok {
			switch {
			case fa < fb:
				return -1, true
			case fa > fb:
				return 1, true
			default:
				return 0, true
			}
		}
	}
	sa, saok := a.(string)
	sb, sbok := b.(string)
	if saok && sbok {
		return strings.Compare(sa, sb), true
	}
	return 0, false
}
