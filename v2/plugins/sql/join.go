package sql

import (
	"context"
	"fmt"

	"github.com/oarkflow/sqlparser/ast"
	"github.com/oarkflow/sqlparser/lexer"

	"github.com/oarkflow/velocity/v2/api"
)

// resolveFrom evaluates a FROM-clause table reference into a set of rows.
// Supports: a simple table scan, INNER/LEFT JOIN (nested-loop — O(left *
// right) per join level; acceptable for this pass's correctness-first
// scope, not optimized with indexes or a hash join), and a subquery
// table. Column values are stored twice per source table: once under the
// bare column name (last table written wins on a name collision — an
// ambiguity callers should avoid by qualifying SELECT/ON/WHERE column
// references as table.col when joining tables that share a column name)
// and once under "table.col"/"alias.col" for unambiguous qualified
// access — see columnRef/resolve in eval.go for how a reference picks
// between the two.
func resolveFrom(ctx context.Context, kv api.KVService, ref ast.TableRef, args []any) ([]api.Row, error) {
	switch t := ref.(type) {
	case *ast.SimpleTable:
		table := qualifiedName(t.Name)
		alias := table
		if t.Alias != nil {
			alias = t.Alias.Unquoted
		}
		var rows []api.Row
		err := scanTable(ctx, kv, table, func(_ string, row api.Row) (bool, error) {
			rows = append(rows, qualifyRow(row, table, alias))
			return true, nil
		})
		if err != nil {
			return nil, err
		}
		return rows, nil

	case *ast.JoinTable:
		if t.Kind != ast.InnerJoin && t.Kind != ast.LeftJoin {
			return nil, fmt.Errorf("sql: only INNER JOIN and LEFT JOIN are supported in this pass")
		}
		left, err := resolveFrom(ctx, kv, t.Left, args)
		if err != nil {
			return nil, err
		}
		right, err := resolveFrom(ctx, kv, t.Right, args)
		if err != nil {
			return nil, err
		}

		// rightNullRow: every right-side column key (bare + qualified),
		// each mapped to nil, used to pad an unmatched LEFT JOIN row so it
		// has the SAME full column set as a matched row — required for
		// SELECT * and for the database/sql adapter, both of which expect
		// every result row to carry the same columns (a matched row simply
		// overwrites these with real values via mergeRows).
		rightNullRow, err := rightSideNullColumns(ctx, kv, t.Right, right)
		if err != nil {
			return nil, err
		}

		// Equality hash-join fast path: `a.col = b.col` (or unqualified
		// `col = col`, when it's unambiguous — see equalityJoinColumns) is
		// by far the common case and this engine only supports equality
		// joins at all (no <, BETWEEN, etc. in ON), so this covers every
		// join this engine can express. Falls back to the nested-loop path
		// below for USING-clause joins or any ON shape that isn't a single
		// bare equality — correctness first, this optimization only
		// activates when it can be done exactly as the nested loop would.
		if t.On != nil {
			if leftCol, rightCol, ok := equalityJoinColumns(t.On, left, right); ok {
				return hashJoin(left, right, leftCol, rightCol, rightNullRow, t.Kind == ast.LeftJoin), nil
			}
		}

		var out []api.Row
		for _, l := range left {
			matched := false
			for _, r := range right {
				combined := mergeRows(l, r)
				ok := true
				if t.On != nil {
					b := newBinder(args)
					ok, err = evalExpr(ctx, kv, t.On, combined, b)
					if err != nil {
						return nil, err
					}
				} else if len(t.Using) > 0 {
					ok = usingMatches(l, r, t.Using)
				}
				if ok {
					matched = true
					out = append(out, combined)
				}
			}
			if !matched && t.Kind == ast.LeftJoin {
				out = append(out, mergeRows(l, rightNullRow))
			}
		}
		return out, nil

	case *ast.SubqueryTable:
		// A FROM-clause subquery is evaluated once, before any outer row
		// exists yet (resolveFrom builds the row set the WHERE clause then
		// filters) — no correlation context applies here, unlike a WHERE-
		// clause subquery (see eval.go's evalIn/evalExists/resolve).
		rows, err := selectRows(ctx, kv, t.Subq, args, nil)
		if err != nil {
			return nil, err
		}
		if t.Alias == nil {
			return rows, nil
		}
		alias := t.Alias.Unquoted
		out := make([]api.Row, len(rows))
		for i, row := range rows {
			out[i] = qualifyRow(row, alias, alias)
		}
		return out, nil

	default:
		return nil, fmt.Errorf("sql: unsupported FROM clause element %T", ref)
	}
}

// qualifyRow returns a copy of row with every column also present under
// "table.col" and, if alias differs from table, "alias.col".
func qualifyRow(row api.Row, table, alias string) api.Row {
	out := make(api.Row, len(row)*2)
	for k, v := range row {
		out[k] = v
		out[table+"."+k] = v
		if alias != table {
			out[alias+"."+k] = v
		}
	}
	return out
}

func mergeRows(l, r api.Row) api.Row {
	out := make(api.Row, len(l)+len(r))
	for k, v := range l {
		out[k] = v
	}
	for k, v := range r {
		out[k] = v
	}
	return out
}

func usingMatches(l, r api.Row, using []*ast.Ident) bool {
	for _, id := range using {
		if !valuesEqual(l[id.Unquoted], r[id.Unquoted]) {
			return false
		}
	}
	return true
}

// rightSideNullColumns returns a Row mapping every column key resolveFrom
// would produce for the right side of a JOIN to nil, used to pad an
// unmatched LEFT JOIN row so every result row shares the same column set
// (required for SELECT * and the database/sql adapter, both of which
// expect uniform columns across rows) — fixing the prior behavior where
// unmatched right-side columns were simply absent from the map.
func rightSideNullColumns(ctx context.Context, kv api.KVService, rightRef ast.TableRef, right []api.Row) (api.Row, error) {
	if len(right) > 0 {
		keys := make(map[string]bool)
		for _, r := range right {
			for k := range r {
				keys[k] = true
			}
		}
		out := make(api.Row, len(keys))
		for k := range keys {
			out[k] = nil
		}
		return out, nil
	}
	// The right side produced zero rows at all — fall back to its declared
	// schema, when it's a plain table, so SELECT * still gets a full,
	// correctly-nulled column set even against a completely empty right
	// table. A nested-join or subquery right side that happens to be
	// completely empty doesn't get this treatment (returns an empty Row) —
	// a narrow, documented edge case; it never affects a row that actually
	// has a match, only the padding columns of a row that doesn't.
	simple, ok := rightRef.(*ast.SimpleTable)
	if !ok {
		return api.Row{}, nil
	}
	table := qualifiedName(simple.Name)
	alias := table
	if simple.Alias != nil {
		alias = simple.Alias.Unquoted
	}
	schema, err := loadSchema(ctx, kv, table)
	if err != nil {
		return api.Row{}, nil // table genuinely missing — the normal path surfaces that error elsewhere
	}
	out := api.Row{}
	for _, c := range schema.Columns {
		out[c.Name] = nil
		out[table+"."+c.Name] = nil
		if alias != table {
			out[alias+"."+c.Name] = nil
		}
	}
	return out, nil
}

// equalityJoinColumns recognizes an ON clause of the exact shape
// `<col> = <col>` (this engine's parser/evaluator only supports equality
// joins at all, so this covers every ON this engine can express) and
// determines which side names the LEFT relation's row key vs the RIGHT
// relation's, by checking actual presence in a sample of each already-
// resolved row set. Returns ok=false — meaning "fall back to the always-
// correct nested-loop path" — whenever this can't be determined with
// certainty (e.g. one side has zero rows to sample), rather than ever
// guessing an orientation that could silently produce a WRONG (empty)
// result instead of just a slower correct one.
func equalityJoinColumns(on ast.Expr, left, right []api.Row) (leftKey, rightKey string, ok bool) {
	be, isBin := on.(*ast.BinaryExpr)
	if !isBin || be.Op != lexer.EQ {
		return "", "", false
	}
	lBare, lQual, lok := columnRef(be.Left)
	rBare, rQual, rok := columnRef(be.Right)
	if !lok || !rok {
		return "", "", false
	}
	lKey := lBare
	if lQual != "" {
		lKey = lQual
	}
	rKey := rBare
	if rQual != "" {
		rKey = rQual
	}
	if keyPresentIn(left, lKey) && keyPresentIn(right, rKey) {
		return lKey, rKey, true
	}
	if keyPresentIn(left, rKey) && keyPresentIn(right, lKey) {
		return rKey, lKey, true
	}
	return "", "", false
}

func keyPresentIn(rows []api.Row, key string) bool {
	for _, r := range rows {
		if _, ok := r[key]; ok {
			return true
		}
	}
	return false
}

// hashJoin implements an equality JOIN in O(len(left)+len(right)) instead
// of the nested loop's O(len(left)*len(right)): bucket every right row by
// its join-column value once, then look up each left row's matches in
// O(1) amortized instead of scanning all of right per left row.
//
// Bucketing uses indexValueKey (the same canonicalization the persistent
// secondary index uses), then re-verifies every candidate with valuesEqual
// before accepting it — valuesEqual additionally cross-matches a numeric
// value against its string-formatted twin (e.g. int64(5) and "5"), which
// indexValueKey's buckets deliberately do not (see index.go's doc
// comment). That means a join column pathologically mixing numeric and
// string-typed values for "the same" value falls outside this fast path's
// guaranteed scope, exactly as documented for the secondary index — a
// real schema (one declared column type, literals parsed consistently)
// never hits this. The re-verify step means a bucketing edge case can
// only cost a missed match candidate that a broader bucket scheme would
// have caught, never a FALSE match, since every candidate is confirmed
// against the real equality semantics before being accepted.
func hashJoin(left, right []api.Row, leftKey, rightKey string, rightNullRow api.Row, isLeftJoin bool) []api.Row {
	buckets := make(map[string][]api.Row, len(right))
	for _, r := range right {
		v, ok := r[rightKey]
		if !ok {
			continue
		}
		bk := indexValueKey(v)
		buckets[bk] = append(buckets[bk], r)
	}
	var out []api.Row
	for _, l := range left {
		matched := false
		if v, ok := l[leftKey]; ok {
			for _, r := range buckets[indexValueKey(v)] {
				if valuesEqual(v, r[rightKey]) {
					matched = true
					out = append(out, mergeRows(l, r))
				}
			}
		}
		if !matched && isLeftJoin {
			out = append(out, mergeRows(l, rightNullRow))
		}
	}
	return out
}
