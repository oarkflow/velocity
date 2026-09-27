package sql

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/oarkflow/sqlparser/ast"
	"github.com/oarkflow/sqlparser/lexer"

	"github.com/oarkflow/velocity/v2/api"
)

// Secondary indexing: every declared column of every table automatically
// gets an equality index, maintained by execInsert/execUpdate/execDelete.
// This is the "automatic" choice documented as a deliberate simplification
// over a hint-based (CREATE INDEX / column-annotation) scheme: it costs one
// extra KV entry per column per row on every write, but guarantees the
// index can never go stale from a caller forgetting to declare one, and
// keeps every write path's maintenance logic identical regardless of which
// columns end up being queried later. Range/LIKE/BETWEEN/inequality
// operators are NOT indexed — only exact equality — and remain on the
// existing full-scan path, which stays correct (just not fast) for them.
//
// Correctness note on value typing: the index bucket key is derived from
// indexValueKey, which normalizes numeric Go types (int64/float64) to one
// canonical form but keeps strings distinct from numbers. valuesEqual (see
// eval.go) additionally treats a numeric value and its string-formatted
// twin (e.g. int64(5) and "5") as equal via a fmt.Sprint fallback — the
// index does NOT replicate that fallback. This is an accepted, documented
// scope boundary: a column whose stored values consistently use one Go
// type per the table's declared literal syntax (the normal case for any
// real schema) is indexed correctly; a column pathologically storing both
// numeric 5 and string "5" as "the same value" falls outside the index's
// guaranteed scope. No query result can be silently WRONG because of this
// — extractEqualityCandidate only fires the indexed path for a literal
// whose resolved Go value is used verbatim as the bucket key, so a miss
// here just means "index lookup finds nothing," at which point the
// generalized fallback (see selectRowsOne) still exists via the full-scan
// path when no candidate can be extracted at all.
func idxPrefix(table, col string) string { return "sql/" + table + "/idx/" + col + "/" }

func idxBucketPrefix(table, col string, v any) string {
	return idxPrefix(table, col) + indexValueKey(v) + "/"
}

func idxEntryKey(table, col string, v any, pk string) string {
	return idxBucketPrefix(table, col, v) + pk
}

// indexValueKey canonicalizes a Go value into a stable, collision-free
// bucket-key fragment. Numeric types (int64/int/float64 — the only numeric
// shapes this engine's JSON-backed row storage ever produces or accepts)
// share one canonical form so int64(5) and float64(5) index into the same
// bucket, matching how valuesEqual/compareValues already treat them as
// equal. A distinct prefix per kind ("n:"/"s:"/"b:") prevents a numeric
// and a string value that happen to format identically from colliding.
func indexValueKey(v any) string {
	if f, ok := numeric(v); ok {
		return "n:" + strconv.FormatFloat(f, 'g', -1, 64)
	}
	if s, ok := v.(string); ok {
		return "s:" + s
	}
	if bl, ok := v.(bool); ok {
		return "b:" + strconv.FormatBool(bl)
	}
	// Any other type (shouldn't occur given this engine's value set) still
	// gets a stable, if less carefully collision-proofed, bucket via its
	// default string form.
	return "o:" + toIndexFallbackString(v)
}

func toIndexFallbackString(v any) string {
	return strings.TrimSpace(fmt.Sprint(v))
}

// indexRow adds one index entry per non-NULL column value in row, for
// every column the schema declares (not just ones actually queried later —
// see the package doc comment above for why). Called after a row is
// successfully written.
func indexRow(ctx context.Context, kv api.KVService, table string, schema *Schema, pk string, row api.Row) error {
	for _, c := range schema.Columns {
		v, ok := row[c.Name]
		if !ok || v == nil {
			continue // NULLs are never index-queried via "=" (see IS NULL instead), so skip indexing them
		}
		if err := kv.Put(ctx, idxEntryKey(table, c.Name, v, pk), []byte(pk)); err != nil {
			return err
		}
	}
	// Maintained from the SAME call site as the equality index above (not
	// a separate call added at each exec.go write path) so the two
	// indexes can never drift out of sync with each other — see
	// range_index.go's package doc comment for what this index covers.
	return indexRowRange(ctx, kv, table, schema, pk, row)
}

// unindexRow removes every index entry indexRow would have added for row —
// called before a row is deleted, or before re-indexing it under new
// values on UPDATE.
func unindexRow(ctx context.Context, kv api.KVService, table string, schema *Schema, pk string, row api.Row) error {
	for _, c := range schema.Columns {
		v, ok := row[c.Name]
		if !ok || v == nil {
			continue
		}
		if err := kv.Delete(ctx, idxEntryKey(table, c.Name, v, pk)); err != nil {
			return err
		}
	}
	return unindexRowRange(ctx, kv, table, schema, pk, row)
}

// indexLookupPKs returns every primary-key string indexed under table.col
// = v. A stale entry (pointing at a since-deleted row) is tolerated by the
// caller re-checking existence on fetch, not treated as corruption here.
func indexLookupPKs(ctx context.Context, kv api.KVService, table, col string, v any) ([]string, error) {
	prefix := idxBucketPrefix(table, col, v)
	var pks []string
	cursor := ""
	for {
		items, next, err := kv.Scan(ctx, prefix, 1000, cursor)
		if err != nil {
			return nil, err
		}
		for k := range items {
			pks = append(pks, strings.TrimPrefix(k, prefix))
		}
		if next == "" {
			return pks, nil
		}
		cursor = next
	}
}

// debugIndexedLookups/debugFullTableScans are test-only instrumentation
// (white-box package-internal counters, not exported) proving whether a
// given query actually used the index or fell back to scanTable — see
// features_test.go's index tests, which assert on these directly rather
// than inferring "fast" from timing (timing-based assertions are flaky;
// a call-count assertion is not). int64 + atomic: Engine.Query has no
// lock of its own around this increment (only parseMu, which guards
// AST-arena safety, not these counters specifically), and a future
// version of this engine may legitimately allow concurrent SELECTs once
// parseMu's upstream cause is fixed — so these must be safe to increment
// concurrently now rather than becoming a latent race later.
var (
	debugIndexedLookups int64
	debugFullTableScans int64
)

func incrIndexedLookups()       { atomic.AddInt64(&debugIndexedLookups, 1) }
func incrFullTableScans()       { atomic.AddInt64(&debugFullTableScans, 1) }
func loadIndexedLookups() int64 { return atomic.LoadInt64(&debugIndexedLookups) }
func loadFullTableScans() int64 { return atomic.LoadInt64(&debugFullTableScans) }

// extractEqualityCandidate walks a WHERE expression looking for a
// conjunct (through top-level ANDs only — an OR can't be safely narrowed
// to one index bucket) of the form `<schema-column> = <value>`, where
// <value> is anything resolve() can turn into a concrete Go value: a
// literal, a placeholder, or — critically for correlated subqueries — a
// reference into the OUTER row (e.g. `i.order_id = o.id` while evaluating
// items' WHERE with o bound as outer: "order_id" is items' own column,
// "o.id" resolves via the outer-row fallback already built into resolve).
//
// A binary `<col> = <col>` where BOTH sides name a column of THIS SAME
// schema is deliberately rejected (returns ok=false) — that is a same-row
// column-to-column comparison, not reducible to a fixed index bucket.
func extractEqualityCandidate(ctx context.Context, kv api.KVService, expr ast.Expr, schema *Schema, b *binder) (col string, val any, ok bool, err error) {
	be, isBin := expr.(*ast.BinaryExpr)
	if !isBin {
		return "", nil, false, nil
	}
	if be.Op == lexer.AND {
		if col, val, ok, err = extractEqualityCandidate(ctx, kv, be.Left, schema, b); ok || err != nil {
			return col, val, ok, err
		}
		return extractEqualityCandidate(ctx, kv, be.Right, schema, b)
	}
	if be.Op != lexer.EQ {
		return "", nil, false, nil
	}
	if col, val, ok, err = tryEqualityPair(ctx, kv, be.Left, be.Right, schema, b); ok || err != nil {
		return col, val, ok, err
	}
	return tryEqualityPair(ctx, kv, be.Right, be.Left, schema, b)
}

func tryEqualityPair(ctx context.Context, kv api.KVService, colSide, valSide ast.Expr, schema *Schema, b *binder) (string, any, bool, error) {
	name, isCol := columnName(colSide)
	if !isCol || !schema.hasColumn(name) {
		return "", nil, false, nil
	}
	if otherName, isOtherCol := columnName(valSide); isOtherCol && schema.hasColumn(otherName) {
		// Same-table column-to-column comparison — not an index candidate.
		return "", nil, false, nil
	}
	v, err := resolve(ctx, kv, valSide, nil, b)
	if err != nil {
		return "", nil, false, err
	}
	if v == nil {
		return "", nil, false, nil // don't index-lookup a NULL comparison
	}
	return name, v, true, nil
}
