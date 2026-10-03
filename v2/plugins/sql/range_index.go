package sql

import (
	"context"
	"encoding/binary"
	"math"
	"strings"
	"sync/atomic"

	"github.com/oarkflow/sqlparser/ast"
	"github.com/oarkflow/sqlparser/lexer"

	"github.com/oarkflow/velocity/v2/api"
)

// Range index: alongside the equality index (index.go), every declared
// column also gets an order-preserving range-index entry, so >, <, >=,
// <=, BETWEEN, and a plain-prefix LIKE can avoid a full-row-table scan.
//
// Key scheme: "sql/<table>/rangeidx/<col>/<tag><encoded-value><pk>".
// encodeSortableFloat/encodeSortableString below produce a byte encoding
// whose LEXICOGRAPHIC order matches the VALUE's natural order — numeric
// via a sign-flipped big-endian IEEE-754 encoding (fixed 8 bytes, so no
// ambiguity with what follows), strings via their raw UTF-8 bytes
// followed by an escaped NUL-terminator (0x00 0x00, with any literal 0x00
// byte in the string escaped to 0x00 0x01) so a proper-prefix string
// (e.g. "a" vs "ab") still sorts correctly relative to a longer string
// whose next byte could otherwise collide with an unescaped delimiter —
// this is the standard "memcomparable" encoding technique. Only numeric
// and string values are range-indexed (matching the two types
// compareValues already supports); a column that also holds bool/other
// values simply isn't range-index-covered for those rows, and the
// existing full-scan path remains correct as the fallback for it.
//
// Scope/performance note, stated plainly rather than oversold: this
// engine's StorageBackend-backed KVService only supports prefix-scoped,
// exact-cursor-resume pagination (see plugins/kv's Scan) — there is no
// seek-to-arbitrary-key primitive. So a range query still walks every
// entry in the QUERIED COLUMN's range-index bucket (decoding each
// lightweight index entry) to find the matching sub-range, rather than
// truly seeking straight to the first matching key the way a real B-tree
// would. What it DOES avoid, and the reason it's still a real
// optimization: fetching, JSON-unmarshaling, and WHERE-evaluating every
// FULL ROW in the table — only rows whose decoded index entry actually
// satisfies the bound are ever Get'd and evaluated. For a selective
// predicate on a wide-row table this is a substantial win; for a
// predicate matching most of the table, the win shrinks toward the cost
// of decoding the index bucket itself, which is still cheaper than
// decoding every full row.
func rangeIdxPrefix(table, col string) string { return "sql/" + table + "/rangeidx/" + col + "/" }

const (
	rangeTagNumber byte = 'n'
	rangeTagString byte = 's'
)

// encodeSortableFloat maps f to an 8-byte big-endian encoding whose
// unsigned-integer order matches f's numeric order: for a non-negative
// float, flip only the sign bit (so it sorts after every negative
// value's flipped form); for a negative float, flip ALL bits (which both
// reverses the raw magnitude ordering back to normal and drops the sign
// bit to 0, so it sorts before every non-negative value). Standard
// technique also used by e.g. FoundationDB's tuple layer for exactly
// this purpose.
func encodeSortableFloat(f float64) []byte {
	bits := math.Float64bits(f)
	if bits&(1<<63) != 0 {
		bits = ^bits
	} else {
		bits ^= 1 << 63
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, bits)
	return buf
}

func decodeSortableFloat(buf []byte) float64 {
	bits := binary.BigEndian.Uint64(buf)
	if bits&(1<<63) != 0 {
		bits ^= 1 << 63
	} else {
		bits = ^bits
	}
	return math.Float64frombits(bits)
}

// encodeSortableString appends s's raw bytes with each literal 0x00 byte
// escaped to [0x00, 0x01], terminated by [0x00, 0x00]. See the package
// doc comment above for why plain concatenation (value + separator + pk)
// is NOT safe in general (a string containing a byte less than the
// separator's byte value can silently invert ordering relative to a
// longer string sharing its prefix), and why this escaped-terminator
// scheme fixes that for arbitrary byte content, not just the common case.
func encodeSortableString(s string) []byte {
	buf := make([]byte, 0, len(s)+2)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x00 {
			buf = append(buf, 0x00, 0x01)
		} else {
			buf = append(buf, c)
		}
	}
	return append(buf, 0x00, 0x00)
}

// decodeSortableString reverses encodeSortableString, returning the
// original string and the number of encoded bytes consumed (including the
// terminator), so the caller can find where the trailing pk begins.
func decodeSortableString(buf []byte) (s string, consumed int, ok bool) {
	var out []byte
	i := 0
	for i < len(buf) {
		if buf[i] == 0x00 {
			if i+1 >= len(buf) {
				return "", 0, false
			}
			switch buf[i+1] {
			case 0x00: // terminator
				return string(out), i + 2, true
			case 0x01: // escaped literal 0x00
				out = append(out, 0x00)
				i += 2
				continue
			default:
				return "", 0, false
			}
		}
		out = append(out, buf[i])
		i++
	}
	return "", 0, false // ran off the end without a terminator — malformed
}

// rangeIdxEntryKey returns the full storage key for one range-index
// entry, or ok=false if v's type isn't range-indexable (only numeric and
// string are).
func rangeIdxEntryKey(table, col string, v any, pk string) (key string, ok bool) {
	prefix := rangeIdxPrefix(table, col)
	if f, isNum := numeric(v); isNum {
		return prefix + string(rangeTagNumber) + string(encodeSortableFloat(f)) + pk, true
	}
	if s, isStr := v.(string); isStr {
		return prefix + string(rangeTagString) + string(encodeSortableString(s)) + pk, true
	}
	return "", false
}

// decodeRangeEntry splits one range-index entry's key suffix (everything
// after rangeIdxPrefix(table, col)) back into its original value and the
// primary-key string. ok is false for a malformed/unrecognized entry
// (tolerated by callers exactly like a stale equality-index entry is —
// see index.go's indexLookupPKs doc comment — not treated as corruption).
func decodeRangeEntry(suffix string) (value any, pk string, ok bool) {
	if len(suffix) < 1 {
		return nil, "", false
	}
	tag := suffix[0]
	rest := []byte(suffix[1:])
	switch tag {
	case rangeTagNumber:
		if len(rest) < 8 {
			return nil, "", false
		}
		return decodeSortableFloat(rest[:8]), string(rest[8:]), true
	case rangeTagString:
		s, n, decOK := decodeSortableString(rest)
		if !decOK {
			return nil, "", false
		}
		return s, string(rest[n:]), true
	default:
		return nil, "", false
	}
}

// indexRowRange/unindexRowRange mirror indexRow/unindexRow (index.go) but
// maintain the range index instead. Called FROM indexRow/unindexRow
// themselves (not as separate call sites added to exec.go) so the two
// indexes can never drift out of sync — every write path that maintains
// one automatically maintains the other.
func indexRowRange(ctx context.Context, kv api.KVService, table string, schema *Schema, pk string, row api.Row) error {
	for _, c := range schema.Columns {
		v, ok := row[c.Name]
		if !ok || v == nil {
			continue
		}
		key, ok := rangeIdxEntryKey(table, c.Name, v, pk)
		if !ok {
			continue // unsupported value type for range indexing — equality index (index.go) still covers it
		}
		if err := kv.Put(ctx, key, []byte(pk)); err != nil {
			return err
		}
	}
	return nil
}

func unindexRowRange(ctx context.Context, kv api.KVService, table string, schema *Schema, pk string, row api.Row) error {
	for _, c := range schema.Columns {
		v, ok := row[c.Name]
		if !ok || v == nil {
			continue
		}
		key, ok := rangeIdxEntryKey(table, c.Name, v, pk)
		if !ok {
			continue
		}
		if err := kv.Delete(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

// Debug/test instrumentation, same pattern as index.go's
// debugIndexedLookups/debugFullTableScans: white-box counters proving
// whether a range query actually used the range index, and how many ROWS
// (not index entries) it actually fetched, so tests can assert real
// candidate-narrowing occurred instead of inferring it from timing.
var (
	debugRangeIndexedLookups int64
	debugRangeRowsFetched    int64
)

func incrRangeIndexedLookup()        { atomic.AddInt64(&debugRangeIndexedLookups, 1) }
func addRangeRowsFetched(n int64)    { atomic.AddInt64(&debugRangeRowsFetched, n) }
func loadRangeIndexedLookups() int64 { return atomic.LoadInt64(&debugRangeIndexedLookups) }
func loadRangeRowsFetched() int64    { return atomic.LoadInt64(&debugRangeRowsFetched) }

// rangeBound is a single-column range predicate extracted from a WHERE
// expression by extractRangeCandidate.
type rangeBound struct {
	col        string
	lowVal     any // nil = unbounded below
	lowIncl    bool
	highVal    any // nil = unbounded above
	highIncl   bool
	likePrefix string // set (with isLike true) instead of low/high for a LIKE 'prefix%' candidate
	isLike     bool
}

func (rb *rangeBound) matches(v any) bool {
	if rb.isLike {
		s, ok := v.(string)
		return ok && strings.HasPrefix(s, rb.likePrefix)
	}
	if rb.lowVal != nil {
		cmp, ok := compareValues(v, rb.lowVal)
		if !ok {
			return false
		}
		if rb.lowIncl {
			if cmp < 0 {
				return false
			}
		} else if cmp <= 0 {
			return false
		}
	}
	if rb.highVal != nil {
		cmp, ok := compareValues(v, rb.highVal)
		if !ok {
			return false
		}
		if rb.highIncl {
			if cmp > 0 {
				return false
			}
		} else if cmp >= 0 {
			return false
		}
	}
	return rb.lowVal != nil || rb.highVal != nil
}

// extractRangeCandidate walks a WHERE expression (through top-level ANDs
// only — an OR can't be safely narrowed to one bounded range, same
// restriction as extractEqualityCandidate) looking for comparisons
// against a single schema column that resolve to a concrete,
// range-indexable value. Multiple ANDed bounds on the SAME column (e.g.
// `age > 10 AND age < 90`) are merged into one tighter bound. Returns
// nil (no error) if no range-indexable predicate is found — the caller
// falls back to the full-scan path exactly as it already does when no
// equality candidate is found either.
func extractRangeCandidate(ctx context.Context, kv api.KVService, expr ast.Expr, schema *Schema, b *binder) (*rangeBound, error) {
	var found *rangeBound

	merge := func(rb *rangeBound) {
		if rb == nil {
			return
		}
		if found == nil {
			found = rb
			return
		}
		if found.col != rb.col || found.isLike || rb.isLike {
			return // only merge additional bounds on the SAME plain (non-LIKE) column
		}
		if rb.lowVal != nil {
			if found.lowVal == nil {
				found.lowVal, found.lowIncl = rb.lowVal, rb.lowIncl
			} else if cmp, ok := compareValues(rb.lowVal, found.lowVal); ok && cmp > 0 {
				found.lowVal, found.lowIncl = rb.lowVal, rb.lowIncl
			}
		}
		if rb.highVal != nil {
			if found.highVal == nil {
				found.highVal, found.highIncl = rb.highVal, rb.highIncl
			} else if cmp, ok := compareValues(rb.highVal, found.highVal); ok && cmp < 0 {
				found.highVal, found.highIncl = rb.highVal, rb.highIncl
			}
		}
	}

	var walkErr error
	var walk func(e ast.Expr)
	walk = func(e ast.Expr) {
		if walkErr != nil {
			return
		}
		if be, ok := e.(*ast.BinaryExpr); ok && be.Op == lexer.AND {
			walk(be.Left)
			walk(be.Right)
			return
		}
		rb, err := extractOneRangeBound(ctx, kv, e, schema, b)
		if err != nil {
			walkErr = err
			return
		}
		merge(rb)
	}
	walk(expr)
	if walkErr != nil {
		return nil, walkErr
	}
	return found, nil
}

// extractOneRangeBound recognizes exactly one of: `<col> <op> <value>` /
// `<value> <op> <col>` for op in {>, <, >=, <=}; `<col> BETWEEN lo AND
// hi`; or `<col> LIKE 'prefix%'` with no other wildcard in the pattern
// and no NOT/ESCAPE.
func extractOneRangeBound(ctx context.Context, kv api.KVService, expr ast.Expr, schema *Schema, b *binder) (*rangeBound, error) {
	switch e := expr.(type) {
	case *ast.BinaryExpr:
		switch e.Op {
		case lexer.GT, lexer.GTE, lexer.LT, lexer.LTE:
			if name, ok := columnName(e.Left); ok && schema.hasColumn(name) {
				if _, isCol := columnName(e.Right); isCol {
					return nil, nil // column-to-column, not a fixed bound
				}
				v, err := resolve(ctx, kv, e.Right, nil, b)
				if err != nil || v == nil {
					return nil, err
				}
				return boundFromOp(name, e.Op, v, false), nil
			}
			if name, ok := columnName(e.Right); ok && schema.hasColumn(name) {
				if _, isCol := columnName(e.Left); isCol {
					return nil, nil
				}
				v, err := resolve(ctx, kv, e.Left, nil, b)
				if err != nil || v == nil {
					return nil, err
				}
				return boundFromOp(name, e.Op, v, true), nil // operands swapped: flip the operator's sense
			}
		}
		return nil, nil
	case *ast.BetweenExpr:
		name, ok := columnName(e.Expr)
		if !ok || !schema.hasColumn(name) || e.Not {
			return nil, nil
		}
		lo, err := resolve(ctx, kv, e.Lo, nil, b)
		if err != nil {
			return nil, err
		}
		hi, err := resolve(ctx, kv, e.Hi, nil, b)
		if err != nil {
			return nil, err
		}
		if lo == nil || hi == nil {
			return nil, nil
		}
		return &rangeBound{col: name, lowVal: lo, lowIncl: true, highVal: hi, highIncl: true}, nil
	case *ast.LikeExpr:
		if e.Not {
			return nil, nil
		}
		name, ok := columnName(e.Expr)
		if !ok || !schema.hasColumn(name) {
			return nil, nil
		}
		p, err := resolve(ctx, kv, e.Pattern, nil, b)
		if err != nil {
			return nil, err
		}
		pat, isStr := p.(string)
		if !isStr {
			return nil, nil
		}
		// Only a plain trailing "%" with no other wildcard anywhere else
		// qualifies as a prefix candidate — "a%b", "a_b", or a bare "%"
		// all fall back to the existing full-scan LIKE evaluation.
		if !strings.HasSuffix(pat, "%") {
			return nil, nil
		}
		prefix := pat[:len(pat)-1]
		if strings.ContainsAny(prefix, "%_") {
			return nil, nil
		}
		return &rangeBound{col: name, isLike: true, likePrefix: prefix}, nil
	default:
		return nil, nil
	}
}

// boundFromOp turns `col <op> value` into a rangeBound, accounting for
// swapped is true when the original expression was `value <op> col`
// (e.g. `50 < age` means age > 50, the same as `age > 50`), which flips
// the direction of every operator.
func boundFromOp(col string, op lexer.TokenType, value any, swapped bool) *rangeBound {
	if swapped {
		switch op {
		case lexer.GT:
			op = lexer.LT
		case lexer.GTE:
			op = lexer.LTE
		case lexer.LT:
			op = lexer.GT
		case lexer.LTE:
			op = lexer.GTE
		}
	}
	rb := &rangeBound{col: col}
	switch op {
	case lexer.GT:
		rb.lowVal, rb.lowIncl = value, false
	case lexer.GTE:
		rb.lowVal, rb.lowIncl = value, true
	case lexer.LT:
		rb.highVal, rb.highIncl = value, false
	case lexer.LTE:
		rb.highVal, rb.highIncl = value, true
	}
	return rb
}

// rangeLookupPKs walks every entry in table.col's range-index bucket
// (see the package doc comment above for why this is a full bucket scan,
// not a true seek), decoding each and keeping the primary keys whose
// decoded value satisfies rb. Errors from a single malformed entry are
// tolerated (skipped) exactly like a stale equality-index entry is.
func rangeLookupPKs(ctx context.Context, kv api.KVService, table string, rb *rangeBound) ([]string, error) {
	prefix := rangeIdxPrefix(table, rb.col)
	var pks []string
	collect := func(k string) {
		suffix := strings.TrimPrefix(k, prefix)
		v, pk, ok := decodeRangeEntry(suffix)
		if !ok {
			return
		}
		if rb.matches(v) {
			pks = append(pks, pk)
		}
	}
	if ss, ok := kv.(api.KVStreamScanner); ok {
		err := ss.ScanKeysStream(ctx, prefix, func(k string) (bool, error) {
			collect(k)
			return true, nil
		})
		return pks, err
	}
	cursor := ""
	for {
		items, next, err := kv.Scan(ctx, prefix, 1000, cursor)
		if err != nil {
			return nil, err
		}
		for k := range items {
			collect(k)
		}
		if next == "" {
			return pks, nil
		}
		cursor = next
	}
}
