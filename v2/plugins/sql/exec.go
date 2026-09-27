package sql

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/oarkflow/sqlparser/ast"

	"github.com/oarkflow/velocity/v2/api"
)

// undoFn reverses one mutation. Pushed onto a txState's undo stack so
// Tx.Rollback can restore prior KV state; ignored (never called) for
// statements run directly through Engine.Exec/Query outside a Tx.
type undoFn func(ctx context.Context) error

func noopUndo(context.Context) error { return nil }

func pkString(v any) (string, error) {
	if v == nil {
		return "", fmt.Errorf("sql: primary key value cannot be NULL")
	}
	return fmt.Sprint(v), nil
}

// encodePK builds one storage-key suffix from an ordered list of primary
// key values. For a single-column PK it's just that value's string form
// (unchanged from before composite-PK support was added, so existing row
// keys stay stable). For a composite PK, each value is length-prefixed
// ("<byte-length>:<value>|") before concatenation so no separator choice
// can collide with a value that happens to contain it.
func encodePK(vals []any) (string, error) {
	if len(vals) == 1 {
		return pkString(vals[0])
	}
	var sb strings.Builder
	for _, v := range vals {
		s, err := pkString(v)
		if err != nil {
			return "", err
		}
		sb.WriteString(strconv.Itoa(len(s)))
		sb.WriteByte(':')
		sb.WriteString(s)
		sb.WriteByte('|')
	}
	return sb.String(), nil
}

// execCreateTable handles CREATE TABLE.
func execCreateTable(ctx context.Context, kv api.KVService, stmt *ast.CreateTableStmt) (int64, undoFn, error) {
	table := qualifiedName(stmt.Table)
	exists, err := tableExists(ctx, kv, table)
	if err != nil {
		return 0, nil, err
	}
	if exists {
		if stmt.IfNotExists {
			return 0, noopUndo, nil
		}
		return 0, nil, fmt.Errorf("sql: table %q already exists", table)
	}

	cols := make([]Column, 0, len(stmt.Columns))
	for _, c := range stmt.Columns {
		typeName := ""
		if c.Type != nil {
			typeName = strings.ToUpper(string(c.Type.Name))
		}
		cols = append(cols, Column{
			Name:          c.Name.Unquoted,
			Type:          typeName,
			PrimaryKey:    c.PrimaryKey,
			NotNull:       c.NotNull || c.PrimaryKey,
			AutoIncrement: c.AutoIncrement,
		})
	}
	// Table-level PRIMARY KEY (col1, col2, ...) constraint: every listed
	// column becomes part of the (possibly composite) primary key, in the
	// declared order — see Schema.PKOrder.
	var pkOrder []string
	for _, tc := range stmt.Constraints {
		if tc.Type == ast.PrimaryKeyConstraint && len(tc.Columns) > 0 {
			for _, tcCol := range tc.Columns {
				pkName := tcCol.Name.Unquoted
				pkOrder = append(pkOrder, pkName)
				for i := range cols {
					if cols[i].Name == pkName {
						cols[i].PrimaryKey = true
						cols[i].NotNull = true
					}
				}
			}
		}
	}
	if len(pkOrder) == 0 {
		// No table-level constraint — fall back to a single inline
		// `col TYPE PRIMARY KEY` column declaration, as before.
		for _, c := range cols {
			if c.PrimaryKey {
				pkOrder = append(pkOrder, c.Name)
			}
		}
	}

	schema := &Schema{Table: table, Columns: cols, PKOrder: pkOrder}
	if len(schema.PrimaryKeyColumns()) == 0 {
		return 0, nil, fmt.Errorf("sql: table %q must declare at least one PRIMARY KEY column", table)
	}
	if err := saveSchema(ctx, kv, schema); err != nil {
		return 0, nil, err
	}
	return 0, func(ctx context.Context) error { return kv.Delete(ctx, schemaKey(table)) }, nil
}

// execInsert handles INSERT INTO ... VALUES (...). INSERT ... SELECT and
// ON DUPLICATE/CONFLICT clauses are not supported in this first pass.
func execInsert(ctx context.Context, kv api.KVService, stmt *ast.InsertStmt, args []any) (int64, []undoFn, error) {
	if stmt.Select != nil {
		return 0, nil, fmt.Errorf("sql: INSERT ... SELECT is not supported in this first pass")
	}
	if len(stmt.Values) == 0 {
		return 0, nil, fmt.Errorf("sql: INSERT requires a VALUES clause")
	}
	table := qualifiedName(stmt.Table)
	schema, err := loadSchema(ctx, kv, table)
	if err != nil {
		return 0, nil, err
	}
	pkCols := schema.PrimaryKeyColumns()
	if len(pkCols) == 0 {
		return 0, nil, fmt.Errorf("sql: table %q has no primary key", table)
	}

	colNames := make([]string, len(stmt.Columns))
	for i, c := range stmt.Columns {
		colNames[i] = c.Unquoted
	}
	if len(colNames) == 0 {
		for _, c := range schema.Columns {
			colNames = append(colNames, c.Name)
		}
	}

	b := newBinder(args)
	var undos []undoFn
	var affected int64

	for _, values := range stmt.Values {
		if len(values) != len(colNames) {
			return 0, nil, fmt.Errorf("sql: INSERT has %d columns but %d values", len(colNames), len(values))
		}
		row := api.Row{}
		for i, expr := range values {
			v, err := valueFromExpr(expr, b)
			if err != nil {
				return 0, nil, err
			}
			if !schema.hasColumn(colNames[i]) {
				return 0, nil, fmt.Errorf("sql: table %q has no column %q", table, colNames[i])
			}
			row[colNames[i]] = v
		}

		// Auto-increment only applies to a single-column PK — a composite
		// key with an auto-increment member would need to pick one member
		// to sequence, which is ambiguous without more schema info, so
		// it's rejected explicitly below instead of guessed at silently.
		if len(pkCols) == 1 {
			pk := pkCols[0]
			pkVal, hasPK := row[pk.Name]
			if (!hasPK || pkVal == nil) && pk.AutoIncrement {
				next, err := kv.Incr(ctx, seqKey(table), 1)
				if err != nil {
					return 0, nil, err
				}
				row[pk.Name] = next
			}
		}
		pkVals := make([]any, len(pkCols))
		for i, pk := range pkCols {
			v, ok := row[pk.Name]
			if !ok || v == nil {
				if len(pkCols) > 1 {
					return 0, nil, fmt.Errorf("sql: missing value for composite primary key column %q (auto-increment is not supported on composite keys)", pk.Name)
				}
				return 0, nil, fmt.Errorf("sql: missing value for primary key column %q", pk.Name)
			}
			pkVals[i] = v
		}
		ks, err := encodePK(pkVals)
		if err != nil {
			return 0, nil, err
		}
		key := rowKey(table, ks)
		existing, err := kv.Exists(ctx, key)
		if err != nil {
			return 0, nil, err
		}
		if existing {
			return 0, nil, fmt.Errorf("sql: duplicate primary key %v for table %q", pkVals, table)
		}
		data, err := json.Marshal(row)
		if err != nil {
			return 0, nil, err
		}
		if err := kv.Put(ctx, key, data); err != nil {
			return 0, nil, err
		}
		if err := indexRow(ctx, kv, table, schema, ks, row); err != nil {
			return 0, nil, err
		}
		k, r, pk := key, row, ks
		undos = append(undos, func(ctx context.Context) error {
			if err := unindexRow(ctx, kv, table, schema, pk, r); err != nil {
				return err
			}
			return kv.Delete(ctx, k)
		})
		affected++
	}
	return affected, undos, nil
}

// scanTable walks every row in table, invoking fn(key, row) for each. fn
// returns (keepGoing, error).
func scanTable(ctx context.Context, kv api.KVService, table string, fn func(key string, row api.Row) (bool, error)) error {
	cursor := ""
	for {
		items, next, err := kv.Scan(ctx, rowPrefix(table), 500, cursor)
		if err != nil {
			return err
		}
		for k, v := range items {
			var row api.Row
			if err := json.Unmarshal(v, &row); err != nil {
				return fmt.Errorf("sql: corrupt row at %q: %w", k, err)
			}
			keepGoing, err := fn(k, row)
			if err != nil {
				return err
			}
			if !keepGoing {
				return nil
			}
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}

// selectRows evaluates a SELECT statement — single table, JOIN, or
// subquery FROM; WHERE (including IN/EXISTS-subquery, correlated or not);
// GROUP BY with COUNT/SUM/AVG/MIN/MAX; ORDER BY; LIMIT/OFFSET; and
// top-level UNION/UNION ALL — and returns matching projected rows.
//
// outer is the enclosing query's current row when stmt is itself a
// subquery being evaluated once per outer row (see evalIn/evalExists/
// resolve's SubqueryExpr case, all in eval.go); it is nil for a top-level
// call. It is threaded through so a correlated inner WHERE clause can
// resolve a column the inner row doesn't have against outer instead (see
// resolve's b.outer fallback).
func selectRows(ctx context.Context, kv api.KVService, stmt *ast.SelectStmt, args []any, outer api.Row) ([]api.Row, error) {
	rows, err := selectRowsOne(ctx, kv, stmt, args, outer)
	if err != nil {
		return nil, err
	}
	if stmt.SetOp == nil {
		return rows, nil
	}
	switch stmt.SetOp.Op {
	case ast.Union:
		rightRows, err := selectRows(ctx, kv, stmt.SetOp.Right, args, outer)
		if err != nil {
			return nil, err
		}
		combined := append(append([]api.Row{}, rows...), rightRows...)
		if !stmt.SetOp.All {
			combined = dedupRows(combined)
		}
		return combined, nil
	default:
		return nil, fmt.Errorf("sql: only UNION/UNION ALL are supported in this pass, not INTERSECT/EXCEPT")
	}
}

// dedupRows removes rows that are deep-equal to an earlier row (by
// marshaled JSON comparison — encoding/json sorts map keys alphabetically,
// so this is a stable, order-independent equality check), preserving the
// first occurrence's position, for UNION (without ALL).
func dedupRows(rows []api.Row) []api.Row {
	seen := make(map[string]bool, len(rows))
	out := make([]api.Row, 0, len(rows))
	for _, r := range rows {
		data, err := json.Marshal(r)
		if err != nil {
			out = append(out, r)
			continue
		}
		key := string(data)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	return out
}

// projectColumns applies a SELECT column list to one row. For "*" it
// returns every bare (unqualified) column, dropping the "table.col"/
// "alias.col" duplicate keys that resolveFrom adds for JOIN queries —
// those exist only to make qualified references in WHERE/ON/SELECT
// unambiguous, not to appear twice in unqualified output.
func projectColumns(cols []ast.SelectColumn, row api.Row) api.Row {
	bareOnly := func(r api.Row) api.Row {
		out := make(api.Row, len(r))
		for k, v := range r {
			if strings.Contains(k, ".") {
				continue
			}
			out[k] = v
		}
		return out
	}
	if len(cols) == 1 && cols[0].Star {
		return bareOnly(row)
	}
	out := api.Row{}
	for _, sc := range cols {
		if sc.Star {
			for k, v := range bareOnly(row) {
				out[k] = v
			}
			continue
		}
		name, ok := columnName(sc.Expr)
		if !ok {
			continue // unsupported projection expression (e.g. a bare function call outside GROUP BY); skipped
		}
		outName := name
		if sc.Alias != nil {
			outName = sc.Alias.Unquoted
		}
		if _, qualified, ok2 := columnRef(sc.Expr); ok2 && qualified != "" {
			if v, present := row[qualified]; present {
				out[outName] = v
				continue
			}
		}
		out[outName] = row[name]
	}
	return out
}

func selectRowsOne(ctx context.Context, kv api.KVService, stmt *ast.SelectStmt, args []any, outer api.Row) ([]api.Row, error) {
	if len(stmt.From) != 1 {
		return nil, fmt.Errorf("sql: SELECT requires exactly one FROM element (comma-joins are not supported — use JOIN)")
	}

	// Fast path: single simple table, WHERE is exactly `pk = <value>`, and
	// no GROUP BY/ORDER BY/LIMIT — a direct point lookup, unchanged from
	// before JOIN/GROUP BY/ORDER BY/LIMIT support was added.
	if simple, ok := stmt.From[0].(*ast.SimpleTable); ok &&
		len(stmt.GroupBy) == 0 && len(stmt.OrderBy) == 0 && stmt.Limit == nil && !selectHasAggregate(stmt) {
		table := qualifiedName(simple.Name)
		schema, err := loadSchema(ctx, kv, table)
		if err != nil {
			return nil, err
		}
		if pk, hasPK := schema.PrimaryKeyColumn(); hasPK && stmt.Where != nil {
			b := newBinder(args).withOuter(outer)
			if v, matched, err := simpleEqualityOnColumn(ctx, kv, stmt.Where, pk.Name, nil, b); err == nil && matched {
				ks, err := pkString(v)
				if err != nil {
					return nil, err
				}
				data, found, err := kv.Get(ctx, rowKey(table, ks))
				if err != nil {
					return nil, err
				}
				if !found {
					return nil, nil
				}
				var row api.Row
				if err := json.Unmarshal(data, &row); err != nil {
					return nil, fmt.Errorf("sql: corrupt row for pk %v: %w", v, err)
				}
				return []api.Row{projectColumns(stmt.Columns, row)}, nil
			}
		}
	}

	// Secondary-index candidate path: for a single simple table with an
	// equality-shaped WHERE (see extractEqualityCandidate), fetch only the
	// indexed candidate rows instead of the whole table via resolveFrom's
	// full scan. This ALWAYS still re-runs the complete WHERE expression
	// against each fetched row (evalExpr, inside finishSelect) — the index
	// only narrows which rows are fetched, it never substitutes for the
	// real filter, so a bucket-key edge case (see index.go's doc comment)
	// can only cost a missed fast-path, never a wrong result.
	if simple, ok := stmt.From[0].(*ast.SimpleTable); ok && stmt.Where != nil {
		table := qualifiedName(simple.Name)
		if schema, err := loadSchema(ctx, kv, table); err == nil {
			b := newBinder(args).withOuter(outer)
			if col, val, found, err2 := extractEqualityCandidate(ctx, kv, stmt.Where, schema, b); err2 == nil && found {
				pks, err3 := indexLookupPKs(ctx, kv, table, col, val)
				if err3 == nil {
					incrIndexedLookups()
					alias := table
					if simple.Alias != nil {
						alias = simple.Alias.Unquoted
					}
					candidates := make([]api.Row, 0, len(pks))
					for _, pk := range pks {
						data, found2, err4 := kv.Get(ctx, rowKey(table, pk))
						if err4 != nil {
							return nil, err4
						}
						if !found2 {
							continue // stale index entry (e.g. a concurrent delete) — tolerated, not corruption
						}
						var row api.Row
						if err4 := json.Unmarshal(data, &row); err4 != nil {
							return nil, fmt.Errorf("sql: corrupt row for pk %v: %w", pk, err4)
						}
						candidates = append(candidates, qualifyRow(row, table, alias))
					}
					return finishSelect(ctx, kv, stmt, args, outer, candidates)
				}
			}
		}
	}

	// Range-index candidate path: for a single simple table with a
	// range-shaped WHERE (>, <, >=, <=, BETWEEN, or a plain-prefix LIKE —
	// see extractRangeCandidate), fetch only the rows whose indexed
	// column value actually satisfies the bound instead of the whole
	// table. Tried only after the equality-candidate path above finds
	// nothing (an equality match, when available, is strictly cheaper).
	// Exactly like the equality path, this ALWAYS still re-runs the full
	// WHERE expression against each fetched row via finishSelect — the
	// index only narrows which rows are fetched.
	if simple, ok := stmt.From[0].(*ast.SimpleTable); ok && stmt.Where != nil {
		table := qualifiedName(simple.Name)
		if schema, err := loadSchema(ctx, kv, table); err == nil {
			b := newBinder(args).withOuter(outer)
			if rb, err2 := extractRangeCandidate(ctx, kv, stmt.Where, schema, b); err2 == nil && rb != nil {
				pks, err3 := rangeLookupPKs(ctx, kv, table, rb)
				if err3 == nil {
					incrRangeIndexedLookup()
					alias := table
					if simple.Alias != nil {
						alias = simple.Alias.Unquoted
					}
					candidates := make([]api.Row, 0, len(pks))
					for _, pk := range pks {
						data, found2, err4 := kv.Get(ctx, rowKey(table, pk))
						if err4 != nil {
							return nil, err4
						}
						if !found2 {
							continue // stale index entry (e.g. a concurrent delete) — tolerated, not corruption
						}
						var row api.Row
						if err4 := json.Unmarshal(data, &row); err4 != nil {
							return nil, fmt.Errorf("sql: corrupt row for pk %v: %w", pk, err4)
						}
						candidates = append(candidates, qualifyRow(row, table, alias))
					}
					addRangeRowsFetched(int64(len(candidates)))
					return finishSelect(ctx, kv, stmt, args, outer, candidates)
				}
			}
		}
	}

	fromRows, err := resolveFrom(ctx, kv, stmt.From[0], args)
	if err != nil {
		return nil, err
	}
	incrFullTableScans()
	return finishSelect(ctx, kv, stmt, args, outer, fromRows)
}

// finishSelect applies WHERE filtering, GROUP BY/aggregation, ORDER BY,
// LIMIT/OFFSET, and column projection to an already-resolved row set —
// shared by the full-scan path (resolveFrom's complete row set) and the
// secondary-index candidate path (selectRowsOne, above), so both apply
// identical semantics regardless of how the candidate rows were found.
func finishSelect(ctx context.Context, kv api.KVService, stmt *ast.SelectStmt, args []any, outer api.Row, fromRows []api.Row) ([]api.Row, error) {
	var filtered []api.Row
	for _, row := range fromRows {
		if stmt.Where != nil {
			b := newBinder(args).withOuter(outer)
			match, err := evalExpr(ctx, kv, stmt.Where, row, b)
			if err != nil {
				return nil, err
			}
			if !match {
				continue
			}
		}
		filtered = append(filtered, row)
	}

	// GROUP BY/aggregate projection happens before ORDER BY/LIMIT (its
	// output rows are already the final projected shape, and ORDER BY in
	// a grouped query legitimately refers to a grouped column or an
	// aggregate's output alias). The ungrouped path is the opposite: it
	// must order/limit on the FULL pre-projection rows and project only
	// as the very last step — ordering after projection would silently
	// no-op whenever ORDER BY names a column that wasn't SELECTed (e.g.
	// `SELECT name FROM t ORDER BY price`), since compareValues treats a
	// missing key on both sides as "not comparable" and simply moves on.
	if len(stmt.GroupBy) > 0 || selectHasAggregate(stmt) {
		groupCols := make([]string, 0, len(stmt.GroupBy))
		for _, g := range stmt.GroupBy {
			name, ok := columnName(g)
			if !ok {
				return nil, fmt.Errorf("sql: unsupported GROUP BY expression %T", g)
			}
			groupCols = append(groupCols, name)
		}
		out, err := groupAndAggregate(filtered, groupCols, stmt.Columns)
		if err != nil {
			return nil, err
		}
		out, err = applyOrderBy(out, stmt.OrderBy)
		if err != nil {
			return nil, err
		}
		if stmt.Limit != nil {
			out, err = applyLimit(out, stmt.Limit, newBinder(args))
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	}

	ordered, err := applyOrderBy(filtered, stmt.OrderBy)
	if err != nil {
		return nil, err
	}
	if stmt.Limit != nil {
		ordered, err = applyLimit(ordered, stmt.Limit, newBinder(args))
		if err != nil {
			return nil, err
		}
	}
	out := make([]api.Row, len(ordered))
	for i, row := range ordered {
		out[i] = projectColumns(stmt.Columns, row)
	}
	return out, nil
}

// execUpdate handles UPDATE table SET ... [WHERE ...].
func execUpdate(ctx context.Context, kv api.KVService, stmt *ast.UpdateStmt, args []any) (int64, []undoFn, error) {
	if len(stmt.Tables) != 1 {
		return 0, nil, fmt.Errorf("sql: UPDATE supports exactly one table in this first pass")
	}
	simple, ok := stmt.Tables[0].(*ast.SimpleTable)
	if !ok {
		return 0, nil, fmt.Errorf("sql: UPDATE target must be a simple table reference")
	}
	table := qualifiedName(simple.Name)
	schema, err0 := loadSchema(ctx, kv, table)
	if err0 != nil {
		return 0, nil, err0
	}
	rowPfx := rowPrefix(table)

	var undos []undoFn
	var affected int64
	var scanErr error

	err := scanTable(ctx, kv, table, func(key string, row api.Row) (bool, error) {
		if stmt.Where != nil {
			b := newBinder(args)
			match, err := evalExpr(ctx, kv, stmt.Where, row, b)
			if err != nil {
				return false, err
			}
			if !match {
				return true, nil
			}
		}
		before, err := json.Marshal(row)
		if err != nil {
			return false, err
		}
		updated := api.Row{}
		for k, v := range row {
			updated[k] = v
		}
		b := newBinder(args)
		for _, a := range stmt.Set {
			v, err := valueFromExpr(a.Value, b)
			if err != nil {
				scanErr = err
				return false, err
			}
			updated[a.Column.Unquoted] = v
		}
		data, err := json.Marshal(updated)
		if err != nil {
			return false, err
		}
		pk := strings.TrimPrefix(key, rowPfx)
		if err := unindexRow(ctx, kv, table, schema, pk, row); err != nil {
			return false, err
		}
		if err := kv.Put(ctx, key, data); err != nil {
			return false, err
		}
		if err := indexRow(ctx, kv, table, schema, pk, updated); err != nil {
			return false, err
		}
		k := key
		prev, prevRow, nextRow := before, row, updated
		undos = append(undos, func(ctx context.Context) error {
			if err := unindexRow(ctx, kv, table, schema, pk, nextRow); err != nil {
				return err
			}
			if err := kv.Put(ctx, k, prev); err != nil {
				return err
			}
			return indexRow(ctx, kv, table, schema, pk, prevRow)
		})
		affected++
		return true, nil
	})
	if err != nil {
		return 0, nil, err
	}
	if scanErr != nil {
		return 0, nil, scanErr
	}
	return affected, undos, nil
}

// execDelete handles DELETE FROM table [WHERE ...].
func execDelete(ctx context.Context, kv api.KVService, stmt *ast.DeleteStmt, args []any) (int64, []undoFn, error) {
	// The parser puts the table name in Tables only for the MySQL
	// multi-table syntax (DELETE t1, t2 FROM ...); the common
	// `DELETE FROM t` form leaves Tables empty and puts t in From instead.
	var table string
	switch {
	case len(stmt.Tables) == 1:
		table = qualifiedName(stmt.Tables[0])
	case len(stmt.Tables) == 0 && len(stmt.From) == 1:
		simple, ok := stmt.From[0].(*ast.SimpleTable)
		if !ok {
			return 0, nil, fmt.Errorf("sql: DELETE FROM target must be a simple table reference")
		}
		table = qualifiedName(simple.Name)
	default:
		return 0, nil, fmt.Errorf("sql: DELETE supports exactly one table in this first pass")
	}
	schema, err0 := loadSchema(ctx, kv, table)
	if err0 != nil {
		return 0, nil, err0
	}
	rowPfx := rowPrefix(table)

	var undos []undoFn
	var affected int64

	err := scanTable(ctx, kv, table, func(key string, row api.Row) (bool, error) {
		if stmt.Where != nil {
			b := newBinder(args)
			match, err := evalExpr(ctx, kv, stmt.Where, row, b)
			if err != nil {
				return false, err
			}
			if !match {
				return true, nil
			}
		}
		before, err := json.Marshal(row)
		if err != nil {
			return false, err
		}
		pk := strings.TrimPrefix(key, rowPfx)
		if err := unindexRow(ctx, kv, table, schema, pk, row); err != nil {
			return false, err
		}
		if err := kv.Delete(ctx, key); err != nil {
			return false, err
		}
		k, prev, prevRow := key, before, row
		undos = append(undos, func(ctx context.Context) error {
			if err := kv.Put(ctx, k, prev); err != nil {
				return err
			}
			return indexRow(ctx, kv, table, schema, pk, prevRow)
		})
		affected++
		return true, nil
	})
	if err != nil {
		return 0, nil, err
	}
	return affected, undos, nil
}
