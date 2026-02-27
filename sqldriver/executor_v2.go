package sqldriver

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/oarkflow/velocity"
	"github.com/xwb1989/sqlparser"
)

// ExecutorV2 builds on top of the xwb1989/sqlparser AST compiler to construct and run physical iterators
type ExecutorV2 struct {
	conn *Conn
}

func (e *ExecutorV2) Execute(ctx context.Context, stmt sqlparser.Statement, args []driver.NamedValue) (driver.Result, error) {
	switch n := stmt.(type) {
	case *sqlparser.Insert:
		return e.executeInsert(ctx, n, args)
	case *sqlparser.Update:
		return e.executeUpdate(ctx, n, args)
	case *sqlparser.Delete:
		return e.executeDelete(ctx, n, args)
	default:
		return nil, fmt.Errorf("velocity driver: unsupported execution node type %T", n)
	}
}

func (e *ExecutorV2) executeInsert(ctx context.Context, n *sqlparser.Insert, args []driver.NamedValue) (driver.Result, error) {
	tableName := sqlparser.String(n.Table.Name)
	var cols []string
	for _, col := range n.Columns {
		cols = append(cols, col.String())
	}

	rows, ok := n.Rows.(sqlparser.Values)
	if !ok {
		return nil, fmt.Errorf("velocity driver: expected VALUES clause in INSERT")
	}

	eval := &Evaluator{Args: args}
	inserted := int64(0)

	for _, row := range rows {
		data := make(map[string]interface{})
		for i, expr := range row {
			if i >= len(cols) {
				return nil, fmt.Errorf("velocity driver: more values than columns")
			}

			// Use the evaluator to get exact literal typing or positional bindings!
			val, err := eval.Eval(expr, nil) // No row context for INSERT VALUES
			if err != nil {
				return nil, err
			}
			data[cols[i]] = val
		}

		key := fmt.Sprintf("%s:%d", tableName, time.Now().UnixNano())
		if id, has := data["id"]; has {
			key = fmt.Sprintf("%s:%v", tableName, id)
		}

		payload, _ := json.Marshal(data)
		err := e.conn.Put([]byte(key), payload)
		if err != nil {
			return nil, err
		}
		inserted++
	}

	return &Result{rowsAffected: inserted}, nil
}

func (e *ExecutorV2) executeUpdate(ctx context.Context, n *sqlparser.Update, args []driver.NamedValue) (driver.Result, error) {
	// 1. Execute the WHERE filter using ExecuteSelect first to find matching documents
	// 2. Apply partial sets to each matching document
	// 3. Use conn.Put to override the fields in a transation if active

	sel := &sqlparser.Select{
		From:        n.TableExprs,
		Where:       n.Where,
		SelectExprs: []sqlparser.SelectExpr{&sqlparser.StarExpr{}},
	}

	rows, err := e.ExecuteSelect(ctx, sel, args)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	updatedCount := int64(0)

	internalRows, ok := rows.(*Rows)
	if !ok {
		return nil, fmt.Errorf("update failed: incompatible rows object returned")
	}

	eval := &Evaluator{Args: args}

	// Apply SET logic across result maps
	for _, res := range internalRows.results {
		var doc map[string]interface{}
		if err := json.Unmarshal(res.Value, &doc); err != nil {
			continue // skip unparseable
		}

		for _, upd := range n.Exprs {
			colName := upd.Name.Name.String()

			// Fully valuate complex SET expressions e.g. SET age = age + 1
			val, err := eval.Eval(upd.Expr, doc)
			if err == nil {
				doc[colName] = val
			}
		}

		newPayload, _ := json.Marshal(doc)
		err = e.conn.Put(res.Key, newPayload)
		if err == nil {
			updatedCount++
		}
	}

	return &Result{rowsAffected: updatedCount}, nil
}

func (e *ExecutorV2) executeDelete(ctx context.Context, n *sqlparser.Delete, args []driver.NamedValue) (driver.Result, error) {
	sel := &sqlparser.Select{
		From:        n.TableExprs,
		Where:       n.Where,
		SelectExprs: []sqlparser.SelectExpr{&sqlparser.StarExpr{}},
	}

	rows, err := e.ExecuteSelect(ctx, sel, args)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	deletedCount := int64(0)
	internalRows, ok := rows.(*Rows)
	if !ok {
		return nil, err
	}

	for _, res := range internalRows.results {
		err = e.conn.Delete(res.Key)
		if err == nil {
			deletedCount++
		}
	}

	return &Result{rowsAffected: deletedCount}, nil
}

// Convert parser AST into an execution plan and execute
func (e *ExecutorV2) ExecuteSelect(ctx context.Context, stmt sqlparser.Statement, args []driver.NamedValue) (driver.Rows, error) {
	selStmt, ok := stmt.(sqlparser.SelectStatement)
	if !ok {
		return nil, fmt.Errorf("velocity driver: expected SELECT or UNION statement")
	}

	return e.executeSelectStatement(ctx, selStmt, args)
}

func (e *ExecutorV2) executeSelectStatement(ctx context.Context, stmt sqlparser.SelectStatement, args []driver.NamedValue) (*Rows, error) {
	switch s := stmt.(type) {
	case *sqlparser.Select:
		return e.executeSingleSelect(ctx, s, args)
	case *sqlparser.Union:
		leftRows, err := e.executeSelectStatement(ctx, s.Left, args)
		if err != nil {
			return nil, err
		}
		rightRows, err := e.executeSelectStatement(ctx, s.Right, args)
		if err != nil {
			return nil, err
		}

		leftRows.results = append(leftRows.results, rightRows.results...)

		if s.Type == sqlparser.UnionStr || s.Type == sqlparser.UnionDistinctStr {
			leftRows.results = distinctResults(leftRows.results)
		}

		return leftRows, nil
	case *sqlparser.ParenSelect:
		return e.executeSelectStatement(ctx, s.Select, args)
	default:
		return nil, fmt.Errorf("velocity driver: unsupported select statement type %T", s)
	}
}

func distinctResults(results []velocity.SearchResult) []velocity.SearchResult {
	seen := make(map[string]bool)
	var unique []velocity.SearchResult
	for _, r := range results {
		hash := string(r.Value)
		if !seen[hash] {
			seen[hash] = true
			unique = append(unique, r)
		}
	}
	return unique
}

func (e *ExecutorV2) executeSingleSelect(ctx context.Context, sel *sqlparser.Select, args []driver.NamedValue) (*Rows, error) {

	// 1. Map Table Expressions (FROM ...)
	var rootIter Iterator
	var err error

	// Usually SQL parser returns `TableExprs` slices
	for _, expr := range sel.From {
		iter, tableErr := e.buildTableExprIterator(ctx, expr, args)
		if tableErr != nil {
			return nil, tableErr
		}

		if rootIter == nil {
			rootIter = iter
		} else {
			// Cross Join / Implicit Join
			rootIter, err = NewNestedLoopJoinIterator(ctx, rootIter, iter, nil)
			if err != nil {
				return nil, err
			}
		}
	}

	if rootIter == nil {
		return nil, fmt.Errorf("velocity driver: no valid FROM clause found")
	}

	// 2. Map WHERE clause (if not optimized into the Search filter earlier)
	if sel.Where != nil {
		rootIter = &FilterIterator{
			next: rootIter,
			cond: e.buildWhereCondition(sel.Where.Expr, args), // Dynamically eval condition vs row map
		}
	}

	// 3. Process the resulting rows back into driver format
	var resultCols []string
	var selectExprs []*sqlparser.AliasedExpr

	// Evaluate selected columns
	isStar := false
	for _, expr := range sel.SelectExprs {
		switch e := expr.(type) {
		case *sqlparser.StarExpr:
			isStar = true
			resultCols = append(resultCols, "*")
			selectExprs = append(selectExprs, nil)
		case *sqlparser.AliasedExpr:
			colName := sqlparser.String(e.Expr)
			if !e.As.IsEmpty() {
				colName = e.As.String()
			}
			resultCols = append(resultCols, colName)
			selectExprs = append(selectExprs, e)
		}
	}

	eval := &Evaluator{Args: args}
	isAggregate := false
	for _, expr := range selectExprs {
		if expr != nil {
			if _, ok := expr.Expr.(*sqlparser.FuncExpr); ok {
				isAggregate = true
				break
			}
		}
	}

	var results []velocity.SearchResult
	if isAggregate {
		// Basic aggregation: count total rows.
		count := 0
		for {
			row, err := rootIter.Next(ctx)
			if err != nil {
				rootIter.Close()
				return nil, err
			}
			if row == nil {
				break
			}
			count++
		}

		aggRow := make(Row)
		for i, expr := range selectExprs {
			colName := resultCols[i]
			if expr != nil {
				if f, ok := expr.Expr.(*sqlparser.FuncExpr); ok {
					if strings.EqualFold(f.Name.String(), "count") {
						aggRow[colName] = int64(count)
					}
				}
			}
		}
		results = append(results, velocity.SearchResult{
			Key:   []byte("agg"),
			Value: rowToJSONBytes(aggRow),
		})
	} else {
		colsPremapped := false
		for {
			row, err := rootIter.Next(ctx)
			if err != nil {
				rootIter.Close()
				return nil, err
			}
			if row == nil {
				break
			}

			if isStar && !colsPremapped {
				// Expand * to all columns found in the first row
				newCols := []string{}
				for _, col := range resultCols {
					if col == "*" {
						for k := range row {
							newCols = append(newCols, k)
						}
					} else {
						newCols = append(newCols, col)
					}
				}
				resultCols = newCols
				colsPremapped = true
			}

			keyBytes := []byte(fmt.Sprintf("%d", time.Now().UnixNano()))
			if k, ok := row["_key"].(string); ok {
				keyBytes = []byte(k)
			}

			projectedRow := make(Row)
			for i, col := range resultCols {
				if i < len(selectExprs) && selectExprs[i] != nil {
					val, err := eval.Eval(selectExprs[i].Expr, row)
					if err == nil {
						projectedRow[col] = val
					} else {
						projectedRow[col] = nil
					}
				} else {
					projectedRow[col] = row[col]
				}
			}

			results = append(results, velocity.SearchResult{
				Key:   keyBytes,
				Value: rowToJSONBytes(projectedRow),
			})
		}
	}
	rootIter.Close()

	if len(resultCols) == 0 {
		resultCols = []string{"*"}
	}

	return &Rows{
		columns: resultCols,
		results: results,
		cursor:  0,
	}, nil
}

func rowToJSONBytes(r Row) []byte {
	out := make(map[string]interface{})
	for k, v := range r {
		out[k] = v
	}
	b, _ := json.Marshal(out)
	return b
}

func (e *ExecutorV2) buildTableExprIterator(ctx context.Context, expr sqlparser.TableExpr, args []driver.NamedValue) (Iterator, error) {
	switch t := expr.(type) {
	case *sqlparser.AliasedTableExpr:
		if subq, isSub := t.Expr.(*sqlparser.Subquery); isSub {
			alias := ""
			if !t.As.IsEmpty() {
				alias = t.As.String()
			}
			return e.buildSubqueryIterator(ctx, subq.Select, alias, args)
		}

		tableName := sqlparser.String(t.Expr)
		alias := tableName
		if !t.As.IsEmpty() {
			alias = t.As.String()
		}

		// Try to extract velocity parameters if we can, otherwise Scan ALL and rely on Filter Iterator.
		// For optimal performance, we would inject filters from the AST down into velocity.SearchQuery here.
		q := velocity.SearchQuery{Prefix: tableName, Limit: 1000} // Capped scan

		return NewTableScanIterator(e.conn.db, alias, q)

	case *sqlparser.JoinTableExpr:
		leftIter, err := e.buildTableExprIterator(ctx, t.LeftExpr, args)
		if err != nil {
			return nil, err
		}
		rightIter, err := e.buildTableExprIterator(ctx, t.RightExpr, args)
		if err != nil {
			return nil, err
		}

		// Simplistic equi-join condition extractor
		condFunc := e.buildJoinCondition(t.Condition, args)

		return NewNestedLoopJoinIterator(ctx, leftIter, rightIter, condFunc)

	default:
		return nil, fmt.Errorf("velocity driver: unsupported table expression %#v", expr)
	}
}

func (e *ExecutorV2) buildSubqueryIterator(ctx context.Context, stmt sqlparser.SelectStatement, alias string, args []driver.NamedValue) (Iterator, error) {
	rows, err := e.executeSelectStatement(ctx, stmt, args)
	if err != nil {
		return nil, err
	}

	return &MemoryIterator{
		alias:  alias,
		rows:   rows.results,
		cursor: 0,
	}, nil
}

func (e *ExecutorV2) buildWhereCondition(expr sqlparser.Expr, args []driver.NamedValue) func(Row) bool {
	eval := &Evaluator{Args: args}
	return func(r Row) bool {
		res, err := eval.evalBool(expr, r)
		if err != nil {
			return false
		}
		return res
	}
}

func (e *ExecutorV2) buildJoinCondition(cond sqlparser.JoinCondition, args []driver.NamedValue) func(Row, Row) bool {
	if cond.On == nil {
		return nil
	}
	eval := &Evaluator{Args: args}
	return func(left, right Row) bool {
		// Merge left and right into a single virtual row context
		merged := make(Row)
		for k, v := range left {
			merged[k] = v
		}
		for k, v := range right {
			merged[k] = v
		}

		res, err := eval.evalBool(cond.On, merged)
		if err != nil {
			return false
		}
		return res
	}
}
