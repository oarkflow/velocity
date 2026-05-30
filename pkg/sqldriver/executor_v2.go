package sqldriver

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	sqlparser "github.com/oarkflow/sqlparser"
	"github.com/oarkflow/sqlparser/ast"
	"github.com/oarkflow/sqlparser/lexer"
	"github.com/oarkflow/velocity"
)

const (
	maxSearchLimit    = int(^uint(0) >> 1)
	tableSchemaPrefix = "__schema:"
	viewPrefix        = "__view:"
)

type ExecutorV2 struct {
	conn       *Conn
	paramOrder map[int32]int
	ctes       map[string]*Rows
	outerRow   Row
	rawSQL     string
	cacheSQL   string
}

type putOperation struct {
	key   []byte
	value []byte
}

type tableSchemaMeta struct {
	Columns      []string               `json:"columns"`
	SearchSchema *velocity.SearchSchema `json:"search_schema,omitempty"`
	PrimaryKey   string                 `json:"primary_key,omitempty"`
	Unique       []string               `json:"unique,omitempty"`
	NotNull      []string               `json:"not_null,omitempty"`
}

type viewMeta struct {
	Columns []string `json:"columns,omitempty"`
	Select  string   `json:"select"`
}

type projectedRow struct {
	values  Row
	context Row
	group   []Row
}

type searchPlan struct {
	filters  []velocity.SearchFilter
	fullText string
}

type tableSearchPlans map[string]searchPlan

func (e *ExecutorV2) Execute(ctx context.Context, stmt sqlparser.Statement, args []driver.NamedValue) (driver.Result, error) {
	switch n := stmt.(type) {
	case *ast.InsertStmt:
		return e.executeInsert(ctx, n, args)
	case *ast.UpdateStmt:
		return e.executeUpdate(ctx, n, args)
	case *ast.DeleteStmt:
		return e.executeDelete(ctx, n, args)
	case *ast.CreateTableStmt:
		return e.executeCreateTable(ctx, n, args)
	case *ast.CreateViewStmt:
		return e.executeCreateView(ctx, n)
	case *ast.DropTableStmt:
		return e.executeDropTable(n)
	case *ast.TruncateStmt:
		return e.executeTruncateTable(qualifiedIdentToString(n.Table))
	default:
		return nil, fmt.Errorf("velocity driver: unsupported execution node type %T", n)
	}
}

func (e *ExecutorV2) ExecuteSelect(ctx context.Context, stmt sqlparser.Statement, args []driver.NamedValue) (driver.Rows, error) {
	sel, ok := stmt.(*ast.SelectStmt)
	if !ok {
		return nil, fmt.Errorf("velocity driver: expected SELECT statement, got %T", stmt)
	}
	var cache *SQLQueryCache
	var key string
	txLocal := false
	if e.conn.tx != nil && e.conn.txHasWrites {
		cache = e.conn.txQueryCache
		txLocal = true
	} else {
		cache = e.conn.queryCache
	}
	if cache != nil && cache.enabled {
		cacheSQL := e.cacheSQL
		if cacheSQL == "" {
			cacheSQL = normalizeSQLForCache(e.rawSQL)
		}
		key = queryCacheKeyFromNormalized(cacheSQL, args, txLocal)
		if rows, ok := cache.Get(key); ok {
			return rows, nil
		}
	}
	rows, err := e.executeSelectStatement(ctx, sel, args)
	if err != nil {
		return nil, err
	}
	if cache != nil && cache.enabled {
		deps := queryDependenciesForSelect(e, sel, args)
		cache.Put(key, rows, deps, e.conn.queryCacheCfg.maxRows, e.conn.queryCacheCfg.maxResultBytes)
	}
	return rows, nil
}

func (e *ExecutorV2) executeInsert(ctx context.Context, n *ast.InsertStmt, args []driver.NamedValue) (driver.Result, error) {
	tableName := qualifiedIdentToString(n.Table)
	columns, err := e.insertColumns(tableName, n.Columns)
	if err != nil {
		return nil, err
	}
	meta, _, err := e.loadTableSchemaMeta(tableName)
	if err != nil {
		return nil, err
	}
	if res, ok, err := e.tryFastBulkInsert(ctx, tableName, columns, n, args); ok || err != nil {
		return res, err
	}

	eval := e.newEvaluator(ctx, args)
	inserted := int64(0)
	var lastInsertID int64
	var puts []putOperation
	batchConstraintKeys := make(map[string]struct{})
	statementLockedRows := make(map[string]struct{})
	var statementUnlocks []func()
	defer func() {
		for i := len(statementUnlocks) - 1; i >= 0; i-- {
			statementUnlocks[i]()
		}
	}()
	lockInsertKey := func(key string) error {
		if key == "" {
			return nil
		}
		if _, exists := statementLockedRows[key]; exists {
			return nil
		}
		statementLockedRows[key] = struct{}{}
		unlock, err := e.conn.lockRows(ctx, []string{key})
		if err != nil {
			return err
		}
		statementUnlocks = append(statementUnlocks, unlock)
		return nil
	}
	needsExistingRow := n.Ignore || n.OnConflictDoNothing || len(n.OnDupKey) > 0 || len(n.OnConflictUpdate) > 0
	var encodedColumns [][]byte
	if !needsExistingRow && n.Select == nil && len(columns) > 0 {
		encodedColumns = make([][]byte, len(columns))
		for i, col := range columns {
			encodedColumns[i] = strconv.AppendQuote(nil, col)
		}
	}

	appendRow := func(data map[string]interface{}) error {
		key, keyValue := insertKey(tableName, data, inserted)
		if keyValue != nil {
			if id, ok := asFloat(keyValue); ok {
				lastInsertID = int64(id)
			}
		}
		if err := lockInsertKey(key); err != nil {
			return err
		}

		if err := e.checkInsertConstraints(tableName, meta, data, key, batchConstraintKeys); err != nil {
			return err
		}

		if needsExistingRow {
			if existing, err := e.conn.Get([]byte(key)); err == nil {
				switch {
				case n.Ignore || n.OnConflictDoNothing:
					return nil
				case len(n.OnDupKey) > 0 || len(n.OnConflictUpdate) > 0:
					var doc map[string]interface{}
					if err := json.Unmarshal(existing, &doc); err != nil {
						doc = make(map[string]interface{})
					}
					rowCtx := make(Row, len(doc))
					for k, v := range doc {
						rowCtx[k] = v
					}
					assignments := n.OnDupKey
					if len(assignments) == 0 {
						assignments = n.OnConflictUpdate
					}
					for _, asg := range assignments {
						val, err := eval.Eval(asg.Value, rowCtx)
						if err != nil {
							return err
						}
						name := identToString(asg.Column)
						doc[name] = val
						rowCtx[name] = val
					}
					data = doc
				}
			}
		}

		payload, err := json.Marshal(data)
		if err != nil {
			return err
		}
		puts = append(puts, putOperation{key: []byte(key), value: payload})
		inserted++
		return nil
	}

	switch {
	case n.Select != nil:
		rows, err := e.executeSelectStatement(ctx, n.Select, args)
		if err != nil {
			return nil, err
		}
		for _, row := range rows.rowMaps {
			data := normalizeProjectedRow(row)
			if len(columns) > 0 {
				filtered := make(map[string]interface{}, len(columns))
				for _, col := range columns {
					filtered[col] = data[col]
				}
				data = filtered
			}
			if err := appendRow(data); err != nil {
				return nil, err
			}
		}
	default:
		for rowIdx, rowExprs := range n.Values {
			if len(columns) > 0 && len(rowExprs) != len(columns) {
				return nil, fmt.Errorf("velocity driver: insert column/value count mismatch")
			}
			if encodedColumns != nil {
				key, keyValue, payload, data, err := e.fastInsertPayload(tableName, columns, encodedColumns, rowExprs, eval, inserted, len(n.Values) > 1, rowIdx)
				if err != nil {
					return nil, err
				}
				if keyValue != nil {
					if id, ok := asFloat(keyValue); ok {
						lastInsertID = int64(id)
					}
				}
				if err := lockInsertKey(key); err != nil {
					return nil, err
				}
				if err := e.checkInsertConstraints(tableName, meta, data, key, batchConstraintKeys); err != nil {
					return nil, err
				}
				puts = append(puts, putOperation{key: []byte(key), value: payload})
				inserted++
				continue
			}
			data := make(map[string]interface{}, len(rowExprs))
			for colIdx, expr := range rowExprs {
				val, err := eval.Eval(expr, nil)
				if err != nil {
					return nil, err
				}
				colName := columns[colIdx]
				data[colName] = val
			}
			if _, ok := data["id"]; !ok && len(n.Values) > 1 {
				data["_rownum"] = rowIdx
			}
			if err := appendRow(data); err != nil {
				return nil, err
			}
			delete(data, "_rownum")
		}
	}

	if err := e.applyPutOperations(puts); err != nil {
		return nil, err
	}
	return &Result{lastInsertId: lastInsertID, rowsAffected: inserted}, nil
}

func (e *ExecutorV2) tryFastBulkInsert(ctx context.Context, tableName string, columns []string, n *ast.InsertStmt, args []driver.NamedValue) (driver.Result, bool, error) {
	if n.Select != nil || n.Ignore || n.OnConflictDoNothing || len(n.OnDupKey) > 0 || len(n.OnConflictUpdate) > 0 {
		return nil, false, nil
	}
	if len(columns) == 0 || len(n.Values) < 2 {
		return nil, false, nil
	}

	encodedColumns := make([][]byte, len(columns))
	idIndex := -1
	for i, col := range columns {
		encodedColumns[i] = strconv.AppendQuote(nil, col)
		if col == "id" {
			idIndex = i
		}
	}
	for _, rowExprs := range n.Values {
		for _, expr := range rowExprs {
			param, ok := expr.(*ast.Param)
			if !ok || string(param.Raw) != "?" {
				return nil, false, nil
			}
		}
	}

	write := func(put func([]byte, []byte) error) (driver.Result, error) {
		inserted := int64(0)
		var lastInsertID int64
		batchConstraintKeys := make(map[string]struct{})
		statementLockedRows := make(map[string]struct{})
		var statementUnlocks []func()
		defer func() {
			for i := len(statementUnlocks) - 1; i >= 0; i-- {
				statementUnlocks[i]()
			}
		}()
		lockInsertKey := func(key string) error {
			if key == "" {
				return nil
			}
			if _, exists := statementLockedRows[key]; exists {
				return nil
			}
			statementLockedRows[key] = struct{}{}
			unlock, err := e.conn.lockRows(ctx, []string{key})
			if err != nil {
				return err
			}
			statementUnlocks = append(statementUnlocks, unlock)
			return nil
		}
		for _, rowExprs := range n.Values {
			if len(rowExprs) != len(columns) {
				return nil, fmt.Errorf("velocity driver: insert column/value count mismatch")
			}

			payload := make([]byte, 0, 96)
			payload = append(payload, '{')
			var keyValue interface{}
			values := make([]any, len(columns))
			for colIdx, expr := range rowExprs {
				value, ok, err := e.fastInsertExprValue(expr, args)
				if err != nil || !ok {
					return nil, err
				}
				values[colIdx] = value
				if colIdx > 0 {
					payload = append(payload, ',')
				}
				payload = append(payload, encodedColumns[colIdx]...)
				payload = append(payload, ':')
				payload = appendJSONValue(payload, value)
				if colIdx == idIndex {
					keyValue = value
				}
			}
			payload = append(payload, '}')

			var key []byte
			if keyValue != nil {
				key = appendTableKey(nil, tableName, keyValue)
				if id, ok := asFloat(keyValue); ok {
					lastInsertID = int64(id)
				}
			} else {
				key = strconv.AppendInt(append(append(key, tableName...), ':'), time.Now().UnixNano()+inserted, 10)
			}
			if err := lockInsertKey(string(key)); err != nil {
				return nil, err
			}
			if err := e.conn.checkRawInsertConstraintsWithSeen(tableName, columns, values, key, batchConstraintKeys); err != nil {
				return nil, err
			}
			if err := put(key, payload); err != nil {
				return nil, err
			}
			inserted++
		}
		return &Result{lastInsertId: lastInsertID, rowsAffected: inserted}, nil
	}

	if e.conn.tx != nil {
		res, err := write(e.conn.tx.PutUnsafe)
		return res, true, err
	}
	bw := e.conn.db.NewBatchWriter(len(n.Values))
	res, err := write(bw.PutUnsafe)
	if err != nil {
		return nil, true, err
	}
	if err := bw.Flush(); err != nil {
		return nil, true, err
	}
	return res, true, nil
}

func (e *ExecutorV2) fastInsertExprValue(expr ast.Expr, args []driver.NamedValue) (interface{}, bool, error) {
	param, ok := expr.(*ast.Param)
	if !ok || string(param.Raw) != "?" {
		return nil, false, nil
	}
	ordinal := 1
	if e.paramOrder != nil {
		var found bool
		ordinal, found = e.paramOrder[param.TokPos]
		if !found {
			return nil, false, fmt.Errorf("missing argument for parameter ?")
		}
	}
	value, err := namedArgByOrdinal(args, ordinal)
	return value, true, err
}

func (e *ExecutorV2) checkInsertConstraints(tableName string, meta tableSchemaMeta, data map[string]interface{}, primaryKey string, seen map[string]struct{}) error {
	hasSeen := func(key string) bool {
		if seen != nil {
			if _, exists := seen[key]; exists {
				return true
			}
		}
		if e.conn.txConstraintKeys != nil {
			if _, exists := e.conn.txConstraintKeys[key]; exists {
				return true
			}
		}
		return false
	}
	markSeen := func(key string) {
		if seen != nil {
			seen[key] = struct{}{}
		}
		if e.conn.txConstraintKeys != nil {
			e.conn.txConstraintKeys[key] = struct{}{}
		}
	}
	for _, col := range meta.NotNull {
		if data[col] == nil {
			return fmt.Errorf("velocity driver: column %s.%s cannot be NULL", tableName, col)
		}
	}
	if meta.PrimaryKey != "" {
		if value, ok := data[meta.PrimaryKey]; ok {
			if value == nil {
				return fmt.Errorf("velocity driver: primary key %s.%s cannot be NULL", tableName, meta.PrimaryKey)
			}
			txKey := "pk\x00" + primaryKey
			if hasSeen(txKey) {
				return fmt.Errorf("velocity driver: duplicate primary key on %s.%s", tableName, meta.PrimaryKey)
			}
			if _, err := e.conn.Get([]byte(primaryKey)); err == nil {
				return fmt.Errorf("velocity driver: duplicate primary key on %s.%s", tableName, meta.PrimaryKey)
			}
			markSeen(txKey)
		}
	}
	for _, col := range meta.Unique {
		value, ok := data[col]
		if !ok {
			continue
		}
		if value == nil {
			continue
		}
		txKey := "unique\x00" + tableName + "\x00" + col + "\x00" + fmt.Sprintf("%v", value)
		if hasSeen(txKey) {
			return fmt.Errorf("velocity driver: duplicate unique value on %s.%s", tableName, col)
		}
		count, err := e.conn.db.SearchCount(velocity.SearchQuery{
			Prefix: tableName,
			Filters: []velocity.SearchFilter{{
				Field:    col,
				Op:       "==",
				Value:    value,
				HashOnly: true,
			}},
			Limit: 1,
		})
		if err != nil {
			return err
		}
		if count > 0 {
			return fmt.Errorf("velocity driver: duplicate unique value on %s.%s", tableName, col)
		}
		for _, entry := range e.conn.PendingTableEntries(tableName) {
			if entry.Deleted {
				continue
			}
			var doc map[string]interface{}
			if err := json.Unmarshal(entry.Value, &doc); err != nil {
				continue
			}
			if sqlValueEqual(doc[col], value) {
				return fmt.Errorf("velocity driver: duplicate unique value on %s.%s", tableName, col)
			}
		}
		markSeen(txKey)
	}
	return nil
}

func (e *ExecutorV2) executeUpdate(ctx context.Context, n *ast.UpdateStmt, args []driver.NamedValue) (driver.Result, error) {
	rows, err := e.selectMutationRows(ctx, n.Tables, n.Where, n.Order, n.Limit, args)
	if err != nil {
		return nil, err
	}
	rowKeys := mutationRowKeys(rows)
	unlock, err := e.conn.lockRows(ctx, rowKeys)
	if err != nil {
		return nil, err
	}
	defer unlock()

	tableName, hasSingleTable := updateTargetTableName(n)
	var meta tableSchemaMeta
	if hasSingleTable {
		if loaded, found, err := e.loadTableSchemaMeta(tableName); err != nil {
			return nil, err
		} else if found {
			meta = loaded
		}
	}

	eval := e.newEvaluator(ctx, args)
	puts := make([]putOperation, 0, len(rows))
	uniqueSeen := make(map[string]string)
	updated := int64(0)
	for _, row := range rows {
		key, ok := row["_key"].(string)
		if !ok || key == "" {
			continue
		}
		raw, err := e.conn.Get([]byte(key))
		if err != nil {
			continue
		}
		var doc map[string]interface{}
		if err := json.Unmarshal(raw, &doc); err != nil {
			doc = make(map[string]interface{})
		}
		for name, value := range doc {
			row[name] = value
		}
		original := copyStringAnyMap(doc)
		for _, asg := range n.Set {
			val, err := eval.Eval(asg.Value, row)
			if err != nil {
				return nil, err
			}
			name := identToString(asg.Column)
			doc[name] = val
			row[name] = val
		}
		if hasSingleTable {
			if err := e.checkUpdateConstraints(tableName, meta, key, original, doc, uniqueSeen); err != nil {
				return nil, err
			}
		}
		payload, err := json.Marshal(doc)
		if err != nil {
			return nil, err
		}
		puts = append(puts, putOperation{key: []byte(key), value: payload})
		updated++
	}

	if err := e.applyPutOperations(puts); err != nil {
		return nil, err
	}
	return &Result{rowsAffected: updated}, nil
}

func updateTargetTableName(n *ast.UpdateStmt) (string, bool) {
	if n == nil || len(n.Tables) != 1 || hasJoinRef(n.Tables) {
		return "", false
	}
	table, ok := n.Tables[0].(*ast.SimpleTable)
	if !ok {
		return "", false
	}
	name := qualifiedIdentToString(table.Name)
	return name, name != ""
}

func copyStringAnyMap(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (e *ExecutorV2) checkUpdateConstraints(tableName string, meta tableSchemaMeta, key string, oldDoc, newDoc map[string]interface{}, uniqueSeen map[string]string) error {
	for _, col := range meta.NotNull {
		if newDoc[col] == nil {
			return fmt.Errorf("velocity driver: column %s.%s cannot be NULL", tableName, col)
		}
	}
	if meta.PrimaryKey != "" {
		if newDoc[meta.PrimaryKey] == nil {
			return fmt.Errorf("velocity driver: primary key %s.%s cannot be NULL", tableName, meta.PrimaryKey)
		}
		if !sqlValueEqual(oldDoc[meta.PrimaryKey], newDoc[meta.PrimaryKey]) {
			return fmt.Errorf("velocity driver: updating primary key %s.%s is not supported", tableName, meta.PrimaryKey)
		}
	}
	for _, col := range meta.Unique {
		newValue, ok := newDoc[col]
		if !ok || newValue == nil || sqlValueEqual(oldDoc[col], newValue) {
			continue
		}
		valueKey := fmt.Sprintf("%s\x00%s\x00%v", tableName, col, newValue)
		if existingKey, exists := uniqueSeen[valueKey]; exists && existingKey != key {
			return fmt.Errorf("velocity driver: duplicate unique value on %s.%s", tableName, col)
		}
		uniqueSeen[valueKey] = key
		if err := e.checkUniqueValueAvailableForUpdate(tableName, col, newValue, key); err != nil {
			return err
		}
	}
	return nil
}

func (e *ExecutorV2) checkUniqueValueAvailableForUpdate(tableName, col string, value interface{}, currentKey string) error {
	rows, err := e.conn.db.Search(velocity.SearchQuery{
		Prefix: tableName,
		Filters: []velocity.SearchFilter{{
			Field:    col,
			Op:       "==",
			Value:    value,
			HashOnly: true,
		}},
		Limit: maxSearchLimit,
	})
	if err != nil {
		return err
	}
	for _, row := range rows {
		if string(row.Key) != currentKey {
			return fmt.Errorf("velocity driver: duplicate unique value on %s.%s", tableName, col)
		}
	}
	for _, entry := range e.conn.PendingTableEntries(tableName) {
		if entry.Deleted || string(entry.Key) == currentKey {
			continue
		}
		var doc map[string]interface{}
		if err := json.Unmarshal(entry.Value, &doc); err != nil {
			continue
		}
		if sqlValueEqual(doc[col], value) {
			return fmt.Errorf("velocity driver: duplicate unique value on %s.%s", tableName, col)
		}
	}
	return nil
}

func sqlValueEqual(a, b interface{}) bool {
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func (e *ExecutorV2) executeDelete(ctx context.Context, n *ast.DeleteStmt, args []driver.NamedValue) (driver.Result, error) {
	rows, err := e.selectMutationRows(ctx, n.From, n.Where, n.Order, n.Limit, args)
	if err != nil {
		return nil, err
	}
	rowKeys := mutationRowKeys(rows)
	unlock, err := e.conn.lockRows(ctx, rowKeys)
	if err != nil {
		return nil, err
	}
	defer unlock()

	keys := make([][]byte, 0, len(rows))
	for _, row := range rows {
		key, ok := row["_key"].(string)
		if !ok || key == "" {
			continue
		}
		keys = append(keys, []byte(key))
	}
	if err := e.applyDeleteOperations(keys); err != nil {
		return nil, err
	}
	return &Result{rowsAffected: int64(len(keys))}, nil
}

func mutationRowKeys(rows []Row) []string {
	keys := make([]string, 0, len(rows))
	for _, row := range rows {
		key, ok := row["_key"].(string)
		if ok && key != "" {
			keys = append(keys, key)
		}
	}
	return keys
}

func (e *ExecutorV2) executeCreateTable(ctx context.Context, n *ast.CreateTableStmt, args []driver.NamedValue) (driver.Result, error) {
	tableName := qualifiedIdentToString(n.Table)
	if _, found, err := e.loadViewMeta(tableName); err != nil {
		return nil, err
	} else if found {
		return nil, fmt.Errorf("velocity driver: relation %s already exists as a view", tableName)
	}
	if _, found, err := e.loadTableSchemaMeta(tableName); err != nil {
		return nil, err
	} else if found {
		if n.IfNotExists {
			return &Result{}, nil
		}
		return nil, fmt.Errorf("velocity driver: table %s already exists", tableName)
	}

	meta, err := e.schemaMetaFromCreateStmt(ctx, n, args)
	if err != nil {
		return nil, err
	}
	if err := e.saveTableSchemaMeta(tableName, meta); err != nil {
		return nil, err
	}

	if n.Select == nil {
		return &Result{}, nil
	}

	rows, err := e.executeSelectStatement(ctx, n.Select, args)
	if err != nil {
		return nil, err
	}

	puts := make([]putOperation, 0, len(rows.rowMaps))
	inserted := int64(0)
	for _, row := range rows.rowMaps {
		data := normalizeProjectedRow(row)
		key, _ := insertKey(tableName, data, inserted)
		payload, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		puts = append(puts, putOperation{key: []byte(key), value: payload})
		inserted++
	}
	if err := e.applyPutOperations(puts); err != nil {
		return nil, err
	}
	return &Result{rowsAffected: inserted}, nil
}

func (e *ExecutorV2) executeCreateView(ctx context.Context, n *ast.CreateViewStmt) (driver.Result, error) {
	viewName := qualifiedIdentToString(n.Name)
	if viewName == "" || n.Select == nil {
		return nil, fmt.Errorf("velocity driver: invalid CREATE VIEW")
	}
	if _, found, err := e.loadTableSchemaMeta(viewName); err != nil {
		return nil, err
	} else if found {
		return nil, fmt.Errorf("velocity driver: relation %s already exists as a table", viewName)
	}
	if _, found, err := e.loadViewMeta(viewName); err != nil {
		return nil, err
	} else if found && !n.OrReplace {
		return nil, fmt.Errorf("velocity driver: view %s already exists", viewName)
	}
	selectSQL, err := extractCreateViewSelectSQL(e.rawSQL)
	if err != nil {
		return nil, err
	}
	if _, err := parseViewSelect(selectSQL); err != nil {
		return nil, err
	}
	columns := make([]string, 0, len(n.Columns))
	for _, col := range n.Columns {
		columns = append(columns, identToString(col))
	}
	meta := viewMeta{Columns: columns, Select: selectSQL}
	if err := e.saveViewMeta(viewName, meta); err != nil {
		return nil, err
	}
	return &Result{}, nil
}

func (e *ExecutorV2) executeDropTable(n *ast.DropTableStmt) (driver.Result, error) {
	var total int64
	for _, table := range n.Tables {
		tableName := qualifiedIdentToString(table)
		if tableName == "" {
			continue
		}
		if _, found, err := e.loadTableSchemaMeta(tableName); err != nil {
			return nil, err
		} else if !found && !n.IfExists {
			if _, viewFound, viewErr := e.loadViewMeta(tableName); viewErr != nil {
				return nil, viewErr
			} else if viewFound {
				if err := e.conn.Delete(viewStorageKey(tableName)); err != nil {
					return nil, err
				}
				e.conn.markSchemaChanged()
				continue
			}
			return nil, fmt.Errorf("velocity driver: table %s does not exist", tableName)
		} else if !found {
			if _, viewFound, viewErr := e.loadViewMeta(tableName); viewErr != nil {
				return nil, viewErr
			} else if viewFound {
				if err := e.conn.Delete(viewStorageKey(tableName)); err != nil {
					return nil, err
				}
				e.conn.markSchemaChanged()
			}
			continue
		}

		rows, err := e.conn.db.Search(velocity.SearchQuery{Prefix: tableName, Limit: maxSearchLimit})
		if err != nil {
			return nil, err
		}
		keys := make([][]byte, 0, len(rows)+1)
		for _, row := range rows {
			keys = append(keys, append([]byte(nil), row.Key...))
		}
		keys = append(keys, schemaStorageKey(tableName))
		if err := e.applyDeleteOperations(keys); err != nil {
			return nil, err
		}
		e.conn.db.SetSearchSchemaForPrefix(tableName, nil)
		e.conn.markSchemaChanged()
		total += int64(len(rows))
	}
	return &Result{rowsAffected: total}, nil
}

func (e *ExecutorV2) executeTruncateTable(tableName string) (driver.Result, error) {
	rows, err := e.conn.db.Search(velocity.SearchQuery{Prefix: tableName, Limit: maxSearchLimit})
	if err != nil {
		return nil, err
	}
	keys := make([][]byte, 0, len(rows))
	for _, row := range rows {
		keys = append(keys, append([]byte(nil), row.Key...))
	}
	if err := e.applyDeleteOperations(keys); err != nil {
		return nil, err
	}
	return &Result{rowsAffected: int64(len(keys))}, nil
}

func (e *ExecutorV2) executeSelectStatement(ctx context.Context, stmt *ast.SelectStmt, args []driver.NamedValue) (*Rows, error) {
	exec := e
	if stmt.With != nil {
		var err error
		exec, err = e.withMaterializedCTEs(ctx, stmt.With, args)
		if err != nil {
			return nil, err
		}
	}
	base := *stmt
	base.SetOp = nil
	base.With = nil
	left, err := exec.executeSingleSelect(ctx, &base, args)
	if err != nil {
		return nil, err
	}

	for op := stmt.SetOp; op != nil; op = op.Right.SetOp {
		rightBase := *op.Right
		rightBase.SetOp = nil
		right, err := exec.executeSelectStatement(ctx, &rightBase, args)
		if err != nil {
			return nil, err
		}
		left = applySetOperation(left, right, op)
	}
	return left, nil
}

func (e *ExecutorV2) withMaterializedCTEs(ctx context.Context, with *ast.WithClause, args []driver.NamedValue) (*ExecutorV2, error) {
	if with == nil || len(with.CTEs) == 0 {
		return e, nil
	}
	if with.Recursive {
		return nil, fmt.Errorf("velocity driver: recursive CTEs are not supported")
	}
	child := &ExecutorV2{
		conn:       e.conn,
		paramOrder: e.paramOrder,
		ctes:       make(map[string]*Rows, len(e.ctes)+len(with.CTEs)),
		outerRow:   e.outerRow,
		rawSQL:     e.rawSQL,
		cacheSQL:   e.cacheSQL,
	}
	for name, rows := range e.ctes {
		child.ctes[name] = rows
	}
	for _, cte := range with.CTEs {
		name := identToString(cte.Name)
		if name == "" || cte.Subq == nil {
			return nil, fmt.Errorf("velocity driver: invalid CTE")
		}
		rows, err := child.executeSelectStatement(ctx, cte.Subq, args)
		if err != nil {
			return nil, fmt.Errorf("velocity driver: CTE %s failed: %w", name, err)
		}
		rows = renameCTEColumns(rows, cte.Columns)
		child.ctes[name] = rows
	}
	return child, nil
}

func (e *ExecutorV2) executeSingleSelect(ctx context.Context, sel *ast.SelectStmt, args []driver.NamedValue) (*Rows, error) {
	if rows, ok, err := e.tryFastPrimaryKeySelect(sel, args); ok {
		return rows, err
	}
	if rows, ok, err := e.tryFastCountSelect(sel, args); ok {
		return rows, err
	}
	if rows, ok, err := e.tryFastPrimaryKeyJoinSelect(ctx, sel, args); ok {
		return rows, err
	}

	sourceRows, schemaCols, err := e.collectSourceRows(ctx, sel, args)
	if err != nil {
		return nil, err
	}

	isAggregate := len(sel.GroupBy) > 0 || selectHasAggregate(sel)
	var columns []string
	var projected []projectedRow
	if isAggregate {
		columns, projected, err = e.projectGroupedRows(ctx, sel, sourceRows, args)
	} else {
		columns, projected, err = e.projectRows(ctx, sel, sourceRows, args)
	}
	if err != nil {
		return nil, err
	}

	if sel.Distinct {
		projected = distinctProjectedRows(projected)
	}
	if len(sel.OrderBy) > 0 {
		if err := e.sortProjectedRows(ctx, projected, sel.OrderBy, args); err != nil {
			return nil, err
		}
	}
	projected = applyOffsetLimit(projected, e.extractOffset(sel.Limit, args), e.extractCount(sel.Limit, args))

	rowMaps := make([]Row, 0, len(projected))
	for _, row := range projected {
		rowMaps = append(rowMaps, row.values)
	}
	if len(columns) == 0 {
		columns = explicitColumnNames(sel.Columns)
	}

	return &Rows{
		columns:    columns,
		schemaCols: schemaCols,
		rowMaps:    rowMaps,
	}, nil
}

func (e *ExecutorV2) tryFastPrimaryKeySelect(sel *ast.SelectStmt, args []driver.NamedValue) (*Rows, bool, error) {
	if sel == nil || sel.Where == nil || sel.Distinct || len(sel.GroupBy) > 0 || len(sel.OrderBy) > 0 || sel.Having != nil || sel.Limit != nil {
		return nil, false, nil
	}
	if len(sel.From) != 1 || hasJoinRef(sel.From) {
		return nil, false, nil
	}
	table, ok := sel.From[0].(*ast.SimpleTable)
	if !ok || table.Alias != nil {
		return nil, false, nil
	}
	tableName := qualifiedIdentToString(table.Name)
	if tableName == "" {
		return nil, false, nil
	}
	if _, found, err := e.loadViewMeta(tableName); err != nil {
		return nil, true, err
	} else if found {
		return nil, false, nil
	}
	columns := explicitColumnNames(sel.Columns)
	if len(columns) == 0 {
		return nil, false, nil
	}

	binary, ok := sel.Where.(*ast.BinaryExpr)
	if !ok || binary.Op != lexer.EQ || exprColumnName(binary.Left) != "id" {
		return nil, false, nil
	}
	eval := &Evaluator{Args: args, ParamOrder: e.paramOrder}
	id, err := eval.Eval(binary.Right, nil)
	if err != nil || id == nil {
		return nil, false, err
	}

	raw, err := e.conn.Get(appendTableKey(nil, tableName, id))
	if err != nil {
		return &Rows{columns: columns, rowMaps: nil}, true, nil
	}
	row := make(Row, len(columns))
	for _, col := range columns {
		value, ok := fastJSONFieldValue(raw, col)
		if !ok {
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				return nil, true, err
			}
			value = doc[col]
		}
		row[col] = value
	}
	return &Rows{columns: columns, rowMaps: []Row{row}}, true, nil
}

func (e *ExecutorV2) tryFastPrimaryKeyJoinSelect(ctx context.Context, sel *ast.SelectStmt, args []driver.NamedValue) (*Rows, bool, error) {
	if sel == nil || sel.Where == nil || sel.Distinct || len(sel.GroupBy) > 0 || len(sel.OrderBy) > 0 || sel.Having != nil || sel.Limit != nil || sel.SetOp != nil {
		return nil, false, nil
	}
	if len(sel.From) != 1 {
		return nil, false, nil
	}
	join, ok := sel.From[0].(*ast.JoinTable)
	if !ok || join.Kind != ast.InnerJoin || join.On == nil {
		return nil, false, nil
	}
	leftTable, leftAlias, ok := simpleTableNameAndAlias(join.Left)
	if !ok {
		return nil, false, nil
	}
	rightTable, rightAlias, ok := simpleTableNameAndAlias(join.Right)
	if !ok {
		return nil, false, nil
	}
	whereTable, whereField, whereValue, ok := e.exactQualifiedFilter(sel.Where, args)
	if !ok || whereField != "id" {
		return nil, false, nil
	}
	on, ok := join.On.(*ast.BinaryExpr)
	if !ok || on.Op != lexer.EQ {
		return nil, false, nil
	}
	leftRefTable, leftRefField := qualifiedExprColumn(on.Left)
	rightRefTable, rightRefField := qualifiedExprColumn(on.Right)
	if leftRefTable == "" || rightRefTable == "" {
		return nil, false, nil
	}

	leftRaw, rightRaw, supported, err := e.fastJoinRowsByPrimaryKeys(leftTable, leftAlias, rightTable, rightAlias, whereTable, whereValue, leftRefTable, leftRefField, rightRefTable, rightRefField)
	if err != nil {
		return nil, true, err
	}
	if !supported {
		return nil, false, nil
	}
	if leftRaw == nil || rightRaw == nil {
		return &Rows{columns: explicitColumnNames(sel.Columns)}, true, nil
	}
	leftRow, err := rowFromRawTable(leftRaw.key, leftRaw.value, leftAlias)
	if err != nil {
		return nil, true, err
	}
	rightRow, err := rowFromRawTable(rightRaw.key, rightRaw.value, rightAlias)
	if err != nil {
		return nil, true, err
	}
	merged := mergeRows(leftRow, rightRow)
	eval := e.newEvaluator(ctx, args)
	ok, err = eval.evalBool(sel.Where, merged)
	if err != nil || !ok {
		return &Rows{columns: explicitColumnNames(sel.Columns)}, true, err
	}
	ok, err = eval.evalBool(join.On, merged)
	if err != nil || !ok {
		return &Rows{columns: explicitColumnNames(sel.Columns)}, true, err
	}
	columns, projected, err := e.projectRows(ctx, sel, []Row{merged}, args)
	if err != nil {
		return nil, true, err
	}
	rowMaps := make([]Row, 0, len(projected))
	for _, row := range projected {
		rowMaps = append(rowMaps, row.values)
	}
	return &Rows{columns: columns, rowMaps: rowMaps}, true, nil
}

type rawJoinRow struct {
	key   []byte
	value []byte
}

func (e *ExecutorV2) fastJoinRowsByPrimaryKeys(leftTable, leftAlias, rightTable, rightAlias, whereTable string, whereValue any, leftRefTable, leftRefField, rightRefTable, rightRefField string) (*rawJoinRow, *rawJoinRow, bool, error) {
	var leftRaw, rightRaw *rawJoinRow
	readByID := func(table string, id any) (*rawJoinRow, error) {
		key := appendTableKey(nil, table, id)
		raw, err := e.conn.Get(key)
		if err != nil {
			return nil, nil
		}
		return &rawJoinRow{key: key, value: raw}, nil
	}
	matches := func(ref, table, alias string) bool {
		return ref == table || ref == alias
	}
	if matches(whereTable, leftTable, leftAlias) {
		var err error
		leftRaw, err = readByID(leftTable, whereValue)
		if err != nil || leftRaw == nil {
			return nil, nil, true, err
		}
		if matches(leftRefTable, leftTable, leftAlias) && leftRefField != "id" && rightRefField == "id" {
			joinValue, ok := fastJSONFieldValue(leftRaw.value, leftRefField)
			if !ok {
				return leftRaw, nil, true, nil
			}
			rightRaw, err = readByID(rightTable, joinValue)
			return leftRaw, rightRaw, true, err
		}
		if matches(rightRefTable, leftTable, leftAlias) && rightRefField != "id" && leftRefField == "id" {
			joinValue, ok := fastJSONFieldValue(leftRaw.value, rightRefField)
			if !ok {
				return leftRaw, nil, true, nil
			}
			rightRaw, err = readByID(rightTable, joinValue)
			return leftRaw, rightRaw, true, err
		}
		return nil, nil, false, nil
	}
	if matches(whereTable, rightTable, rightAlias) {
		var err error
		rightRaw, err = readByID(rightTable, whereValue)
		if err != nil || rightRaw == nil {
			return nil, nil, true, err
		}
		if matches(rightRefTable, rightTable, rightAlias) && rightRefField != "id" && leftRefField == "id" {
			joinValue, ok := fastJSONFieldValue(rightRaw.value, rightRefField)
			if !ok {
				return nil, rightRaw, true, nil
			}
			leftRaw, err = readByID(leftTable, joinValue)
			return leftRaw, rightRaw, true, err
		}
		if matches(leftRefTable, rightTable, rightAlias) && leftRefField != "id" && rightRefField == "id" {
			joinValue, ok := fastJSONFieldValue(rightRaw.value, leftRefField)
			if !ok {
				return nil, rightRaw, true, nil
			}
			leftRaw, err = readByID(leftTable, joinValue)
			return leftRaw, rightRaw, true, err
		}
		return nil, nil, false, nil
	}
	return nil, nil, false, nil
}

func simpleTableNameAndAlias(ref ast.TableRef) (string, string, bool) {
	table, ok := ref.(*ast.SimpleTable)
	if !ok {
		return "", "", false
	}
	name := qualifiedIdentToString(table.Name)
	if name == "" {
		return "", "", false
	}
	alias := name
	if table.Alias != nil {
		alias = identToString(table.Alias)
	}
	return name, alias, true
}

func (e *ExecutorV2) exactQualifiedFilter(expr ast.Expr, args []driver.NamedValue) (string, string, any, bool) {
	eval := &Evaluator{Args: args, ParamOrder: e.paramOrder}
	var walk func(ast.Expr) (string, string, any, bool)
	walk = func(node ast.Expr) (string, string, any, bool) {
		switch v := node.(type) {
		case *ast.BinaryExpr:
			if v.Op == lexer.AND {
				if table, field, value, ok := walk(v.Left); ok {
					return table, field, value, true
				}
				return walk(v.Right)
			}
			if v.Op != lexer.EQ {
				return "", "", nil, false
			}
			table, field := qualifiedExprColumn(v.Left)
			if table == "" || field == "" {
				return "", "", nil, false
			}
			value, err := eval.Eval(v.Right, nil)
			if err != nil || value == nil {
				return "", "", nil, false
			}
			return table, field, value, true
		}
		return "", "", nil, false
	}
	return walk(expr)
}

func rowFromRawTable(key, value []byte, alias string) (Row, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(value, &data); err != nil {
		return nil, err
	}
	data["_key"] = string(key)
	row := make(Row, len(data)*2)
	for k, v := range data {
		row[alias+"."+k] = v
		row[k] = v
	}
	return row, nil
}

func fastJSONFieldValue(raw []byte, field string) (any, bool) {
	if field == "" {
		return nil, false
	}
	pattern := []byte(strconv.Quote(field))
	for searchFrom := 0; searchFrom < len(raw); {
		idx := bytes.Index(raw[searchFrom:], pattern)
		if idx < 0 {
			return nil, false
		}
		i := searchFrom + idx + len(pattern)
		for i < len(raw) && isJSONSpaceByte(raw[i]) {
			i++
		}
		if i >= len(raw) || raw[i] != ':' {
			searchFrom = searchFrom + idx + 1
			continue
		}
		i++
		for i < len(raw) && isJSONSpaceByte(raw[i]) {
			i++
		}
		if i >= len(raw) {
			return nil, false
		}
		if raw[i] == '"' {
			end := i + 1
			escaped := false
			for end < len(raw) {
				c := raw[end]
				if c == '\\' {
					escaped = true
					end += 2
					continue
				}
				if c == '"' {
					if !escaped {
						return string(raw[i+1 : end]), true
					}
					unquoted, err := strconv.Unquote(string(raw[i : end+1]))
					if err != nil {
						return nil, false
					}
					return unquoted, true
				}
				end++
			}
			return nil, false
		}
		end := i
		for end < len(raw) && raw[end] != ',' && raw[end] != '}' {
			end++
		}
		token := strings.TrimSpace(string(raw[i:end]))
		switch token {
		case "true":
			return true, true
		case "false":
			return false, true
		case "null":
			return nil, true
		}
		if n, err := strconv.ParseInt(token, 10, 64); err == nil {
			return n, true
		}
		if f, err := strconv.ParseFloat(token, 64); err == nil {
			return f, true
		}
		return token, true
	}
	return nil, false
}

func isJSONSpaceByte(c byte) bool {
	return c == ' ' || c == '\n' || c == '\r' || c == '\t'
}

func (e *ExecutorV2) collectSourceRows(ctx context.Context, sel *ast.SelectStmt, args []driver.NamedValue) ([]Row, []string, error) {
	if len(sel.From) == 0 {
		return []Row{{}}, nil, nil
	}

	var plan searchPlan
	var tablePlans tableSearchPlans
	queryLimit := maxSearchLimit
	if len(sel.From) == 1 && !hasJoinRef(sel.From) {
		plan = e.extractSearchPlan(sel.Where, args)
		queryLimit = e.scanQueryLimit(sel, plan, args)
	} else if sel.Where != nil {
		tablePlans = e.extractTableSearchPlans(sel.Where, args)
	}

	var root Iterator
	for _, ref := range sel.From {
		if ref == nil {
			continue
		}
		iter, err := e.buildTableRefIterator(ctx, ref, args, plan, tablePlans, queryLimit)
		if err != nil {
			return nil, nil, err
		}
		if root == nil {
			root = iter
			continue
		}
		root, err = NewNestedLoopJoinIterator(ctx, root, iter, nil)
		if err != nil {
			return nil, nil, err
		}
	}
	if root == nil {
		return nil, nil, fmt.Errorf("velocity driver: empty FROM clause")
	}
	defer root.Close()

	if sel.Where != nil {
		root = &FilterIterator{
			next: root,
			cond: e.buildWhereCondition(ctx, sel.Where, args),
		}
	}

	rows := make([]Row, 0, 32)
	for {
		row, err := root.Next(ctx)
		if err != nil {
			return nil, nil, err
		}
		if row == nil {
			break
		}
		if len(e.outerRow) > 0 {
			row = mergeRows(e.outerRow, row)
		}
		rows = append(rows, row)
	}

	if len(rows) == 0 && plan.fullText != "" {
		plan.fullText = ""
		return e.collectSourceRowsWithPlan(ctx, sel, args, plan, queryLimit)
	}

	var schemaCols []string
	if hasStarColumn(sel.Columns) {
		schemaCols = e.defaultStarColumns(sel.From)
	}
	return rows, schemaCols, nil
}

func (e *ExecutorV2) collectSourceRowsWithPlan(ctx context.Context, sel *ast.SelectStmt, args []driver.NamedValue, plan searchPlan, queryLimit int) ([]Row, []string, error) {
	var root Iterator
	for _, ref := range sel.From {
		if ref == nil {
			continue
		}
		iter, err := e.buildTableRefIterator(ctx, ref, args, plan, nil, queryLimit)
		if err != nil {
			return nil, nil, err
		}
		if root == nil {
			root = iter
			continue
		}
		root, err = NewNestedLoopJoinIterator(ctx, root, iter, nil)
		if err != nil {
			return nil, nil, err
		}
	}
	if root == nil {
		return nil, nil, fmt.Errorf("velocity driver: empty FROM clause")
	}
	defer root.Close()

	if sel.Where != nil {
		root = &FilterIterator{
			next: root,
			cond: e.buildWhereCondition(ctx, sel.Where, args),
		}
	}

	rows := make([]Row, 0, 32)
	for {
		row, err := root.Next(ctx)
		if err != nil {
			return nil, nil, err
		}
		if row == nil {
			break
		}
		if len(e.outerRow) > 0 {
			row = mergeRows(e.outerRow, row)
		}
		rows = append(rows, row)
	}

	var schemaCols []string
	if hasStarColumn(sel.Columns) {
		schemaCols = e.defaultStarColumns(sel.From)
	}
	return rows, schemaCols, nil
}

func (e *ExecutorV2) buildTableRefIterator(ctx context.Context, ref ast.TableRef, args []driver.NamedValue, plan searchPlan, tablePlans tableSearchPlans, queryLimit int) (Iterator, error) {
	switch t := ref.(type) {
	case *ast.SimpleTable:
		tableName := qualifiedIdentToString(t.Name)
		alias := tableName
		if t.Alias != nil {
			alias = identToString(t.Alias)
		}
		tablePlan := plan
		if tablePlans != nil {
			if p, ok := tablePlans[alias]; ok {
				tablePlan = mergeSearchPlans(tablePlan, p)
			}
			if alias != tableName {
				if p, ok := tablePlans[tableName]; ok {
					tablePlan = mergeSearchPlans(tablePlan, p)
				}
			}
		}
		if rows, ok := e.ctes[tableName]; ok {
			return &MemoryIterator{
				alias:  alias,
				rows:   rowMapsToResults(rows.rowMaps),
				cursor: 0,
			}, nil
		}
		if view, found, err := e.loadViewMeta(tableName); err != nil {
			return nil, err
		} else if found {
			rows, err := e.executeView(ctx, tableName, view, args)
			if err != nil {
				return nil, err
			}
			return &MemoryIterator{
				alias:  alias,
				rows:   rowMapsToResults(rows.rowMaps),
				cursor: 0,
			}, nil
		}
		if queryLimit <= 0 {
			queryLimit = maxSearchLimit
		}
		return NewConnTableScanIterator(e.conn, alias, velocity.SearchQuery{
			Prefix:   tableName,
			FullText: tablePlan.fullText,
			Filters:  tablePlan.filters,
			Limit:    queryLimit,
		})

	case *ast.SubqueryTable:
		rows, err := e.executeSelectStatement(ctx, t.Subq, args)
		if err != nil {
			return nil, err
		}
		alias := ""
		if t.Alias != nil {
			alias = identToString(t.Alias)
		}
		return &MemoryIterator{
			alias:  alias,
			rows:   rowMapsToResults(rows.rowMaps),
			cursor: 0,
		}, nil

	case *ast.JoinTable:
		left, err := e.buildTableRefIterator(ctx, t.Left, args, searchPlan{}, tablePlans, maxSearchLimit)
		if err != nil {
			return nil, err
		}
		right, err := e.buildTableRefIterator(ctx, t.Right, args, searchPlan{}, tablePlans, maxSearchLimit)
		if err != nil {
			return nil, err
		}
		return NewJoinIterator(ctx, left, right, t.Kind, e.buildJoinCondition(ctx, t, args))
	}

	return nil, fmt.Errorf("velocity driver: unsupported table reference %T", ref)
}

func (e *ExecutorV2) buildWhereCondition(ctx context.Context, expr ast.Expr, args []driver.NamedValue) func(Row) bool {
	eval := e.newEvaluator(ctx, args)
	return func(row Row) bool {
		if len(e.outerRow) > 0 {
			row = mergeRows(e.outerRow, row)
		}
		ok, err := eval.evalBool(expr, row)
		return err == nil && ok
	}
}

func (e *ExecutorV2) buildJoinCondition(ctx context.Context, join *ast.JoinTable, args []driver.NamedValue) func(Row, Row) bool {
	if join == nil {
		return nil
	}
	if len(join.Using) > 0 {
		return func(left, right Row) bool {
			for _, col := range join.Using {
				name := identToString(col)
				cmp, err := compareValues(left[name], right[name])
				if err != nil || cmp != 0 {
					return false
				}
			}
			return true
		}
	}
	if join.On == nil {
		return nil
	}

	eval := e.newEvaluator(ctx, args)
	return func(left, right Row) bool {
		merged := mergeRows(left, right)
		ok, err := eval.evalBool(join.On, merged)
		return err == nil && ok
	}
}

func (e *ExecutorV2) extractFilters(expr ast.Expr, args []driver.NamedValue) []velocity.SearchFilter {
	if expr == nil {
		return nil
	}
	eval := &Evaluator{Args: args, ParamOrder: e.paramOrder}
	switch v := expr.(type) {
	case *ast.BinaryExpr:
		switch v.Op {
		case lexer.AND:
			left := e.extractFilters(v.Left, args)
			right := e.extractFilters(v.Right, args)
			return append(left, right...)
		case lexer.EQ, lexer.NEQ, lexer.GT, lexer.GTE, lexer.LT, lexer.LTE:
			field := exprColumnName(v.Left)
			if field == "" {
				return nil
			}
			value, err := eval.Eval(v.Right, nil)
			if err != nil {
				return nil
			}
			if value == nil {
				return nil
			}
			op := tokenToFilterOp(v.Op)
			if op == "" {
				return nil
			}
			return []velocity.SearchFilter{{
				Field:    field,
				Op:       op,
				Value:    value,
				HashOnly: v.Op == lexer.EQ,
			}}
		}
	}
	return nil
}

func (e *ExecutorV2) extractSearchPlan(expr ast.Expr, args []driver.NamedValue) searchPlan {
	return searchPlan{
		filters:  e.extractFilters(expr, args),
		fullText: e.extractFullText(expr, args),
	}
}

func mergeSearchPlans(a, b searchPlan) searchPlan {
	if len(b.filters) > 0 {
		a.filters = append(a.filters, b.filters...)
	}
	if a.fullText == "" {
		a.fullText = b.fullText
	}
	return a
}

func (e *ExecutorV2) extractTableSearchPlans(expr ast.Expr, args []driver.NamedValue) tableSearchPlans {
	plans := make(tableSearchPlans)
	e.extractTableSearchPlansInto(expr, args, plans)
	if len(plans) == 0 {
		return nil
	}
	return plans
}

func (e *ExecutorV2) extractTableSearchPlansInto(expr ast.Expr, args []driver.NamedValue, plans tableSearchPlans) {
	if expr == nil {
		return
	}
	eval := &Evaluator{Args: args, ParamOrder: e.paramOrder}
	switch v := expr.(type) {
	case *ast.BinaryExpr:
		if v.Op == lexer.AND {
			e.extractTableSearchPlansInto(v.Left, args, plans)
			e.extractTableSearchPlansInto(v.Right, args, plans)
			return
		}
		switch v.Op {
		case lexer.EQ, lexer.NEQ, lexer.GT, lexer.GTE, lexer.LT, lexer.LTE:
			table, field := qualifiedExprColumn(v.Left)
			if table == "" || field == "" {
				return
			}
			value, err := eval.Eval(v.Right, nil)
			if err != nil || value == nil {
				return
			}
			op := tokenToFilterOp(v.Op)
			if op == "" {
				return
			}
			p := plans[table]
			p.filters = append(p.filters, velocity.SearchFilter{
				Field:    field,
				Op:       op,
				Value:    value,
				HashOnly: v.Op == lexer.EQ,
			})
			plans[table] = p
		}
	case *ast.LikeExpr:
		if v.Not || v.Escape != nil {
			return
		}
		table, field := qualifiedExprColumn(v.Expr)
		if table == "" || field == "" {
			return
		}
		raw, err := eval.Eval(v.Pattern, nil)
		if err != nil {
			return
		}
		pattern, ok := raw.(string)
		if !ok {
			return
		}
		term, ok := likePatternToFullText(pattern)
		if !ok {
			return
		}
		p := plans[table]
		p.fullText = strings.TrimSpace(strings.Join([]string{p.fullText, term}, " "))
		plans[table] = p
	}
}

func (e *ExecutorV2) extractFullText(expr ast.Expr, args []driver.NamedValue) string {
	if expr == nil {
		return ""
	}
	eval := &Evaluator{Args: args, ParamOrder: e.paramOrder}
	terms := make([]string, 0, 4)
	var walk func(ast.Expr)
	walk = func(node ast.Expr) {
		if node == nil {
			return
		}
		switch v := node.(type) {
		case *ast.BinaryExpr:
			if v.Op == lexer.AND {
				walk(v.Left)
				walk(v.Right)
			}
		case *ast.LikeExpr:
			if v.Not || v.Escape != nil || exprColumnName(v.Expr) == "" {
				return
			}
			raw, err := eval.Eval(v.Pattern, nil)
			if err != nil {
				return
			}
			pattern, ok := raw.(string)
			if !ok {
				return
			}
			term, ok := likePatternToFullText(pattern)
			if !ok {
				return
			}
			terms = append(terms, term)
		}
	}
	walk(expr)
	return strings.Join(dedupeStrings(terms), " ")
}

func likePatternToFullText(pattern string) (string, bool) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || strings.Contains(pattern, "_") {
		return "", false
	}
	trimmed := strings.Trim(pattern, "%")
	if trimmed == "" {
		return "", false
	}
	if strings.Contains(trimmed, "%") {
		return "", false
	}
	return trimmed, true
}

func (e *ExecutorV2) scanQueryLimit(sel *ast.SelectStmt, plan searchPlan, args []driver.NamedValue) int {
	if len(sel.OrderBy) > 0 || sel.Distinct || len(sel.GroupBy) > 0 || sel.Having != nil || sel.SetOp != nil {
		if hasExactIDFilter(plan.filters) {
			return 1
		}
		return maxSearchLimit
	}

	if hasExactIDFilter(plan.filters) {
		return 1
	}

	if sel.Limit == nil {
		return maxSearchLimit
	}

	count := e.extractCount(sel.Limit, args)
	offset := e.extractOffset(sel.Limit, args)
	if count <= 0 {
		return maxSearchLimit
	}
	return count + offset
}

func hasExactIDFilter(filters []velocity.SearchFilter) bool {
	for _, filter := range filters {
		if strings.EqualFold(filter.Field, "id") && (filter.Op == "=" || filter.Op == "==") {
			return true
		}
	}
	return false
}

func (e *ExecutorV2) tryFastCountSelect(sel *ast.SelectStmt, args []driver.NamedValue) (*Rows, bool, error) {
	if e.conn.tx != nil {
		return nil, false, nil
	}
	if sel == nil || sel.Distinct || len(sel.GroupBy) > 0 || sel.Having != nil || sel.SetOp != nil || len(sel.From) != 1 || hasJoinRef(sel.From) {
		return nil, false, nil
	}

	columnName, ok := countOnlySelectName(sel.Columns)
	if !ok {
		return nil, false, nil
	}

	tableRef, ok := sel.From[0].(*ast.SimpleTable)
	if !ok {
		return nil, false, nil
	}
	tableName := qualifiedIdentToString(tableRef.Name)
	if tableName == "" {
		return nil, false, nil
	}
	if _, found, err := e.loadViewMeta(tableName); err != nil {
		return nil, true, err
	} else if found {
		return nil, false, nil
	}
	if !e.fastCountWhereSupported(sel.Where, args) {
		return nil, false, nil
	}

	plan := e.extractSearchPlan(sel.Where, args)
	if plan.fullText != "" {
		return nil, false, nil
	}
	limit := e.extractCount(sel.Limit, args)
	count, err := e.conn.db.SearchCount(velocity.SearchQuery{
		Prefix:   tableName,
		FullText: plan.fullText,
		Filters:  plan.filters,
		Limit:    limit,
	})
	if err != nil {
		return nil, true, err
	}

	return &Rows{
		columns: []string{columnName},
		rowMaps: []Row{{columnName: count}},
	}, true, nil
}

func (e *ExecutorV2) fastCountWhereSupported(expr ast.Expr, args []driver.NamedValue) bool {
	if expr == nil {
		return true
	}
	switch v := expr.(type) {
	case *ast.BinaryExpr:
		if v.Op == lexer.AND {
			return e.fastCountWhereSupported(v.Left, args) && e.fastCountWhereSupported(v.Right, args)
		}
		if v.Op != lexer.EQ && v.Op != lexer.NEQ && v.Op != lexer.GT && v.Op != lexer.GTE && v.Op != lexer.LT && v.Op != lexer.LTE {
			return false
		}
		if exprColumnName(v.Left) == "" {
			return false
		}
		eval := &Evaluator{Args: args, ParamOrder: e.paramOrder}
		value, err := eval.Eval(v.Right, nil)
		return err == nil && value != nil
	case *ast.LikeExpr:
		if v.Not || v.Escape != nil || exprColumnName(v.Expr) == "" {
			return false
		}
		eval := &Evaluator{Args: args, ParamOrder: e.paramOrder}
		raw, err := eval.Eval(v.Pattern, nil)
		if err != nil {
			return false
		}
		pattern, ok := raw.(string)
		if !ok {
			return false
		}
		_, ok = likePatternToFullText(pattern)
		return ok
	default:
		return false
	}
}

func countOnlySelectName(cols []ast.SelectColumn) (string, bool) {
	if len(cols) != 1 || cols[0].Star {
		return "", false
	}
	call, ok := cols[0].Expr.(*ast.FuncCall)
	if !ok || !strings.EqualFold(qualifiedIdentToString(call.Name), "count") {
		return "", false
	}
	if cols[0].Alias != nil {
		return identToString(cols[0].Alias), true
	}
	return selectColumnName(cols[0]), true
}

func (e *ExecutorV2) projectRows(ctx context.Context, sel *ast.SelectStmt, sourceRows []Row, args []driver.NamedValue) ([]string, []projectedRow, error) {
	eval := e.newEvaluator(ctx, args)
	columns := explicitColumnNames(sel.Columns)
	projected := make([]projectedRow, 0, len(sourceRows))

	for _, row := range sourceRows {
		values, cols, err := projectSelectColumns(sel.Columns, row, eval)
		if err != nil {
			return nil, nil, err
		}
		if len(columns) == 0 {
			columns = cols
		}
		projected = append(projected, projectedRow{
			values:  values,
			context: row,
		})
	}

	if len(sourceRows) == 0 && len(columns) == 0 {
		columns = explicitColumnNames(sel.Columns)
	}
	return columns, projected, nil
}

func (e *ExecutorV2) projectGroupedRows(ctx context.Context, sel *ast.SelectStmt, sourceRows []Row, args []driver.NamedValue) ([]string, []projectedRow, error) {
	type groupEntry struct {
		key  string
		rows []Row
		base Row
	}

	entries := make([]groupEntry, 0)
	groupIndex := make(map[string]int)

	if len(sel.GroupBy) == 0 {
		if len(sourceRows) == 0 {
			entries = append(entries, groupEntry{key: "__all__", rows: nil, base: Row{}})
		} else {
			entries = append(entries, groupEntry{key: "__all__", rows: sourceRows, base: sourceRows[0]})
		}
	} else {
		eval := e.newEvaluator(ctx, args)
		for _, row := range sourceRows {
			groupValues := make([]interface{}, 0, len(sel.GroupBy))
			for _, expr := range sel.GroupBy {
				val, err := eval.Eval(expr, row)
				if err != nil {
					return nil, nil, err
				}
				groupValues = append(groupValues, val)
			}
			keyBytes, _ := json.Marshal(groupValues)
			key := string(keyBytes)
			idx, ok := groupIndex[key]
			if !ok {
				groupIndex[key] = len(entries)
				entries = append(entries, groupEntry{key: key, base: row})
				idx = len(entries) - 1
			}
			entries[idx].rows = append(entries[idx].rows, row)
		}
	}

	columns := explicitColumnNames(sel.Columns)
	projected := make([]projectedRow, 0, len(entries))
	for _, entry := range entries {
		values := make(Row)
		colNames := make([]string, 0, len(sel.Columns))
		for _, col := range sel.Columns {
			if col.Star {
				for _, name := range visibleColumns(entry.base) {
					values[name] = entry.base[name]
					colNames = append(colNames, name)
				}
				continue
			}
			label := selectColumnName(col)
			val, err := e.evalGroupedExpr(ctx, col.Expr, entry.base, entry.rows, args)
			if err != nil {
				return nil, nil, err
			}
			values[label] = val
			colNames = append(colNames, label)
		}
		if len(columns) == 0 {
			columns = dedupeStrings(colNames)
		}
		context := mergeRows(entry.base, values)
		if sel.Having != nil {
			having, err := e.evalGroupedExpr(ctx, sel.Having, context, entry.rows, args)
			if err != nil {
				return nil, nil, err
			}
			ok, _ := having.(bool)
			if !ok {
				continue
			}
		}
		projected = append(projected, projectedRow{
			values:  values,
			context: context,
			group:   entry.rows,
		})
	}
	return columns, projected, nil
}

func (e *ExecutorV2) evalGroupedExpr(ctx context.Context, expr ast.Expr, row Row, groupRows []Row, args []driver.NamedValue) (interface{}, error) {
	switch v := expr.(type) {
	case *ast.FuncCall:
		if isAggregateFunc(v) {
			return e.evalAggregateFunc(ctx, v, groupRows, args)
		}
	case *ast.BinaryExpr:
		left, err := e.evalGroupedExpr(ctx, v.Left, row, groupRows, args)
		if err != nil {
			return nil, err
		}
		right, err := e.evalGroupedExpr(ctx, v.Right, row, groupRows, args)
		if err != nil {
			return nil, err
		}
		return evalBinaryValues(v.Op, left, right)
	case *ast.UnaryExpr:
		val, err := e.evalGroupedExpr(ctx, v.Expr, row, groupRows, args)
		if err != nil {
			return nil, err
		}
		return evalUnaryValue(v.Op, val)
	case *ast.BetweenExpr:
		val, err := e.evalGroupedExpr(ctx, v.Expr, row, groupRows, args)
		if err != nil {
			return nil, err
		}
		lo, err := e.evalGroupedExpr(ctx, v.Lo, row, groupRows, args)
		if err != nil {
			return nil, err
		}
		hi, err := e.evalGroupedExpr(ctx, v.Hi, row, groupRows, args)
		if err != nil {
			return nil, err
		}
		cmpLo, err := compareValues(val, lo)
		if err != nil {
			return false, nil
		}
		cmpHi, err := compareValues(val, hi)
		if err != nil {
			return false, nil
		}
		ok := cmpLo >= 0 && cmpHi <= 0
		if v.Not {
			return !ok, nil
		}
		return ok, nil
	case *ast.LikeExpr:
		val, err := e.evalGroupedExpr(ctx, v.Expr, row, groupRows, args)
		if err != nil {
			return nil, err
		}
		pat, err := e.evalGroupedExpr(ctx, v.Pattern, row, groupRows, args)
		if err != nil {
			return nil, err
		}
		ok := matchLikePattern(fmt.Sprintf("%v", val), fmt.Sprintf("%v", pat))
		if v.Not {
			return !ok, nil
		}
		return ok, nil
	case *ast.IsNullExpr:
		val, err := e.evalGroupedExpr(ctx, v.Expr, row, groupRows, args)
		if err != nil {
			return nil, err
		}
		ok := val == nil
		if v.Not {
			return !ok, nil
		}
		return ok, nil
	case *ast.CaseExpr:
		return e.newEvaluator(ctx, args).evalCase(v, row)
	}
	return e.newEvaluator(ctx, args).Eval(expr, row)
}

func (e *ExecutorV2) evalAggregateFunc(ctx context.Context, call *ast.FuncCall, groupRows []Row, args []driver.NamedValue) (interface{}, error) {
	name := strings.ToUpper(qualifiedIdentToString(call.Name))
	eval := e.newEvaluator(ctx, args)
	switch name {
	case "COUNT":
		if call.Star || len(call.Args) == 0 {
			return int64(len(groupRows)), nil
		}
		count := 0
		seen := make(map[string]struct{})
		for _, row := range groupRows {
			val, err := eval.Eval(call.Args[0], row)
			if err != nil || val == nil {
				continue
			}
			if call.Distinct {
				key := distinctKey(val)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
			}
			count++
		}
		return int64(count), nil
	case "SUM", "AVG":
		var sum float64
		var count int
		seen := make(map[string]struct{})
		for _, row := range groupRows {
			if len(call.Args) == 0 {
				continue
			}
			val, err := eval.Eval(call.Args[0], row)
			if err != nil || val == nil {
				continue
			}
			if call.Distinct {
				key := distinctKey(val)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
			}
			num, ok := asFloat(val)
			if !ok {
				continue
			}
			sum += num
			count++
		}
		if name == "SUM" {
			return sum, nil
		}
		if count == 0 {
			return nil, nil
		}
		return sum / float64(count), nil
	case "MIN", "MAX":
		var best interface{}
		seen := false
		for _, row := range groupRows {
			if len(call.Args) == 0 {
				continue
			}
			val, err := eval.Eval(call.Args[0], row)
			if err != nil || val == nil {
				continue
			}
			if !seen {
				best = val
				seen = true
				continue
			}
			cmp, err := compareValues(val, best)
			if err != nil {
				continue
			}
			if (name == "MIN" && cmp < 0) || (name == "MAX" && cmp > 0) {
				best = val
			}
		}
		return best, nil
	}
	return eval.Eval(call, nil)
}

func (e *ExecutorV2) sortProjectedRows(ctx context.Context, rows []projectedRow, order []ast.OrderByItem, args []driver.NamedValue) error {
	var sortErr error
	sort.SliceStable(rows, func(i, j int) bool {
		if sortErr != nil {
			return false
		}
		for _, item := range order {
			iv, err := e.orderValue(ctx, item.Expr, rows[i], args)
			if err != nil {
				sortErr = err
				return false
			}
			jv, err := e.orderValue(ctx, item.Expr, rows[j], args)
			if err != nil {
				sortErr = err
				return false
			}
			cmp, ok := compareOrderValues(iv, jv)
			if !ok || cmp == 0 {
				continue
			}
			if item.Desc {
				return cmp > 0
			}
			return cmp < 0
		}
		return false
	})
	return sortErr
}

func (e *ExecutorV2) orderValue(ctx context.Context, expr ast.Expr, row projectedRow, args []driver.NamedValue) (interface{}, error) {
	if ident, ok := expr.(*ast.Ident); ok {
		if val, exists := row.values[ident.Unquoted]; exists {
			return val, nil
		}
	}
	ctxRow := mergeRows(row.context, row.values)
	if row.group != nil {
		return e.evalGroupedExpr(ctx, expr, ctxRow, row.group, args)
	}
	return e.newEvaluator(ctx, args).Eval(expr, ctxRow)
}

func (e *ExecutorV2) newEvaluator(ctx context.Context, args []driver.NamedValue) *Evaluator {
	return &Evaluator{
		Args:       args,
		ParamOrder: e.paramOrder,
		SubqueryRunner: func(stmt *ast.SelectStmt, outer Row) ([]Row, error) {
			child := *e
			if len(e.outerRow) > 0 && len(outer) > 0 {
				child.outerRow = mergeRows(e.outerRow, outer)
			} else if len(outer) > 0 {
				child.outerRow = outer
			}
			rows, err := child.executeSelectStatement(ctx, stmt, args)
			if err != nil {
				return nil, err
			}
			return rows.rowMaps, nil
		},
	}
}

func (e *ExecutorV2) selectMutationRows(ctx context.Context, tables []ast.TableRef, where ast.Expr, order []ast.OrderByItem, limit *ast.LimitClause, args []driver.NamedValue) ([]Row, error) {
	sel := &ast.SelectStmt{From: tables, Where: where}
	sourceRows, _, err := e.collectSourceRows(ctx, sel, args)
	if err != nil {
		return nil, err
	}
	projected := make([]projectedRow, 0, len(sourceRows))
	for _, row := range sourceRows {
		projected = append(projected, projectedRow{values: row, context: row})
	}
	if len(order) > 0 {
		if err := e.sortProjectedRows(ctx, projected, order, args); err != nil {
			return nil, err
		}
	}
	projected = applyOffsetLimit(projected, e.extractOffset(limit, args), e.extractCount(limit, args))
	return rowMapsFromProjected(projected), nil
}

func (e *ExecutorV2) insertColumns(tableName string, cols []*ast.Ident) ([]string, error) {
	if len(cols) > 0 {
		out := make([]string, 0, len(cols))
		for _, col := range cols {
			out = append(out, identToString(col))
		}
		return out, nil
	}
	meta, found, err := e.loadTableSchemaMeta(tableName)
	if err != nil {
		return nil, err
	}
	if found && len(meta.Columns) > 0 {
		return append([]string(nil), meta.Columns...), nil
	}
	return nil, fmt.Errorf("velocity driver: INSERT requires an explicit column list for table %s", tableName)
}

func (e *ExecutorV2) schemaMetaFromCreateStmt(ctx context.Context, stmt *ast.CreateTableStmt, args []driver.NamedValue) (tableSchemaMeta, error) {
	if stmt.Like != nil {
		meta, found, err := e.loadTableSchemaMeta(qualifiedIdentToString(stmt.Like))
		if err != nil {
			return tableSchemaMeta{}, err
		}
		if found {
			return meta, nil
		}
	}

	meta := tableSchemaMeta{}
	fieldByName := make(map[string]*velocity.SearchSchemaField)
	for _, col := range stmt.Columns {
		name := identToString(col.Name)
		meta.Columns = append(meta.Columns, name)
		field := velocity.SearchSchemaField{Name: name, Searchable: true}
		if col.PrimaryKey || col.Unique {
			field.HashSearch = true
		}
		if col.PrimaryKey {
			meta.PrimaryKey = name
			meta.Unique = appendUniqueString(meta.Unique, name)
			meta.NotNull = appendUniqueString(meta.NotNull, name)
		}
		if col.Unique {
			meta.Unique = appendUniqueString(meta.Unique, name)
		}
		if col.NotNull {
			meta.NotNull = appendUniqueString(meta.NotNull, name)
		}
		if meta.SearchSchema == nil {
			meta.SearchSchema = &velocity.SearchSchema{}
		}
		meta.SearchSchema.Fields = append(meta.SearchSchema.Fields, field)
		fieldByName[name] = &meta.SearchSchema.Fields[len(meta.SearchSchema.Fields)-1]
	}
	for _, constraint := range stmt.Constraints {
		if constraint.Type != ast.PrimaryKeyConstraint && constraint.Type != ast.UniqueConstraint {
			continue
		}
		if len(constraint.Columns) != 1 {
			return tableSchemaMeta{}, fmt.Errorf("velocity driver: composite %s constraints are not supported", strings.ToLower(string(constraint.Type)))
		}
		name := identToString(constraint.Columns[0].Name)
		if field, ok := fieldByName[name]; ok {
			field.HashSearch = true
		}
		if constraint.Type == ast.PrimaryKeyConstraint {
			meta.PrimaryKey = name
			meta.Unique = appendUniqueString(meta.Unique, name)
			meta.NotNull = appendUniqueString(meta.NotNull, name)
		}
		if constraint.Type == ast.UniqueConstraint {
			meta.Unique = appendUniqueString(meta.Unique, name)
		}
	}

	if stmt.Select != nil {
		rows, err := e.executeSelectStatement(ctx, stmt.Select, args)
		if err != nil {
			return tableSchemaMeta{}, err
		}
		if len(meta.Columns) == 0 {
			meta.Columns = append(meta.Columns, rows.Columns()...)
		}
		if meta.SearchSchema == nil && len(meta.Columns) > 0 {
			meta.SearchSchema = &velocity.SearchSchema{}
			for _, col := range meta.Columns {
				meta.SearchSchema.Fields = append(meta.SearchSchema.Fields, velocity.SearchSchemaField{
					Name:       col,
					Searchable: true,
				})
			}
		}
	}
	return meta, nil
}

func (e *ExecutorV2) saveTableSchemaMeta(tableName string, meta tableSchemaMeta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	if err := e.conn.Put(schemaStorageKey(tableName), data); err != nil {
		return err
	}
	e.conn.db.SetSearchSchemaForPrefix(tableName, meta.SearchSchema)
	e.conn.markSchemaChanged()
	return nil
}

func (e *ExecutorV2) loadTableSchemaMeta(tableName string) (tableSchemaMeta, bool, error) {
	data, err := e.conn.db.Get(schemaStorageKey(tableName))
	if err != nil {
		return tableSchemaMeta{}, false, nil
	}
	var meta tableSchemaMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return tableSchemaMeta{}, false, err
	}
	return meta, true, nil
}

func (e *ExecutorV2) saveViewMeta(viewName string, meta viewMeta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	if err := e.conn.Put(viewStorageKey(viewName), data); err != nil {
		return err
	}
	e.conn.markSchemaChanged()
	return nil
}

func (e *ExecutorV2) loadViewMeta(viewName string) (viewMeta, bool, error) {
	data, err := e.conn.db.Get(viewStorageKey(viewName))
	if err != nil {
		return viewMeta{}, false, nil
	}
	var meta viewMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return viewMeta{}, false, err
	}
	return meta, true, nil
}

func (e *ExecutorV2) executeView(ctx context.Context, viewName string, meta viewMeta, args []driver.NamedValue) (*Rows, error) {
	stmt, err := parseViewSelect(meta.Select)
	if err != nil {
		return nil, fmt.Errorf("velocity driver: invalid view %s: %w", viewName, err)
	}
	child := *e
	rows, err := child.executeSelectStatement(ctx, stmt, args)
	if err != nil {
		return nil, err
	}
	if len(meta.Columns) > 0 {
		rows = renameRowsColumns(rows, meta.Columns)
	}
	return rows, nil
}

func (e *ExecutorV2) defaultStarColumns(from []ast.TableRef) []string {
	if len(from) != 1 {
		return nil
	}
	table, ok := from[0].(*ast.SimpleTable)
	if !ok {
		return nil
	}
	meta, found, err := e.loadTableSchemaMeta(qualifiedIdentToString(table.Name))
	if err != nil || !found {
		return nil
	}
	return append([]string(nil), meta.Columns...)
}

func (e *ExecutorV2) extractCount(limit *ast.LimitClause, args []driver.NamedValue) int {
	if limit == nil || limit.Count == nil {
		return maxSearchLimit
	}
	return exprToPositiveInt(limit.Count, args, e.paramOrder, maxSearchLimit)
}

func (e *ExecutorV2) extractOffset(limit *ast.LimitClause, args []driver.NamedValue) int {
	if limit == nil || limit.Offset == nil {
		return 0
	}
	return exprToPositiveInt(limit.Offset, args, e.paramOrder, 0)
}

func (e *ExecutorV2) applyPutOperations(ops []putOperation) error {
	if len(ops) == 0 {
		return nil
	}
	if e.conn.tx != nil {
		for _, op := range ops {
			if err := e.conn.Put(op.key, op.value); err != nil {
				return err
			}
		}
		for _, op := range ops {
			e.conn.markRowsChanged([][]byte{op.key})
		}
		return nil
	}
	bw := e.conn.db.NewBatchWriter(len(ops))
	for _, op := range ops {
		if err := bw.Put(op.key, op.value); err != nil {
			return err
		}
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	keys := make([][]byte, 0, len(ops))
	for _, op := range ops {
		keys = append(keys, op.key)
	}
	e.conn.markRowsChanged(keys)
	return nil
}

func (e *ExecutorV2) applyDeleteOperations(keys [][]byte) error {
	if len(keys) == 0 {
		return nil
	}
	if e.conn.tx != nil {
		for _, key := range keys {
			if err := e.conn.Delete(key); err != nil {
				return err
			}
		}
		e.conn.markRowsChanged(keys)
		return nil
	}
	bw := e.conn.db.NewBatchWriter(len(keys))
	for _, key := range keys {
		if err := bw.Delete(key); err != nil {
			return err
		}
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	e.conn.markRowsChanged(keys)
	return nil
}

func applySetOperation(left, right *Rows, op *ast.SetOperation) *Rows {
	switch op.Op {
	case ast.Union:
		left.rowMaps = append(left.rowMaps, right.rowMaps...)
		if !op.All {
			left.rowMaps = rowMapsFromProjected(distinctProjectedRows(toProjectedRows(left.rowMaps)))
		}
	case ast.Intersect:
		rightSet := make(map[string]struct{}, len(right.rowMaps))
		for _, row := range right.rowMaps {
			rightSet[distinctKey(row)] = struct{}{}
		}
		filtered := make([]Row, 0, len(left.rowMaps))
		for _, row := range left.rowMaps {
			if _, ok := rightSet[distinctKey(row)]; ok {
				filtered = append(filtered, row)
			}
		}
		left.rowMaps = filtered
	case ast.Except:
		rightSet := make(map[string]struct{}, len(right.rowMaps))
		for _, row := range right.rowMaps {
			rightSet[distinctKey(row)] = struct{}{}
		}
		filtered := make([]Row, 0, len(left.rowMaps))
		for _, row := range left.rowMaps {
			if _, ok := rightSet[distinctKey(row)]; !ok {
				filtered = append(filtered, row)
			}
		}
		left.rowMaps = filtered
	}
	if len(left.columns) == 0 {
		left.columns = right.columns
	}
	return left
}

func explicitColumnNames(cols []ast.SelectColumn) []string {
	if len(cols) == 0 {
		return nil
	}
	out := make([]string, 0, len(cols))
	for _, col := range cols {
		if col.Star {
			return nil
		}
		out = append(out, selectColumnName(col))
	}
	return out
}

func selectColumnName(col ast.SelectColumn) string {
	if col.Alias != nil {
		return identToString(col.Alias)
	}
	switch expr := col.Expr.(type) {
	case *ast.Ident:
		return expr.Unquoted
	case *ast.QualifiedIdent:
		if len(expr.Parts) > 0 {
			return expr.Parts[len(expr.Parts)-1].Unquoted
		}
	case *ast.FuncCall:
		return strings.ToLower(qualifiedIdentToString(expr.Name))
	}
	return "expr"
}

func projectSelectColumns(cols []ast.SelectColumn, row Row, eval *Evaluator) (Row, []string, error) {
	projected := make(Row)
	names := make([]string, 0, len(cols))
	for _, col := range cols {
		if col.Star {
			for _, name := range visibleColumns(row) {
				projected[name] = row[name]
				names = append(names, name)
			}
			continue
		}
		val, err := eval.Eval(col.Expr, row)
		if err != nil {
			return nil, nil, err
		}
		name := selectColumnName(col)
		projected[name] = val
		names = append(names, name)
	}
	return projected, dedupeStrings(names), nil
}

func visibleColumns(row Row) []string {
	cols := make([]string, 0, len(row))
	for key := range row {
		if strings.HasPrefix(key, "_") || strings.Contains(key, ".") {
			continue
		}
		cols = append(cols, key)
	}
	sort.Strings(cols)
	return cols
}

func mergeRows(left, right Row) Row {
	merged := make(Row, len(left)+len(right))
	for k, v := range left {
		merged[k] = v
	}
	for k, v := range right {
		merged[k] = v
	}
	return merged
}

func normalizeProjectedRow(row Row) map[string]interface{} {
	data := make(map[string]interface{})
	for key, value := range row {
		if strings.HasPrefix(key, "_") || strings.Contains(key, ".") {
			continue
		}
		data[key] = value
	}
	return data
}

func rowMapsToResults(rows []Row) []velocity.SearchResult {
	out := make([]velocity.SearchResult, 0, len(rows))
	for i, row := range rows {
		out = append(out, velocity.SearchResult{
			Key:   []byte(fmt.Sprintf("row:%d", i)),
			Value: rowToJSONBytes(row),
		})
	}
	return out
}

func renameCTEColumns(rows *Rows, aliases []*ast.Ident) *Rows {
	if rows == nil || len(aliases) == 0 {
		return rows
	}
	names := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		name := identToString(alias)
		if name != "" {
			names = append(names, name)
		}
	}
	return renameRowsColumns(rows, names)
}

func renameRowsColumns(rows *Rows, names []string) *Rows {
	if rows == nil || len(names) == 0 {
		return rows
	}
	limit := len(names)
	if limit > len(rows.columns) {
		limit = len(rows.columns)
	}
	if limit == 0 {
		return rows
	}
	oldCols := append([]string(nil), rows.columns...)
	newCols := append([]string(nil), rows.columns...)
	for i := 0; i < limit; i++ {
		if names[i] != "" {
			newCols[i] = names[i]
		}
	}
	renamed := make([]Row, 0, len(rows.rowMaps))
	for _, row := range rows.rowMaps {
		next := make(Row, len(row))
		for k, v := range row {
			next[k] = v
		}
		for i := 0; i < limit; i++ {
			oldName := oldCols[i]
			newName := newCols[i]
			if oldName == newName || newName == "" {
				continue
			}
			if v, ok := row[oldName]; ok {
				next[newName] = v
				delete(next, oldName)
			}
		}
		renamed = append(renamed, next)
	}
	return &Rows{
		columns:    newCols,
		schemaCols: rows.schemaCols,
		rowMaps:    renamed,
	}
}

func rowToJSONBytes(row Row) []byte {
	data, _ := json.Marshal(row)
	return data
}

func insertKey(tableName string, data map[string]interface{}, rowNum int64) (string, interface{}) {
	if id, ok := data["id"]; ok {
		return fmt.Sprintf("%s:%v", tableName, id), id
	}
	if rowNumRaw, ok := data["_rownum"]; ok {
		return fmt.Sprintf("%s:%d:%v", tableName, time.Now().UnixNano(), rowNumRaw), nil
	}
	return fmt.Sprintf("%s:%d", tableName, time.Now().UnixNano()), nil
}

func (e *ExecutorV2) fastInsertPayload(tableName string, columns []string, encodedColumns [][]byte, rowExprs []ast.Expr, eval *Evaluator, inserted int64, multiRow bool, rowIdx int) (string, interface{}, []byte, map[string]interface{}, error) {
	var keyValue interface{}
	data := make(map[string]interface{}, len(rowExprs))
	payload := make([]byte, 0, 96)
	payload = append(payload, '{')
	for colIdx, expr := range rowExprs {
		val, err := eval.Eval(expr, nil)
		if err != nil {
			return "", nil, nil, nil, err
		}
		data[columns[colIdx]] = val
		if colIdx > 0 {
			payload = append(payload, ',')
		}
		payload = append(payload, encodedColumns[colIdx]...)
		payload = append(payload, ':')
		payload = appendJSONValue(payload, val)
		if columns[colIdx] == "id" {
			keyValue = val
		}
	}
	payload = append(payload, '}')

	if keyValue != nil {
		return fmt.Sprintf("%s:%v", tableName, keyValue), keyValue, payload, data, nil
	}
	if multiRow {
		return fmt.Sprintf("%s:%d:%d", tableName, time.Now().UnixNano(), rowIdx), nil, payload, data, nil
	}
	return fmt.Sprintf("%s:%d", tableName, time.Now().UnixNano()), nil, payload, data, nil
}

func appendJSONValue(dst []byte, value interface{}) []byte {
	switch v := value.(type) {
	case nil:
		return append(dst, "null"...)
	case string:
		return strconv.AppendQuote(dst, v)
	case []byte:
		return strconv.AppendQuote(dst, string(v))
	case bool:
		return strconv.AppendBool(dst, v)
	case int:
		return strconv.AppendInt(dst, int64(v), 10)
	case int8:
		return strconv.AppendInt(dst, int64(v), 10)
	case int16:
		return strconv.AppendInt(dst, int64(v), 10)
	case int32:
		return strconv.AppendInt(dst, int64(v), 10)
	case int64:
		return strconv.AppendInt(dst, v, 10)
	case uint:
		return strconv.AppendUint(dst, uint64(v), 10)
	case uint8:
		return strconv.AppendUint(dst, uint64(v), 10)
	case uint16:
		return strconv.AppendUint(dst, uint64(v), 10)
	case uint32:
		return strconv.AppendUint(dst, uint64(v), 10)
	case uint64:
		return strconv.AppendUint(dst, v, 10)
	case float32:
		return strconv.AppendFloat(dst, float64(v), 'f', -1, 32)
	case float64:
		return strconv.AppendFloat(dst, v, 'f', -1, 64)
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return append(dst, "null"...)
		}
		return append(dst, encoded...)
	}
}

func schemaStorageKey(tableName string) []byte {
	return []byte(tableSchemaPrefix + tableName)
}

func viewStorageKey(viewName string) []byte {
	return []byte(viewPrefix + viewName)
}

func extractCreateViewSelectSQL(query string) (string, error) {
	query = strings.TrimSpace(strings.TrimSuffix(query, ";"))
	if query == "" {
		return "", fmt.Errorf("velocity driver: CREATE VIEW requires original SQL text")
	}
	upper := strings.ToUpper(query)
	for i := 0; i < len(upper)-1; i++ {
		if upper[i] != 'A' || upper[i+1] != 'S' {
			continue
		}
		if i > 0 && isSQLIdentByte(upper[i-1]) {
			continue
		}
		j := i + 2
		for j < len(upper) && isSQLSpaceByte(upper[j]) {
			j++
		}
		if strings.HasPrefix(upper[j:], "SELECT") || strings.HasPrefix(upper[j:], "WITH") {
			return strings.TrimSpace(query[j:]), nil
		}
	}
	return "", fmt.Errorf("velocity driver: CREATE VIEW missing AS SELECT")
}

func parseViewSelect(sqlText string) (*ast.SelectStmt, error) {
	parser := sqlparser.NewString(sqlText)
	stmt, err := parser.Next()
	if err != nil {
		return nil, err
	}
	sel, ok := stmt.(*ast.SelectStmt)
	if !ok {
		return nil, fmt.Errorf("view definition must be a SELECT, got %T", stmt)
	}
	return sel, nil
}

func isSQLSpaceByte(b byte) bool {
	return b == ' ' || b == '\n' || b == '\r' || b == '\t'
}

func isSQLIdentByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func exprToPositiveInt(expr ast.Expr, args []driver.NamedValue, paramOrder map[int32]int, fallback int) int {
	eval := &Evaluator{Args: args, ParamOrder: paramOrder}
	raw, err := eval.Eval(expr, nil)
	if err != nil {
		return fallback
	}
	switch v := raw.(type) {
	case int:
		if v >= 0 {
			return v
		}
	case int32:
		if v >= 0 {
			return int(v)
		}
	case int64:
		if v >= 0 {
			return int(v)
		}
	case float64:
		if v >= 0 {
			return int(v)
		}
	}
	return fallback
}

func tokenToFilterOp(op lexer.TokenType) string {
	switch op {
	case lexer.EQ:
		return "="
	case lexer.NEQ:
		return "!="
	case lexer.GT:
		return ">"
	case lexer.GTE:
		return ">="
	case lexer.LT:
		return "<"
	case lexer.LTE:
		return "<="
	default:
		return ""
	}
}

func exprColumnName(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.Ident:
		return v.Unquoted
	case *ast.QualifiedIdent:
		if len(v.Parts) > 0 {
			return v.Parts[len(v.Parts)-1].Unquoted
		}
	}
	return ""
}

func qualifiedExprColumn(expr ast.Expr) (string, string) {
	v, ok := expr.(*ast.QualifiedIdent)
	if !ok || len(v.Parts) < 2 {
		return "", ""
	}
	table := v.Parts[len(v.Parts)-2].Unquoted
	field := v.Parts[len(v.Parts)-1].Unquoted
	return table, field
}

func hasJoinRef(refs []ast.TableRef) bool {
	for _, ref := range refs {
		if ref == nil {
			continue
		}
		if hasJoinInRef(ref) {
			return true
		}
	}
	return false
}

func hasJoinInRef(ref ast.TableRef) bool {
	switch ref.(type) {
	case *ast.JoinTable:
		return true
	case *ast.SubqueryTable:
		return false
	case *ast.SimpleTable:
		return false
	default:
		return false
	}
}

func hasStarColumn(cols []ast.SelectColumn) bool {
	for _, col := range cols {
		if col.Star {
			return true
		}
	}
	return false
}

func selectHasAggregate(sel *ast.SelectStmt) bool {
	for _, col := range sel.Columns {
		if exprHasAggregate(col.Expr) {
			return true
		}
	}
	return exprHasAggregate(sel.Having)
}

func exprHasAggregate(expr ast.Expr) bool {
	switch v := expr.(type) {
	case nil:
		return false
	case *ast.FuncCall:
		if isAggregateFunc(v) {
			return true
		}
		for _, arg := range v.Args {
			if exprHasAggregate(arg) {
				return true
			}
		}
	case *ast.BinaryExpr:
		return exprHasAggregate(v.Left) || exprHasAggregate(v.Right)
	case *ast.UnaryExpr:
		return exprHasAggregate(v.Expr)
	case *ast.BetweenExpr:
		return exprHasAggregate(v.Expr) || exprHasAggregate(v.Lo) || exprHasAggregate(v.Hi)
	case *ast.InExpr:
		if exprHasAggregate(v.Expr) {
			return true
		}
		for _, item := range v.List {
			if exprHasAggregate(item) {
				return true
			}
		}
	case *ast.LikeExpr:
		return exprHasAggregate(v.Expr) || exprHasAggregate(v.Pattern) || exprHasAggregate(v.Escape)
	case *ast.IsNullExpr:
		return exprHasAggregate(v.Expr)
	case *ast.CaseExpr:
		if exprHasAggregate(v.Operand) || exprHasAggregate(v.Else) {
			return true
		}
		for _, when := range v.Whens {
			if exprHasAggregate(when.Cond) || exprHasAggregate(when.Result) {
				return true
			}
		}
	}
	return false
}

func isAggregateFunc(call *ast.FuncCall) bool {
	switch strings.ToUpper(qualifiedIdentToString(call.Name)) {
	case "COUNT", "SUM", "AVG", "MIN", "MAX":
		return true
	default:
		return false
	}
}

func evalBinaryValues(op lexer.TokenType, left, right interface{}) (interface{}, error) {
	switch op {
	case lexer.AND:
		return truthy(left) && truthy(right), nil
	case lexer.OR:
		return truthy(left) || truthy(right), nil
	case lexer.EQ, lexer.NEQ, lexer.GT, lexer.GTE, lexer.LT, lexer.LTE:
		if left == nil || right == nil {
			return false, nil
		}
		cmp, err := compareValues(left, right)
		if err != nil {
			return false, nil
		}
		switch op {
		case lexer.EQ:
			return cmp == 0, nil
		case lexer.NEQ:
			return cmp != 0, nil
		case lexer.GT:
			return cmp > 0, nil
		case lexer.GTE:
			return cmp >= 0, nil
		case lexer.LT:
			return cmp < 0, nil
		case lexer.LTE:
			return cmp <= 0, nil
		}
	case lexer.PLUS, lexer.MINUS, lexer.STAR, lexer.SLASH, lexer.PERCENT:
		return evalArithmeticValues(op, left, right)
	case lexer.DBAR:
		return fmt.Sprintf("%v%v", left, right), nil
	}
	return nil, fmt.Errorf("velocity engine: unsupported binary operator %v", op)
}

func evalUnaryValue(op lexer.TokenType, val interface{}) (interface{}, error) {
	switch op {
	case lexer.NOT:
		return !truthy(val), nil
	case lexer.MINUS:
		f, ok := asFloat(val)
		if !ok {
			return nil, fmt.Errorf("velocity engine: cannot negate %T", val)
		}
		return -f, nil
	case lexer.PLUS:
		return val, nil
	}
	return nil, fmt.Errorf("velocity engine: unsupported unary operator %v", op)
}

func evalArithmeticValues(op lexer.TokenType, left, right interface{}) (interface{}, error) {
	lf, lok := asFloat(left)
	rf, rok := asFloat(right)
	if !lok || !rok {
		return nil, fmt.Errorf("velocity engine: arithmetic on non-numeric values")
	}
	switch op {
	case lexer.PLUS:
		return lf + rf, nil
	case lexer.MINUS:
		return lf - rf, nil
	case lexer.STAR:
		return lf * rf, nil
	case lexer.SLASH:
		if rf == 0 {
			return nil, fmt.Errorf("velocity engine: division by zero")
		}
		return lf / rf, nil
	case lexer.PERCENT:
		if rf == 0 {
			return nil, fmt.Errorf("velocity engine: modulo by zero")
		}
		return float64(int64(lf) % int64(rf)), nil
	}
	return nil, fmt.Errorf("velocity engine: unsupported arithmetic operator %v", op)
}

func truthy(val interface{}) bool {
	switch v := val.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != "" && !strings.EqualFold(v, "false") && v != "0"
	default:
		f, ok := asFloat(val)
		return ok && f != 0
	}
}

func compareOrderValues(left, right interface{}) (int, bool) {
	if left == nil && right == nil {
		return 0, false
	}
	if left == nil {
		return 1, true
	}
	if right == nil {
		return -1, true
	}
	cmp, err := compareValues(left, right)
	if err != nil {
		return 0, false
	}
	return cmp, true
}

func distinctProjectedRows(rows []projectedRow) []projectedRow {
	seen := make(map[string]struct{}, len(rows))
	out := make([]projectedRow, 0, len(rows))
	for _, row := range rows {
		key := distinctKey(row.values)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, row)
	}
	return out
}

func applyOffsetLimit(rows []projectedRow, offset, limit int) []projectedRow {
	if offset >= len(rows) {
		return nil
	}
	rows = rows[offset:]
	if limit >= 0 && limit < len(rows) {
		return rows[:limit]
	}
	return rows
}

func distinctKey(value interface{}) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func toProjectedRows(rows []Row) []projectedRow {
	out := make([]projectedRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, projectedRow{values: row, context: row})
	}
	return out
}

func rowMapsFromProjected(rows []projectedRow) []Row {
	out := make([]Row, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.values)
	}
	return out
}
