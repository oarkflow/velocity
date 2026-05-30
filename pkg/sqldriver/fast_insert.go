package sqldriver

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strconv"
	"unsafe"

	sqlparser "github.com/oarkflow/sqlparser"
	"github.com/oarkflow/sqlparser/ast"
	"github.com/oarkflow/velocity"
)

type simpleInsertPlan struct {
	table          string
	columns        []string
	encodedCols    [][]byte
	paramOrdinals  []int
	idIndex        int
	payloadScratch []byte
	keyScratch     []byte
	fieldsScratch  []velocity.IndexFieldValue
	indexScratch   []velocity.IndexFieldValue
	valuesScratch  []any
	constraints    rawInsertConstraintPlan
	constraintVer  uint64
	constraintOK   bool
}

func newSimpleInsertPlan(stmt sqlparser.Statement, paramOrder map[int32]int) *simpleInsertPlan {
	n, ok := stmt.(*ast.InsertStmt)
	if !ok || n.Select != nil || n.Ignore || n.OnConflictDoNothing || len(n.OnDupKey) > 0 || len(n.OnConflictUpdate) > 0 {
		return nil
	}
	if len(n.Columns) == 0 || len(n.Values) != 1 || len(n.Values[0]) != len(n.Columns) {
		return nil
	}

	plan := &simpleInsertPlan{
		table:         qualifiedIdentToString(n.Table),
		columns:       make([]string, len(n.Columns)),
		encodedCols:   make([][]byte, len(n.Columns)),
		paramOrdinals: make([]int, len(n.Columns)),
		idIndex:       -1,
	}
	for i, col := range n.Columns {
		plan.columns[i] = identToString(col)
		plan.encodedCols[i] = strconv.AppendQuote(nil, plan.columns[i])
		if plan.columns[i] == "id" {
			plan.idIndex = i
		}
		param, ok := n.Values[0][i].(*ast.Param)
		if !ok || string(param.Raw) != "?" {
			return nil
		}
		ordinal := i + 1
		if paramOrder != nil {
			var found bool
			ordinal, found = paramOrder[param.TokPos]
			if !found {
				return nil
			}
		}
		plan.paramOrdinals[i] = ordinal
	}
	return plan
}

func (p *simpleInsertPlan) Exec(ctx context.Context, conn *Conn, args []driver.NamedValue) (driver.Result, error) {
	constraints, err := p.constraintPlan(conn)
	if err != nil {
		return nil, err
	}
	data := make(map[string]any, len(p.columns))
	for i, ordinal := range p.paramOrdinals {
		value, err := namedArgByOrdinal(args, ordinal)
		if err != nil {
			return nil, err
		}
		data[p.columns[i]] = value
	}
	eval := &Evaluator{Args: args}
	data, err = applyInsertDefaultsAndTypes(p.table, constraints.meta, data, eval)
	if err != nil {
		return nil, err
	}

	var lastInsertID int64
	keyString, keyValue := insertKey(p.table, constraints.meta, data, 0)
	if keyValue != nil {
		if id, ok := asFloat(keyValue); ok {
			lastInsertID = int64(id)
		}
	}
	key := []byte(keyString)
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	fields := indexFieldsFromData(constraints.meta, data)

	var ownedKey []byte
	var ownedPayload []byte
	ownedKeyString := ""
	if conn.tx != nil {
		buf := make([]byte, len(key)+len(payload))
		ownedKey = buf[:len(key)]
		ownedPayload = buf[len(key):]
		copy(ownedKey, key)
		copy(ownedPayload, payload)
		if len(ownedKey) > 0 {
			ownedKeyString = unsafe.String(&ownedKey[0], len(ownedKey))
		}
	}
	if conn.tx == nil {
		unlock, err := conn.lockRows(ctx, []string{string(key)})
		if err != nil {
			return nil, err
		}
		defer unlock()
	}
	if err := conn.checkInsertConstraintsForData(p.table, constraints.meta, data, string(key), nil); err != nil {
		return nil, err
	}
	executor := &ExecutorV2{conn: conn}
	if err := executor.validateSQLTableCompliance(ctx, p.table, "write", false); err != nil {
		return nil, err
	}
	if err := executor.validateSQLRowCompliance(ctx, p.table, string(key), "write", false); err != nil {
		return nil, err
	}
	if err := executor.validateSQLColumnsCompliance(ctx, p.table, mapKeys(data), "write", false); err != nil {
		return nil, err
	}
	if ownedKeyString != "" {
		err = conn.PutNewOwnedTableRowWithIndexFieldPairsKeyString(p.table, ownedKey, ownedKeyString, ownedPayload, fields)
	} else {
		err = conn.PutNewTableRowWithIndexFieldPairs(p.table, key, payload, fields)
	}
	if err != nil {
		return nil, err
	}
	p.keyScratch = key[:0]
	return singleInsertResult(lastInsertID), nil
}

func (p *simpleInsertPlan) constraintPlan(conn *Conn) (rawInsertConstraintPlan, error) {
	if p.constraintOK && p.constraintVer == conn.schemaVersion {
		return p.constraints, nil
	}
	meta, found, err := conn.loadSchemaMeta(p.table)
	if err != nil || !found {
		p.constraints = rawInsertConstraintPlan{}
		p.constraintVer = conn.schemaVersion
		p.constraintOK = true
		return p.constraints, err
	}
	plan := rawInsertConstraintPlan{
		table:           p.table,
		meta:            meta,
		found:           true,
		columnIndexes:   make(map[string]int, len(p.columns)),
		primaryKeyIndex: -1,
	}
	for i, col := range p.columns {
		plan.columnIndexes[col] = i
	}
	plan.finish()
	p.constraints = plan
	p.constraintVer = conn.schemaVersion
	p.constraintOK = true
	return plan, nil
}

func (p *simpleInsertPlan) indexFieldsForSchema(fields []velocity.IndexFieldValue, schema *velocity.SearchSchema) []velocity.IndexFieldValue {
	if schema == nil || len(schema.Fields) == 0 {
		return fields
	}
	if cap(p.indexScratch) < len(fields) {
		p.indexScratch = make([]velocity.IndexFieldValue, 0, len(fields))
	}
	out := p.indexScratch[:0]
	for _, schemaField := range schema.Fields {
		if schemaField.Name == "" || schemaField.Name == "$value" {
			return fields
		}
		if !schemaField.Searchable && !schemaField.ValueIndex && (!schemaField.HashSearch || isPrimaryKeyColumnName(schemaField.Name)) {
			continue
		}
		for _, field := range fields {
			if field.Name == schemaField.Name {
				out = append(out, field)
				break
			}
		}
	}
	p.indexScratch = out
	return out
}

func isPrimaryKeyColumnName(name string) bool {
	return len(name) == 2 && (name[0] == 'i' || name[0] == 'I') && (name[1] == 'd' || name[1] == 'D')
}

func namedArgByOrdinal(args []driver.NamedValue, ordinal int) (interface{}, error) {
	if ordinal >= 1 && ordinal <= len(args) {
		arg := args[ordinal-1]
		if arg.Ordinal == ordinal || arg.Ordinal == 0 {
			return arg.Value, nil
		}
	}
	for _, arg := range args {
		if arg.Ordinal == ordinal {
			return arg.Value, nil
		}
	}
	return nil, fmt.Errorf("missing argument for positional parameter %d", ordinal)
}

func appendTableKey(dst []byte, table string, value interface{}) []byte {
	dst = append(dst, table...)
	dst = append(dst, ':')
	switch v := value.(type) {
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
	case string:
		return append(dst, v...)
	case []byte:
		return append(dst, v...)
	default:
		return fmt.Appendf(dst, "%v", value)
	}
}
