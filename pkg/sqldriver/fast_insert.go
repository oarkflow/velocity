package sqldriver

import (
	"context"
	"database/sql/driver"
	"fmt"
	"strconv"
	"time"

	sqlparser "github.com/oarkflow/sqlparser"
	"github.com/oarkflow/sqlparser/ast"
	"github.com/oarkflow/velocity"
)

type simpleInsertPlan struct {
	table         string
	columns       []string
	encodedCols   [][]byte
	paramOrdinals []int
	idIndex       int
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

func (p *simpleInsertPlan) Exec(conn *Conn, args []driver.NamedValue) (driver.Result, error) {
	payload := make([]byte, 0, 96)
	payload = append(payload, '{')
	var keyValue interface{}
	fields := make([]velocity.IndexFieldValue, len(p.columns))

	for i, ordinal := range p.paramOrdinals {
		value, err := namedArgByOrdinal(args, ordinal)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			payload = append(payload, ',')
		}
		payload = append(payload, p.encodedCols[i]...)
		payload = append(payload, ':')
		payload = appendJSONValue(payload, value)
		fields[i] = velocity.IndexFieldValue{Name: p.columns[i], Value: value}
		if i == p.idIndex {
			keyValue = value
		}
	}
	payload = append(payload, '}')

	var lastInsertID int64
	var key []byte
	if keyValue != nil {
		key = appendTableKey(nil, p.table, keyValue)
		if id, ok := asFloat(keyValue); ok {
			lastInsertID = int64(id)
		}
	} else {
		key = strconv.AppendInt(append(append(key, p.table...), ':'), time.Now().UnixNano(), 10)
	}

	values := make([]any, len(fields))
	for i, field := range fields {
		values[i] = field.Value
	}
	if err := conn.checkRawInsertConstraints(p.table, p.columns, values, key); err != nil {
		return nil, err
	}
	unlock, err := conn.lockRows(context.Background(), []string{string(key)})
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := conn.PutWithIndexFieldPairs(key, payload, fields); err != nil {
		return nil, err
	}
	conn.markRowsChanged([][]byte{key})
	return &Result{lastInsertId: lastInsertID, rowsAffected: 1}, nil
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
