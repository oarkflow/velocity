package sqldriver

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/oarkflow/money"
	"github.com/oarkflow/sqlparser"
	"github.com/oarkflow/sqlparser/ast"
	"github.com/oarkflow/velocity"
)

type columnTypeKind string

const (
	columnTypeAny        columnTypeKind = ""
	columnTypeText       columnTypeKind = "text"
	columnTypeInt        columnTypeKind = "int"
	columnTypeInt8       columnTypeKind = "int8"
	columnTypeInt16      columnTypeKind = "int16"
	columnTypeInt32      columnTypeKind = "int32"
	columnTypeInt64      columnTypeKind = "int64"
	columnTypeFloat32    columnTypeKind = "float32"
	columnTypeFloat64    columnTypeKind = "float64"
	columnTypeDecimal    columnTypeKind = "decimal"
	columnTypeBool       columnTypeKind = "bool"
	columnTypeJSON       columnTypeKind = "json"
	columnTypeDate       columnTypeKind = "date"
	columnTypeDateTime   columnTypeKind = "datetime"
	columnTypeTimestamp  columnTypeKind = "timestamp"
	columnTypeTimestampZ columnTypeKind = "timestampz"
	columnTypeTime       columnTypeKind = "time"
	columnTypeUUID       columnTypeKind = "uuid"
	columnTypeMoney      columnTypeKind = "money"
)

type sqlColumnType struct {
	Name      string         `json:"name"`
	Kind      columnTypeKind `json:"kind"`
	Precision int            `json:"precision,omitempty"`
	Scale     int            `json:"scale,omitempty"`
	Unsigned  bool           `json:"unsigned,omitempty"`
}

var decimalPattern = regexp.MustCompile(`^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$`)

func columnTypeFromAST(dt *ast.DataType) (sqlColumnType, error) {
	if dt == nil || len(dt.Name) == 0 {
		return sqlColumnType{}, nil
	}
	name := strings.ToLower(string(dt.Name))
	name = strings.TrimSpace(name)
	meta := sqlColumnType{
		Name:      name,
		Precision: dt.Precision,
		Scale:     dt.Scale,
		Unsigned:  dt.Unsigned,
	}
	switch name {
	case "string", "text", "varchar", "char", "character", "nvarchar", "nchar":
		meta.Kind = columnTypeText
	case "int", "integer", "mediumint":
		meta.Kind = columnTypeInt
	case "tinyint", "int8":
		meta.Kind = columnTypeInt8
	case "smallint", "int16":
		meta.Kind = columnTypeInt16
	case "int32":
		meta.Kind = columnTypeInt32
	case "bigint", "int64":
		meta.Kind = columnTypeInt64
	case "float", "float32", "real":
		meta.Kind = columnTypeFloat32
	case "double", "float64":
		meta.Kind = columnTypeFloat64
	case "decimal", "numeric":
		meta.Kind = columnTypeDecimal
	case "bool", "boolean":
		meta.Kind = columnTypeBool
	case "json", "jsonb":
		meta.Kind = columnTypeJSON
	case "date":
		meta.Kind = columnTypeDate
	case "datetime":
		meta.Kind = columnTypeDateTime
	case "timestamp":
		meta.Kind = columnTypeTimestamp
	case "timestamptz", "timestampz":
		meta.Kind = columnTypeTimestampZ
	case "time":
		meta.Kind = columnTypeTime
	case "uuid":
		meta.Kind = columnTypeUUID
	case "money":
		meta.Kind = columnTypeMoney
	default:
		return sqlColumnType{}, fmt.Errorf("velocity driver: unsupported SQL column type %q", name)
	}
	return meta, nil
}

func applyInsertDefaultsAndTypes(table string, meta tableSchemaMeta, data map[string]any, eval *Evaluator) (map[string]any, error) {
	out := copyStringAnyMap(data)
	if len(meta.Defaults) > 0 {
		for _, col := range meta.Columns {
			if _, exists := out[col]; exists {
				continue
			}
			expr := meta.Defaults[col]
			if expr == "" {
				continue
			}
			val, err := evalDefaultExpression(expr, eval)
			if err != nil {
				return nil, fmt.Errorf("velocity driver: default for %s.%s failed: %w", table, col, err)
			}
			out[col] = val
		}
	}
	return coerceRowTypes(table, meta, out)
}

func coerceRowTypes(table string, meta tableSchemaMeta, data map[string]any) (map[string]any, error) {
	if len(meta.ColumnTypes) == 0 {
		return data, nil
	}
	out := copyStringAnyMap(data)
	for col, typ := range meta.ColumnTypes {
		value, exists := out[col]
		if !exists || value == nil {
			continue
		}
		coerced, err := coerceColumnValue(typ, value)
		if err != nil {
			return nil, fmt.Errorf("velocity driver: invalid value for %s.%s (%s): %w", table, col, typ.Name, err)
		}
		out[col] = coerced
	}
	return out, nil
}

func evalDefaultExpression(expr string, eval *Evaluator) (any, error) {
	if eval == nil {
		eval = &Evaluator{}
	}
	parser := sqlparser.NewString("SELECT " + expr)
	stmt, err := parser.Next()
	if err != nil {
		return nil, err
	}
	sel, ok := stmt.(*ast.SelectStmt)
	if !ok || len(sel.Columns) == 0 || sel.Columns[0].Expr == nil {
		return nil, fmt.Errorf("invalid default expression %q", expr)
	}
	return eval.Eval(sel.Columns[0].Expr, nil)
}

func coerceColumnValue(typ sqlColumnType, value any) (any, error) {
	switch typ.Kind {
	case columnTypeAny:
		return value, nil
	case columnTypeText:
		return coerceString(value)
	case columnTypeUUID:
		s, err := coerceString(value)
		if err != nil {
			return nil, err
		}
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, err
		}
		return id.String(), nil
	case columnTypeInt:
		return coerceIntRange(value, math.MinInt, math.MaxInt)
	case columnTypeInt8:
		return coerceIntRange(value, math.MinInt8, math.MaxInt8)
	case columnTypeInt16:
		return coerceIntRange(value, math.MinInt16, math.MaxInt16)
	case columnTypeInt32:
		return coerceIntRange(value, math.MinInt32, math.MaxInt32)
	case columnTypeInt64:
		return coerceIntRange(value, math.MinInt64, math.MaxInt64)
	case columnTypeFloat32:
		f, err := coerceFloat(value)
		if err != nil {
			return nil, err
		}
		if f < -math.MaxFloat32 || f > math.MaxFloat32 {
			return nil, fmt.Errorf("float32 out of range")
		}
		return float64(float32(f)), nil
	case columnTypeFloat64:
		return coerceFloat(value)
	case columnTypeDecimal:
		return coerceDecimalString(value)
	case columnTypeBool:
		return coerceBool(value)
	case columnTypeJSON:
		return coerceJSONValue(value)
	case columnTypeDate:
		return coerceDate(value)
	case columnTypeDateTime:
		return coerceDateTime(value, false)
	case columnTypeTimestamp:
		return coerceDateTime(value, false)
	case columnTypeTimestampZ:
		return coerceDateTime(value, true)
	case columnTypeTime:
		return coerceTimeOnly(value)
	case columnTypeMoney:
		return coerceMoney(value)
	default:
		return value, nil
	}
}

func coerceString(value any) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	case fmt.Stringer:
		return v.String(), nil
	default:
		return "", fmt.Errorf("expected string, got %T", value)
	}
}

func coerceIntRange(value any, min, max int64) (int64, error) {
	var n int64
	switch v := value.(type) {
	case int:
		n = int64(v)
	case int8:
		n = int64(v)
	case int16:
		n = int64(v)
	case int32:
		n = int64(v)
	case int64:
		n = v
	case uint:
		if uint64(v) > uint64(math.MaxInt64) {
			return 0, fmt.Errorf("integer out of range")
		}
		n = int64(v)
	case uint8:
		n = int64(v)
	case uint16:
		n = int64(v)
	case uint32:
		n = int64(v)
	case uint64:
		if v > uint64(math.MaxInt64) {
			return 0, fmt.Errorf("integer out of range")
		}
		n = int64(v)
	case float32:
		f := float64(v)
		if math.Trunc(f) != f {
			return 0, fmt.Errorf("expected integer")
		}
		n = int64(f)
	case float64:
		if math.Trunc(v) != v {
			return 0, fmt.Errorf("expected integer")
		}
		n = int64(v)
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return 0, err
		}
		n = parsed
	case []byte:
		return coerceIntRange(string(v), min, max)
	default:
		return 0, fmt.Errorf("expected integer, got %T", value)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("integer out of range")
	}
	return n, nil
}

func coerceFloat(value any) (float64, error) {
	switch v := value.(type) {
	case float32:
		return float64(v), nil
	case float64:
		return v, nil
	case int:
		return float64(v), nil
	case int8:
		return float64(v), nil
	case int16:
		return float64(v), nil
	case int32:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case uint:
		return float64(v), nil
	case uint8:
		return float64(v), nil
	case uint16:
		return float64(v), nil
	case uint32:
		return float64(v), nil
	case uint64:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(strings.TrimSpace(v), 64)
	case []byte:
		return coerceFloat(string(v))
	default:
		return 0, fmt.Errorf("expected float, got %T", value)
	}
}

func coerceDecimalString(value any) (string, error) {
	switch v := value.(type) {
	case string:
		s := strings.TrimSpace(v)
		if !decimalPattern.MatchString(s) {
			return "", fmt.Errorf("invalid decimal")
		}
		return normalizeDecimalString(s), nil
	case []byte:
		return coerceDecimalString(string(v))
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%v", v), nil
	default:
		return "", fmt.Errorf("expected decimal string or integer, got %T", value)
	}
}

func normalizeDecimalString(s string) string {
	if strings.HasPrefix(s, "+") {
		s = s[1:]
	}
	if strings.HasPrefix(s, ".") {
		return "0" + s
	}
	if strings.HasPrefix(s, "-.") {
		return "-0" + s[1:]
	}
	return s
}

func coerceBool(value any) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		return strconv.ParseBool(strings.TrimSpace(v))
	case []byte:
		return coerceBool(string(v))
	case int:
		return intToBool(int64(v))
	case int8:
		return intToBool(int64(v))
	case int16:
		return intToBool(int64(v))
	case int32:
		return intToBool(int64(v))
	case int64:
		return intToBool(v)
	default:
		return false, fmt.Errorf("expected boolean, got %T", value)
	}
}

func intToBool(v int64) (bool, error) {
	switch v {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("expected 0 or 1")
	}
}

func coerceJSONValue(value any) (any, error) {
	switch v := value.(type) {
	case string:
		return parseJSONBytes([]byte(v))
	case []byte:
		return parseJSONBytes(v)
	case json.RawMessage:
		return parseJSONBytes(v)
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		return parseJSONBytes(encoded)
	}
}

func parseJSONBytes(raw []byte) (any, error) {
	var out any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return jsonSafeNumberValue(out), nil
}

func jsonSafeNumberValue(value any) any {
	switch v := value.(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i
		}
		if f, err := v.Float64(); err == nil {
			return f
		}
		return v.String()
	case []any:
		for i := range v {
			v[i] = jsonSafeNumberValue(v[i])
		}
		return v
	case map[string]any:
		for k := range v {
			v[k] = jsonSafeNumberValue(v[k])
		}
		return v
	default:
		return value
	}
}

func coerceDate(value any) (string, error) {
	switch v := value.(type) {
	case time.Time:
		return v.Format("2006-01-02"), nil
	case string:
		t, err := parseFlexibleTime(strings.TrimSpace(v), false)
		if err != nil {
			return "", err
		}
		return t.Format("2006-01-02"), nil
	case []byte:
		return coerceDate(string(v))
	default:
		return "", fmt.Errorf("expected date, got %T", value)
	}
}

func coerceDateTime(value any, requireZone bool) (string, error) {
	switch v := value.(type) {
	case time.Time:
		return v.Format(time.RFC3339Nano), nil
	case string:
		t, err := parseFlexibleTime(strings.TrimSpace(v), requireZone)
		if err != nil {
			return "", err
		}
		return t.Format(time.RFC3339Nano), nil
	case []byte:
		return coerceDateTime(string(v), requireZone)
	default:
		return "", fmt.Errorf("expected timestamp, got %T", value)
	}
}

func coerceTimeOnly(value any) (string, error) {
	switch v := value.(type) {
	case time.Time:
		return v.Format("15:04:05"), nil
	case string:
		s := strings.TrimSpace(v)
		for _, layout := range []string{"15:04:05", "15:04"} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.Format("15:04:05"), nil
			}
		}
		return "", fmt.Errorf("invalid time")
	case []byte:
		return coerceTimeOnly(string(v))
	default:
		return "", fmt.Errorf("expected time, got %T", value)
	}
}

func parseFlexibleTime(s string, requireZone bool) (time.Time, error) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05Z07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	var last error
	for i, layout := range layouts {
		if requireZone && i >= 4 {
			break
		}
		t, err := time.Parse(layout, s)
		if err == nil {
			return t, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("invalid timestamp")
	}
	return time.Time{}, last
}

func coerceMoney(value any) (any, error) {
	switch v := value.(type) {
	case money.Money:
		return moneyJSONMap(v)
	case string:
		m, err := money.Parse(v)
		if err != nil {
			return nil, err
		}
		return moneyJSONMap(m)
	case []byte:
		return coerceMoney(string(v))
	case driver.Valuer:
		raw, err := v.Value()
		if err != nil {
			return nil, err
		}
		return coerceMoney(raw)
	case map[string]any:
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		var m money.Money
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		return moneyJSONMap(m)
	default:
		return nil, fmt.Errorf("expected money, got %T", value)
	}
}

func moneyJSONMap(m money.Money) (map[string]any, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func exprToSQL(expr ast.Expr) string {
	switch v := expr.(type) {
	case nil:
		return ""
	case *ast.Literal:
		return string(v.Raw)
	case *ast.NullLit:
		return "NULL"
	case *ast.Ident:
		return v.Unquoted
	case *ast.QualifiedIdent:
		return qualifiedIdentToString(v)
	case *ast.FuncCall:
		args := make([]string, 0, len(v.Args))
		for _, arg := range v.Args {
			args = append(args, exprToSQL(arg))
		}
		return qualifiedIdentToString(v.Name) + "(" + strings.Join(args, ", ") + ")"
	case *ast.UnaryExpr:
		return v.Op.String() + exprToSQL(v.Expr)
	case *ast.BinaryExpr:
		return exprToSQL(v.Left) + " " + v.Op.String() + " " + exprToSQL(v.Right)
	case *ast.CastExpr:
		return exprToSQL(v.Expr)
	default:
		return ""
	}
}

func indexFieldsFromData(meta tableSchemaMeta, data map[string]any) []velocity.IndexFieldValue {
	if len(data) == 0 {
		return nil
	}
	if meta.SearchSchema == nil || len(meta.SearchSchema.Fields) == 0 {
		fields := make([]velocity.IndexFieldValue, 0, len(data))
		for name, value := range data {
			fields = append(fields, velocity.IndexFieldValue{Name: name, Value: value})
		}
		return fields
	}
	fields := make([]velocity.IndexFieldValue, 0, len(meta.SearchSchema.Fields))
	for _, field := range meta.SearchSchema.Fields {
		if field.Name == "" || field.Name == "$value" {
			continue
		}
		value, ok := data[field.Name]
		if !ok {
			continue
		}
		fields = append(fields, velocity.IndexFieldValue{Name: field.Name, Value: value})
	}
	return fields
}

func dataValuesForColumns(columns []string, data map[string]any) []any {
	values := make([]any, len(columns))
	for i, col := range columns {
		values[i] = data[col]
	}
	return values
}
