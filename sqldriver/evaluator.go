package sqldriver

import (
	"database/sql/driver"
	"fmt"
	"strconv"
	"strings"

	"github.com/oarkflow/sqlparser/ast"
	"github.com/oarkflow/sqlparser/lexer"
)

// Evaluator provides a recursive execution environment for SQL Expressions
type Evaluator struct {
	Args           []driver.NamedValue
	ParamOrder     map[int32]int
	SubqueryRunner func(*ast.SelectStmt) ([]Row, error)
}

// Eval evaluates an AST expression against a specific Row context and bound arguments
func (e *Evaluator) Eval(expr ast.Expr, row Row) (interface{}, error) {
	if expr == nil {
		return true, nil // Empty expressions (like missing WHERE) are true
	}

	switch v := expr.(type) {
	case *ast.BinaryExpr:
		return e.evalBinaryExpr(v, row)

	case *ast.UnaryExpr:
		return e.evalUnaryExpr(v, row)

	case *ast.Literal:
		return e.evalLiteral(v)

	case *ast.Param:
		return e.evalParam(v)

	case *ast.Ident:
		colName := v.Unquoted
		val, exists := row[colName]
		if !exists {
			return nil, nil
		}
		return val, nil

	case *ast.QualifiedIdent:
		colName := qualifiedIdentToString(v)
		val, exists := row[colName]
		if !exists {
			// Fallback: try just the last part (column name without table qualifier)
			if len(v.Parts) > 0 {
				shortName := v.Parts[len(v.Parts)-1].Unquoted
				val, exists = row[shortName]
				if !exists {
					return nil, nil
				}
				return val, nil
			}
			return nil, nil
		}
		return val, nil

	case *ast.NullLit:
		return nil, nil

	case *ast.StarExpr:
		return "*", nil

	case *ast.FuncCall:
		return e.evalFuncCall(v, row)

	case *ast.BetweenExpr:
		return e.evalBetween(v, row)

	case *ast.InExpr:
		return e.evalIn(v, row)

	case *ast.LikeExpr:
		return e.evalLike(v, row)

	case *ast.IsNullExpr:
		return e.evalIsNull(v, row)

	case *ast.CaseExpr:
		return e.evalCase(v, row)

	case *ast.SubqueryExpr:
		return e.evalScalarSubquery(v)

	case *ast.ExistsExpr:
		return e.evalExists(v)

	case *ast.CastExpr:
		return e.evalCast(v, row)

	case *ast.SelectStmt:
		return nil, fmt.Errorf("velocity engine: bare SELECT is not supported in expression context")

	default:
		return nil, fmt.Errorf("velocity engine: unsupported expression type %T", v)
	}
}

func (e *Evaluator) evalBool(expr ast.Expr, row Row) (bool, error) {
	val, err := e.Eval(expr, row)
	if err != nil {
		return false, err
	}
	if val == nil {
		return false, nil
	}
	b, ok := val.(bool)
	if !ok {
		return false, fmt.Errorf("expected boolean expression, got %T", val)
	}
	return b, nil
}

func (e *Evaluator) evalBinaryExpr(v *ast.BinaryExpr, row Row) (interface{}, error) {
	switch v.Op {
	// Logical operators
	case lexer.AND:
		left, err := e.evalBool(v.Left, row)
		if err != nil || !left {
			return false, err
		}
		return e.evalBool(v.Right, row)

	case lexer.OR:
		left, err := e.evalBool(v.Left, row)
		if err != nil {
			return false, err
		}
		if left {
			return true, nil
		}
		return e.evalBool(v.Right, row)

	// Comparison operators
	case lexer.EQ, lexer.NEQ, lexer.LT, lexer.GT, lexer.LTE, lexer.GTE:
		return e.evalComparison(v, row)

	// Arithmetic operators
	case lexer.PLUS, lexer.MINUS, lexer.STAR, lexer.SLASH, lexer.PERCENT:
		return e.evalArithmetic(v, row)

	// String concatenation
	case lexer.DBAR:
		leftVal, err := e.Eval(v.Left, row)
		if err != nil {
			return nil, err
		}
		rightVal, err := e.Eval(v.Right, row)
		if err != nil {
			return nil, err
		}
		return fmt.Sprintf("%v%v", leftVal, rightVal), nil

	default:
		return nil, fmt.Errorf("velocity engine: unsupported binary operator %v", v.Op)
	}
}

func (e *Evaluator) evalUnaryExpr(v *ast.UnaryExpr, row Row) (interface{}, error) {
	switch v.Op {
	case lexer.NOT:
		val, err := e.evalBool(v.Expr, row)
		if err != nil {
			return false, err
		}
		return !val, nil

	case lexer.MINUS:
		val, err := e.Eval(v.Expr, row)
		if err != nil {
			return nil, err
		}
		f, ok := asFloat(val)
		if !ok {
			return nil, fmt.Errorf("velocity engine: cannot negate non-numeric value %v", val)
		}
		// Preserve integer type if possible
		if i, isInt := val.(int64); isInt {
			return -i, nil
		}
		return -f, nil

	case lexer.PLUS:
		return e.Eval(v.Expr, row)

	default:
		return nil, fmt.Errorf("velocity engine: unsupported unary operator %v", v.Op)
	}
}

func (e *Evaluator) evalComparison(v *ast.BinaryExpr, row Row) (bool, error) {
	leftVal, err := e.Eval(v.Left, row)
	if err != nil {
		return false, err
	}
	rightVal, err := e.Eval(v.Right, row)
	if err != nil {
		return false, err
	}

	// Handle NULL comparisons
	if leftVal == nil || rightVal == nil {
		return false, nil
	}

	cmp, err := compareValues(leftVal, rightVal)
	if err != nil {
		return false, nil
	}

	switch v.Op {
	case lexer.EQ:
		return cmp == 0, nil
	case lexer.NEQ:
		return cmp != 0, nil
	case lexer.LT:
		return cmp < 0, nil
	case lexer.GT:
		return cmp > 0, nil
	case lexer.LTE:
		return cmp <= 0, nil
	case lexer.GTE:
		return cmp >= 0, nil
	default:
		return false, fmt.Errorf("unsupported comparison operator: %v", v.Op)
	}
}

func (e *Evaluator) evalArithmetic(v *ast.BinaryExpr, row Row) (interface{}, error) {
	leftVal, err := e.Eval(v.Left, row)
	if err != nil {
		return nil, err
	}
	rightVal, err := e.Eval(v.Right, row)
	if err != nil {
		return nil, err
	}

	lf, lok := asFloat(leftVal)
	rf, rok := asFloat(rightVal)
	if !lok || !rok {
		return nil, fmt.Errorf("velocity engine: arithmetic on non-numeric values: %v %v %v", leftVal, v.Op, rightVal)
	}

	switch v.Op {
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
	default:
		return nil, fmt.Errorf("velocity engine: unsupported arithmetic operator %v", v.Op)
	}
}

func (e *Evaluator) evalLiteral(v *ast.Literal) (interface{}, error) {
	switch v.Kind {
	case lexer.STRING:
		return unquoteSQLString(string(v.Raw)), nil
	case lexer.INT:
		return strconv.ParseInt(string(v.Raw), 10, 64)
	case lexer.FLOAT:
		return strconv.ParseFloat(string(v.Raw), 64)
	case lexer.TRUE_KW:
		return true, nil
	case lexer.FALSE_KW:
		return false, nil
	default:
		return string(v.Raw), nil
	}
}

func unquoteSQLString(raw string) string {
	if len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		raw = raw[1 : len(raw)-1]
		raw = strings.ReplaceAll(raw, "''", "'")
	}
	return raw
}

func (e *Evaluator) evalParam(v *ast.Param) (interface{}, error) {
	paramName := string(v.Raw)

	// Positional ? parameter
	if paramName == "?" {
		if e.ParamOrder != nil {
			if ordinal, ok := e.ParamOrder[v.TokPos]; ok {
				return e.argByOrdinal(ordinal)
			}
		}
		return e.argByOrdinal(1)
	}

	// Positional :v1, :v2 style
	if strings.HasPrefix(paramName, ":v") {
		idx, err := strconv.Atoi(paramName[2:])
		if err == nil && idx >= 1 && idx <= len(e.Args) {
			return e.argByOrdinal(idx)
		}
	}

	// Named :name style
	paramNameTrimmed := strings.TrimPrefix(paramName, ":")
	paramNameTrimmed = strings.TrimPrefix(paramNameTrimmed, "@")
	for _, arg := range e.Args {
		if arg.Name == paramNameTrimmed {
			return arg.Value, nil
		}
	}

	// Fallback: try positional by ordinal
	if len(e.Args) > 0 {
		// Try to parse the number
		if idx, err := strconv.Atoi(paramNameTrimmed); err == nil && idx >= 1 && idx <= len(e.Args) {
			return e.argByOrdinal(idx)
		}
	}

	return nil, fmt.Errorf("missing argument for parameter %s", paramName)
}

func (e *Evaluator) argByOrdinal(ordinal int) (interface{}, error) {
	for _, arg := range e.Args {
		if arg.Ordinal == ordinal {
			return arg.Value, nil
		}
	}
	if ordinal >= 1 && ordinal <= len(e.Args) {
		return e.Args[ordinal-1].Value, nil
	}
	return nil, fmt.Errorf("missing argument for positional parameter %d", ordinal)
}

func (e *Evaluator) evalFuncCall(v *ast.FuncCall, row Row) (interface{}, error) {
	funcName := qualifiedIdentToString(v.Name)

	if strings.EqualFold(funcName, "count") {
		return 1, nil // Base count for single row context
	}
	if strings.EqualFold(funcName, "coalesce") {
		for _, arg := range v.Args {
			val, err := e.Eval(arg, row)
			if err != nil {
				return nil, err
			}
			if val != nil {
				return val, nil
			}
		}
		return nil, nil
	}
	if strings.EqualFold(funcName, "ifnull") || strings.EqualFold(funcName, "nvl") {
		if len(v.Args) >= 2 {
			val, err := e.Eval(v.Args[0], row)
			if err != nil {
				return nil, err
			}
			if val != nil {
				return val, nil
			}
			return e.Eval(v.Args[1], row)
		}
	}
	if strings.EqualFold(funcName, "upper") && len(v.Args) == 1 {
		val, err := e.Eval(v.Args[0], row)
		if err != nil {
			return nil, err
		}
		return strings.ToUpper(fmt.Sprintf("%v", val)), nil
	}
	if strings.EqualFold(funcName, "lower") && len(v.Args) == 1 {
		val, err := e.Eval(v.Args[0], row)
		if err != nil {
			return nil, err
		}
		return strings.ToLower(fmt.Sprintf("%v", val)), nil
	}
	if strings.EqualFold(funcName, "length") || strings.EqualFold(funcName, "len") {
		if len(v.Args) == 1 {
			val, err := e.Eval(v.Args[0], row)
			if err != nil {
				return nil, err
			}
			return int64(len(fmt.Sprintf("%v", val))), nil
		}
	}

	return nil, fmt.Errorf("velocity engine: unsupported function %s", funcName)
}

func (e *Evaluator) evalBetween(v *ast.BetweenExpr, row Row) (interface{}, error) {
	val, err := e.Eval(v.Expr, row)
	if err != nil {
		return false, err
	}
	lo, err := e.Eval(v.Lo, row)
	if err != nil {
		return false, err
	}
	hi, err := e.Eval(v.Hi, row)
	if err != nil {
		return false, err
	}

	if val == nil || lo == nil || hi == nil {
		return false, nil
	}

	cmpLo, _ := compareValues(val, lo)
	cmpHi, _ := compareValues(val, hi)
	result := cmpLo >= 0 && cmpHi <= 0

	if v.Not {
		return !result, nil
	}
	return result, nil
}

func (e *Evaluator) evalIn(v *ast.InExpr, row Row) (interface{}, error) {
	val, err := e.Eval(v.Expr, row)
	if err != nil {
		return false, err
	}
	if val == nil {
		return false, nil
	}

	if v.Subq != nil {
		if e.SubqueryRunner == nil {
			return nil, fmt.Errorf("velocity engine: subquery not supported in evaluator")
		}
		rows, err := e.SubqueryRunner(v.Subq)
		if err != nil {
			return false, err
		}
		for _, subRow := range rows {
			itemVal, ok := firstRowValue(subRow)
			if !ok {
				continue
			}
			cmp, err := compareValues(val, itemVal)
			if err == nil && cmp == 0 {
				if v.Not {
					return false, nil
				}
				return true, nil
			}
		}
		if v.Not {
			return true, nil
		}
		return false, nil
	}

	for _, item := range v.List {
		itemVal, err := e.Eval(item, row)
		if err != nil {
			return false, err
		}
		cmp, err := compareValues(val, itemVal)
		if err == nil && cmp == 0 {
			if v.Not {
				return false, nil
			}
			return true, nil
		}
	}

	if v.Not {
		return true, nil
	}
	return false, nil
}

func (e *Evaluator) evalLike(v *ast.LikeExpr, row Row) (interface{}, error) {
	val, err := e.Eval(v.Expr, row)
	if err != nil {
		return false, err
	}
	patVal, err := e.Eval(v.Pattern, row)
	if err != nil {
		return false, err
	}

	if val == nil || patVal == nil {
		return false, nil
	}

	str := fmt.Sprintf("%v", val)
	pattern := fmt.Sprintf("%v", patVal)

	result := matchLikePattern(str, pattern)
	if v.Not {
		return !result, nil
	}
	return result, nil
}

func (e *Evaluator) evalIsNull(v *ast.IsNullExpr, row Row) (interface{}, error) {
	val, err := e.Eval(v.Expr, row)
	if err != nil {
		return false, err
	}
	isNull := val == nil
	if v.Not {
		return !isNull, nil
	}
	return isNull, nil
}

func (e *Evaluator) evalCase(v *ast.CaseExpr, row Row) (interface{}, error) {
	if v.Operand != nil {
		// Simple CASE: CASE expr WHEN val THEN result ...
		operand, err := e.Eval(v.Operand, row)
		if err != nil {
			return nil, err
		}
		for _, w := range v.Whens {
			cond, err := e.Eval(w.Cond, row)
			if err != nil {
				return nil, err
			}
			cmp, err := compareValues(operand, cond)
			if err == nil && cmp == 0 {
				return e.Eval(w.Result, row)
			}
		}
	} else {
		// Searched CASE: CASE WHEN cond THEN result ...
		for _, w := range v.Whens {
			cond, err := e.evalBool(w.Cond, row)
			if err != nil {
				return nil, err
			}
			if cond {
				return e.Eval(w.Result, row)
			}
		}
	}

	if v.Else != nil {
		return e.Eval(v.Else, row)
	}
	return nil, nil
}

func (e *Evaluator) evalExists(v *ast.ExistsExpr) (interface{}, error) {
	if e.SubqueryRunner == nil {
		return nil, fmt.Errorf("velocity engine: subquery not supported in evaluator")
	}
	rows, err := e.SubqueryRunner(v.Subq)
	if err != nil {
		return false, err
	}
	result := len(rows) > 0
	if v.Not {
		return !result, nil
	}
	return result, nil
}

func (e *Evaluator) evalScalarSubquery(v *ast.SubqueryExpr) (interface{}, error) {
	if e.SubqueryRunner == nil {
		return nil, fmt.Errorf("velocity engine: scalar subquery not supported in evaluator")
	}
	rows, err := e.SubqueryRunner(v.Subq)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	val, ok := firstRowValue(rows[0])
	if !ok {
		return nil, nil
	}
	return val, nil
}

func (e *Evaluator) evalCast(v *ast.CastExpr, row Row) (interface{}, error) {
	val, err := e.Eval(v.Expr, row)
	if err != nil {
		return nil, err
	}
	if val == nil || v.Type == nil {
		return val, nil
	}

	typeName := strings.ToUpper(string(v.Type.Name))
	switch typeName {
	case "INT", "INTEGER", "BIGINT", "SMALLINT", "TINYINT", "MEDIUMINT":
		f, ok := asFloat(val)
		if !ok {
			return nil, fmt.Errorf("velocity engine: cannot cast %T to %s", val, typeName)
		}
		return int64(f), nil
	case "FLOAT", "DOUBLE", "REAL", "DECIMAL", "NUMERIC":
		f, ok := asFloat(val)
		if !ok {
			return nil, fmt.Errorf("velocity engine: cannot cast %T to %s", val, typeName)
		}
		return f, nil
	case "CHAR", "VARCHAR", "TEXT", "LONGTEXT", "MEDIUMTEXT", "TINYTEXT", "JSON", "JSONB":
		return fmt.Sprintf("%v", val), nil
	case "BOOLEAN":
		switch t := val.(type) {
		case bool:
			return t, nil
		case string:
			switch strings.ToLower(t) {
			case "1", "t", "true", "yes", "y":
				return true, nil
			case "0", "f", "false", "no", "n":
				return false, nil
			}
		}
		f, ok := asFloat(val)
		if ok {
			return f != 0, nil
		}
	}
	return val, nil
}

// matchLikePattern implements SQL LIKE pattern matching.
// % matches any sequence of characters, _ matches any single character.
func matchLikePattern(str, pattern string) bool {
	str = strings.ToLower(str)
	pattern = strings.ToLower(pattern)

	s, p := 0, 0
	starS, starP := -1, -1

	for s < len(str) {
		if p < len(pattern) && (pattern[p] == '_' || pattern[p] == str[s]) {
			s++
			p++
		} else if p < len(pattern) && pattern[p] == '%' {
			starS = s
			starP = p
			p++
		} else if starP >= 0 {
			starS++
			s = starS
			p = starP + 1
		} else {
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '%' {
		p++
	}
	return p == len(pattern)
}

// qualifiedIdentToString converts a QualifiedIdent to a dotted string.
func qualifiedIdentToString(qi *ast.QualifiedIdent) string {
	if qi == nil || len(qi.Parts) == 0 {
		return ""
	}
	if len(qi.Parts) == 1 {
		return qi.Parts[0].Unquoted
	}
	parts := make([]string, len(qi.Parts))
	for i, p := range qi.Parts {
		parts[i] = p.Unquoted
	}
	return strings.Join(parts, ".")
}

// identToString extracts the string from an Ident
func identToString(id *ast.Ident) string {
	if id == nil {
		return ""
	}
	return id.Unquoted
}

func firstRowValue(row Row) (interface{}, bool) {
	if len(row) == 0 {
		return nil, false
	}
	var firstKey string
	for key := range row {
		if strings.HasPrefix(key, "_") || strings.Contains(key, ".") {
			continue
		}
		if firstKey == "" || key < firstKey {
			firstKey = key
		}
	}
	if firstKey == "" {
		for key := range row {
			if firstKey == "" || key < firstKey {
				firstKey = key
			}
		}
	}
	val, ok := row[firstKey]
	return val, ok
}

// compareValues softly compares interface types
func compareValues(a, b interface{}) (int, error) {
	if a == b {
		return 0, nil
	}

	// Try numeric comparison
	aFloat, aIsNum := asFloat(a)
	bFloat, bIsNum := asFloat(b)
	if aIsNum && bIsNum {
		if aFloat < bFloat {
			return -1, nil
		}
		if aFloat > bFloat {
			return 1, nil
		}
		return 0, nil
	}

	// Try string comparison
	aStr := fmt.Sprintf("%v", a)
	bStr := fmt.Sprintf("%v", b)
	if aStr < bStr {
		return -1, nil
	}
	if aStr > bStr {
		return 1, nil
	}

	return 0, nil
}

func asFloat(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case int:
		return float64(val), true
	case int32:
		return float64(val), true
	case int64:
		return float64(val), true
	case float32:
		return float64(val), true
	case float64:
		return val, true
	case string:
		f, err := strconv.ParseFloat(val, 64)
		return f, err == nil
	default:
		return 0, false
	}
}
