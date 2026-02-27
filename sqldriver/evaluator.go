package sqldriver

import (
	"database/sql/driver"
	"fmt"
	"strconv"
	"strings"

	"github.com/xwb1989/sqlparser"
)

// Evaluator provides a recursive execution environment for SQL Expressions
type Evaluator struct {
	Args []driver.NamedValue
}

// Eval evaluates an AST expression against a specific Row context and bound arguments
func (e *Evaluator) Eval(expr sqlparser.Expr, row Row) (interface{}, error) {
	if expr == nil {
		return true, nil // Empty expressions (like missing WHERE) are true
	}

	switch v := expr.(type) {
	case *sqlparser.AndExpr:
		left, err := e.evalBool(v.Left, row)
		if err != nil || !left {
			return false, err
		}
		return e.evalBool(v.Right, row)

	case *sqlparser.OrExpr:
		left, err := e.evalBool(v.Left, row)
		if err != nil {
			return false, err
		}
		if left {
			return true, nil
		}
		return e.evalBool(v.Right, row)

	case *sqlparser.NotExpr:
		val, err := e.evalBool(v.Expr, row)
		if err != nil {
			return false, err
		}
		return !val, nil

	case *sqlparser.ParenExpr:
		return e.Eval(v.Expr, row)

	case *sqlparser.ComparisonExpr:
		return e.evalComparison(v, row)

	case *sqlparser.SQLVal:
		return e.evalSQLVal(v)

	case *sqlparser.ColName:
		colName := v.Name.String()
		if !v.Qualifier.IsEmpty() {
			colName = v.Qualifier.Name.String() + "." + colName
		}

		val, exists := row[colName]
		if !exists {
			// Fallback: try unqualified name if qualified missing
			val, exists = row[v.Name.String()]
			if !exists {
				return nil, nil // Typically missing columns evaluate to NULL
			}
		}
		return val, nil

	case *sqlparser.NullVal:
		return nil, nil

	case *sqlparser.FuncExpr:
		// SQL function evaluation.
		// Aggregate functions like COUNT are handled by the execution engine's aggregation layer.
		funcName := v.Name.String()
		if strings.EqualFold(funcName, "count") {
			return 1, nil // Base count for row context
		}
		return nil, fmt.Errorf("velocity engine: unsupported function %s", funcName)

	default:
		return nil, fmt.Errorf("velocity engine: unsupported expression type %T", v)
	}
}

func (e *Evaluator) evalBool(expr sqlparser.Expr, row Row) (bool, error) {
	val, err := e.Eval(expr, row)
	if err != nil {
		return false, err
	}
	b, ok := val.(bool)
	if !ok {
		return false, fmt.Errorf("expected boolean expression, got %T", val)
	}
	return b, nil
}

func (e *Evaluator) evalComparison(c *sqlparser.ComparisonExpr, row Row) (bool, error) {
	leftVal, err := e.Eval(c.Left, row)
	if err != nil {
		return false, err
	}
	rightVal, err := e.Eval(c.Right, row)
	if err != nil {
		return false, err
	}

	// Handle NULL comparisons
	if leftVal == nil || rightVal == nil {
		// IN SQL, `NULL = NULL` is false. Only `IS NULL` works natively.
		return false, nil
	}

	// Unify types for comparison
	cmp, err := compareValues(leftVal, rightVal)
	if err != nil {
		// Log error, but SQL usually returns false for incomparable types instead of hard crashing
		return false, nil
	}

	switch c.Operator {
	case sqlparser.EqualStr:
		return cmp == 0, nil
	case sqlparser.NotEqualStr:
		return cmp != 0, nil
	case sqlparser.LessThanStr:
		return cmp < 0, nil
	case sqlparser.GreaterThanStr:
		return cmp > 0, nil
	case sqlparser.LessEqualStr:
		return cmp <= 0, nil
	case sqlparser.GreaterEqualStr:
		return cmp >= 0, nil
	default:
		return false, fmt.Errorf("unsupported comparison operator: %s", c.Operator)
	}
}

func (e *Evaluator) evalSQLVal(v *sqlparser.SQLVal) (interface{}, error) {
	switch v.Type {
	case sqlparser.StrVal:
		return string(v.Val), nil
	case sqlparser.IntVal:
		return strconv.ParseInt(string(v.Val), 10, 64)
	case sqlparser.FloatVal:
		return strconv.ParseFloat(string(v.Val), 64)
	case sqlparser.ValArg:
		// Parameters e.g. :v1, :v2, or named :name
		paramName := string(v.Val)

		// If it's a positional variable from '?' like `:v1`
		if strings.HasPrefix(paramName, ":v") {
			idx, err := strconv.Atoi(paramName[2:])
			if err == nil && idx >= 1 && idx <= len(e.Args) {
				return e.Args[idx-1].Value, nil
			}
		}

		// If it's a named variable like `:name`
		paramNameTrimmed := strings.TrimPrefix(paramName, ":")
		for _, arg := range e.Args {
			if arg.Name == paramNameTrimmed {
				return arg.Value, nil
			}
		}
		return nil, fmt.Errorf("missing argument for parameter %s", paramName)
	default:
		return string(v.Val), nil
	}
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
