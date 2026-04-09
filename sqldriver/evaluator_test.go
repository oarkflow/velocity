package sqldriver

import (
	"testing"

	sqlparser "github.com/oarkflow/sqlparser"
	"github.com/oarkflow/sqlparser/ast"
)

func TestASTExploration(t *testing.T) {
	parser := sqlparser.NewString("SELECT * FROM users WHERE age = ? AND name = :name")
	stmt, err := parser.Next()
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	sel, ok := stmt.(*ast.SelectStmt)
	if !ok {
		t.Fatalf("expected *ast.SelectStmt, got %T", stmt)
	}
	if sel.Where == nil {
		t.Fatalf("expected WHERE clause")
	}
	if _, ok := sel.Where.(*ast.BinaryExpr); !ok {
		t.Fatalf("expected binary expression in WHERE, got %T", sel.Where)
	}
}
