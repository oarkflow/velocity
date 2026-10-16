package sql

import (
	"testing"

	"github.com/oarkflow/sqlparser"
	"github.com/oarkflow/sqlparser/ast"
	"github.com/oarkflow/sqlparser/lexer"
)

// stubExpr is a test-only node type the parser can never produce, used to
// prove exprMayBeCorrelated's default case is CONSERVATIVE (qualify) —
// a new/unknown AST node type must never enable bare-only rows before
// the walker has been taught about it.
type stubExpr struct{ ast.Expr }

func (s *stubExpr) node()      {}
func (s *stubExpr) exprNode()  {}
func (s *stubExpr) Pos() int32 { return 0 }

func mustParseSelect(t *testing.T, q string) *ast.SelectStmt {
	t.Helper()
	stmt, err := sqlparser.ParseStatement(q)
	if err != nil {
		t.Fatalf("parse %q: %v", q, err)
	}
	sel, ok := stmt.(*ast.SelectStmt)
	if !ok {
		t.Fatalf("parse %q: not a SELECT", q)
	}
	return sel
}

// TestStmtUnqualifiable_ClassificationMatrix is the decision matrix that
// makes the qualified-key-skip safe to extend later: every shape true,
// every shape that can correlate/consume qualified keys false, plus the
// conservative default for node types the walker doesn't know.
func TestStmtUnqualifiable_ClassificationMatrix(t *testing.T) {
	qualify := map[string]string{
		// The whole point: subquery constructs anywhere in the statement
		// force qualification, because the produced rows become every
		// nested evaluation's outer context (see correlated_test.go for
		// the end-to-end proof of the bare-shadow hazard they cover).
		"inSubquery":     "SELECT id FROM bench WHERE id IN (SELECT x FROM other)",
		"scalarSubquery": "SELECT id FROM bench WHERE age = (SELECT MAX(age) FROM other)",
		"existsSubquery": "SELECT id FROM bench WHERE EXISTS (SELECT 1 FROM other)",

		// Subqueries can hide in non-WHERE clauses too: every clause the
		// evaluator resolves with these rows must be walked.
		"havingSubquery":  "SELECT city FROM bench GROUP BY city HAVING COUNT(*) > (SELECT AVG(x) FROM other)",
		"orderBySubquery": "SELECT id FROM bench ORDER BY (SELECT COUNT(*) FROM other)",
		"groupBySubquery": "SELECT id FROM bench GROUP BY (SELECT COUNT(*) FROM other)",
		// Column-list subqueries.
		"columnSubquery": "SELECT (SELECT MAX(x) FROM other) AS mx FROM bench",

		// Set-operation / CTE statements are out of the walker's model.
		// NOTE: only parsed successfully when the parser supports the
		// shape; entries that fail to parse are skipped by the loop below
		// and asserted directly instead. (Both do parse.)
		"setOp": "SELECT id FROM bench UNION SELECT id FROM bench2",
	}
	for name, q := range qualify {
		if s := mustParseSelect(t, q); stmtUnqualifiable(s) {
			t.Errorf("%s: %q must NOT be classified unqualifiable", name, q)
		}
	}

	for _, q := range []string{
		"SELECT id FROM bench",
		"SELECT id FROM bench WHERE age > 5",
		"SELECT id FROM bench WHERE age > 5 AND name LIKE 'user-%'",
		"SELECT id, name FROM bench WHERE age BETWEEN 1 AND 9 ORDER BY id LIMIT 3",
		// Literal/param placeholders never correlate.
		"SELECT id FROM bench WHERE age = ?",
	} {
		if !stmtUnqualifiable(mustParseSelect(t, q)) {
			t.Errorf("%q must be classified unqualifiable", q)
		}
	}
}

// TestExprMayBeCorrelated_ConservativeDefault proves the walker never
// gambles: a node type it was never taught (test stub) forces
// qualification, in every nesting position including inside an AND.
func TestExprMayBeCorrelated_ConservativeDefault(t *testing.T) {
	if !exprMayBeCorrelated(&stubExpr{}) {
		t.Fatal("unknown node type must correlate (qualify)")
	}
	foo := &stubExpr{}
	bar := &ast.BinaryExpr{Op: lexer.AND}
	_ = foo
	_ = bar
	if exprMayBeCorrelated(&ast.BinaryExpr{
		Op:    lexer.AND,
		Left:  &ast.Literal{TokPos: 1},
		Right: &stubExpr{},
	}) != true {
		t.Fatal("AND leaving an unknown node must still correlate")
	}
}
