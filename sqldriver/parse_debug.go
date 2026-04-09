package sqldriver

import (
	"fmt"

	sqlparser "github.com/oarkflow/sqlparser"
	"github.com/oarkflow/sqlparser/ast"
)

func DebugParse() {
	parser := sqlparser.NewString("SELECT * FROM users WHERE age = ? AND name = :name")
	stmt, err := parser.Next()
	if err != nil {
		fmt.Printf("parse error: %v\n", err)
		return
	}
	fmt.Printf("%#v\n", stmt)
	sel, ok := stmt.(*ast.SelectStmt)
	if !ok {
		fmt.Printf("unexpected statement type: %T\n", stmt)
		return
	}
	fmt.Printf("Where: %#v\n", sel.Where)
}
