package sqldriver

import (
	"fmt"
	"testing"

	"github.com/xwb1989/sqlparser"
)

func TestASTExploration(t *testing.T) {
	stmt, _ := sqlparser.Parse("SELECT * FROM users WHERE age = ? AND name = :name")
	sel := stmt.(*sqlparser.Select)
	sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
		fmt.Printf("Node: %T -> %#v\n", node, node)
		return true, nil
	}, sel.Where.Expr)
}
