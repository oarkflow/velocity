package sqldriver

import (
"fmt"
"github.com/xwb1989/sqlparser"
)

func DebugParse() {
	stmt, _ := sqlparser.Parse("SELECT * FROM users WHERE age = ? AND name = :name")
	fmt.Printf("%#v\n", stmt)
	// let's print the where expression deeply
sel := stmt.(*sqlparser.Select)
fmt.Printf("Where: %#v\n", sel.Where.Expr)
sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
fmt.Printf("Node: %T -> %#v\n", node, node)
return true, nil
}, sel.Where.Expr)
}
