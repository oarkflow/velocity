package sqldriver

import (
	"context"
	"fmt"
	"github.com/oarkflow/velocity/pkg/compliance"
	"strings"
	"time"

	"github.com/oarkflow/sqlparser/ast"
	"github.com/oarkflow/velocity"
)

func (e *ExecutorV2) validateSQLTableCompliance(ctx context.Context, table, operation string, encrypted bool) error {
	ctm := e.conn.db.ComplianceTagManager()
	if ctm == nil || table == "" {
		return nil
	}
	ref := velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceSQLTable, SQLTable: table}
	return validateSQLComplianceRef(ctx, ctm, ref, operation, encrypted)
}

func (e *ExecutorV2) validateSQLRowCompliance(ctx context.Context, table, rowKey, operation string, encrypted bool) error {
	ctm := e.conn.db.ComplianceTagManager()
	if ctm == nil || table == "" || rowKey == "" {
		return nil
	}
	ref := velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceSQLRow, SQLTable: table, SQLRowKey: rowKey}
	return validateSQLComplianceRef(ctx, ctm, ref, operation, encrypted)
}

func (e *ExecutorV2) validateSQLColumnsCompliance(ctx context.Context, table string, columns []string, operation string, encrypted bool) error {
	ctm := e.conn.db.ComplianceTagManager()
	if ctm == nil || table == "" {
		return nil
	}
	for _, column := range columns {
		column = strings.TrimSpace(column)
		if column == "" || strings.HasPrefix(column, "_") || strings.Contains(column, "(") {
			continue
		}
		ref := velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceSQLColumn, SQLTable: table, SQLColumn: column}
		if err := validateSQLComplianceRef(ctx, ctm, ref, operation, encrypted); err != nil {
			return err
		}
	}
	return nil
}

func validateSQLComplianceRef(ctx context.Context, ctm *velocity.ComplianceTagManager, ref velocity.ComplianceResourceRef, operation string, encrypted bool) error {
	result, err := ctm.ValidateResourceOperation(ctx, ref, &velocity.ComplianceOperationRequest{
		Operation: operation,
		Actor:     "sql",
		Encrypted: encrypted,
		Timestamp: time.Now(),
	})
	if err != nil {
		return err
	}
	if !result.Allowed {
		return fmt.Errorf("velocity driver: compliance violation: %s", strings.Join(result.ViolatedRules, "; "))
	}
	return nil
}

func (e *ExecutorV2) maskSQLRowForCompliance(table string, row Row, context Row, columns []string) Row {
	ctm := e.conn.db.ComplianceTagManager()
	if ctm == nil || table == "" || row == nil {
		return row
	}
	out := copyRow(row)
	for _, column := range columns {
		if column == "" || strings.HasPrefix(column, "_") {
			continue
		}
		value, ok := out[column]
		if !ok || value == nil {
			continue
		}
		class := e.sqlColumnClass(ctm, table, column, context)
		if !velocity.DataClassAtLeast(class, compliance.DataClassConfidential) {
			continue
		}
		out[column] = ctm.MaskStringForClass(fmt.Sprint(value), class)
	}
	return out
}

func (e *ExecutorV2) sqlColumnClass(ctm *velocity.ComplianceTagManager, table, column string, row Row) compliance.DataClassification {
	class := compliance.DataClassPublic
	refs := []velocity.ComplianceResourceRef{
		{Type: velocity.ComplianceResourceSQLTable, SQLTable: table},
		{Type: velocity.ComplianceResourceSQLColumn, SQLTable: table, SQLColumn: column},
	}
	if key, _ := row["_key"].(string); key != "" {
		refs = append(refs, velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceSQLRow, SQLTable: table, SQLRowKey: key})
	}
	for _, ref := range refs {
		if tag := ctm.GetResourceTag(ref); tag != nil && velocity.DataClassRank(tag.DataClass) > velocity.DataClassRank(class) {
			class = tag.DataClass
		}
	}
	return class
}

func singleSelectTable(sel *ast.SelectStmt) string {
	if sel == nil || len(sel.From) != 1 || hasJoinRef(sel.From) {
		return ""
	}
	table, ok := sel.From[0].(*ast.SimpleTable)
	if !ok {
		return ""
	}
	return qualifiedIdentToString(table.Name)
}

func (e *ExecutorV2) sqlSelectHasComplianceTags(sel *ast.SelectStmt) bool {
	ctm := e.conn.db.ComplianceTagManager()
	if ctm == nil {
		return false
	}
	if ctm.HasAnyTags() {
		return true
	}
	table := singleSelectTable(sel)
	if table == "" {
		return false
	}
	if tag := ctm.GetResourceTag(velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceSQLTable, SQLTable: table}); tag != nil {
		return true
	}
	for _, column := range explicitColumnNames(sel.Columns) {
		if tag := ctm.GetResourceTag(velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceSQLColumn, SQLTable: table, SQLColumn: column}); tag != nil {
			return true
		}
	}
	return false
}

func columnsFromAssignments(assignments []ast.Assignment) []string {
	cols := make([]string, 0, len(assignments))
	for _, asg := range assignments {
		cols = append(cols, identToString(asg.Column))
	}
	return dedupeStrings(cols)
}

func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}
