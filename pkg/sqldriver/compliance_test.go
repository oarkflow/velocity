package sqldriver

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oarkflow/velocity"
)

func openComplianceSQLDB(t *testing.T, name string, tagFn func(*velocity.ComplianceTagManager)) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	vdb, err := velocity.NewWithConfig(velocity.Config{Path: path, DisableEncryption: true})
	if err != nil {
		t.Fatalf("open velocity db: %v", err)
	}
	if tagFn != nil {
		tagFn(vdb.ComplianceTagManager())
	}
	if err := vdb.Close(); err != nil {
		t.Fatalf("close velocity db: %v", err)
	}
	DSNConfigs[path] = velocity.Config{Path: path, DisableEncryption: true}
	t.Cleanup(func() {
		delete(DSNConfigs, path)
	})
	db, err := sql.Open(DriverName, path)
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

func TestSQLComplianceTableAndSchemaTagsBlockWrites(t *testing.T) {
	ctx := context.Background()
	db, _ := openComplianceSQLDB(t, "table_block", func(ctm *velocity.ComplianceTagManager) {
		if err := ctm.TagResource(ctx, velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceSQLTable, SQLTable: "patients"}, &velocity.ComplianceTag{
			Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkHIPAA},
			DataClass:     velocity.DataClassRestricted,
			EncryptionReq: true,
			CreatedBy:     "test",
		}); err != nil {
			t.Fatalf("tag table: %v", err)
		}
	})
	if _, err := db.Exec(`CREATE TABLE patients (id BIGINT PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO patients (id, name) VALUES (?, ?)`, 1, "Alice"); err == nil {
		t.Fatalf("expected table compliance tag to block insert")
	}

	db2, _ := openComplianceSQLDB(t, "schema_block", func(ctm *velocity.ComplianceTagManager) {
		if err := ctm.TagResource(ctx, velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceSQLSchema, SQLSchema: "main"}, &velocity.ComplianceTag{
			Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkHIPAA},
			DataClass:     velocity.DataClassRestricted,
			EncryptionReq: true,
			CreatedBy:     "test",
		}); err != nil {
			t.Fatalf("tag schema: %v", err)
		}
	})
	if _, err := db2.Exec(`CREATE TABLE visits (id BIGINT PRIMARY KEY, note TEXT)`); err != nil {
		t.Fatalf("create visits: %v", err)
	}
	if _, err := db2.Exec(`INSERT INTO visits (id, note) VALUES (?, ?)`, 1, "PHI"); err == nil {
		t.Fatalf("expected schema compliance tag to block insert")
	}
}

func TestSQLComplianceColumnMaskAndBlock(t *testing.T) {
	ctx := context.Background()
	db, _ := openComplianceSQLDB(t, "column_mask", func(ctm *velocity.ComplianceTagManager) {
		if err := ctm.TagResource(ctx, velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceSQLColumn, SQLTable: "patients", SQLColumn: "ssn"}, &velocity.ComplianceTag{
			Frameworks: []velocity.ComplianceFramework{velocity.FrameworkSOC2},
			DataClass:  velocity.DataClassRestricted,
			CreatedBy:  "test",
		}); err != nil {
			t.Fatalf("tag column: %v", err)
		}
	})
	if _, err := db.Exec(`CREATE TABLE patients (id BIGINT PRIMARY KEY, name TEXT, ssn TEXT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO patients (id, name, ssn) VALUES (?, ?, ?)`, 1, "Alice", "123-45-6789"); err != nil {
		t.Fatalf("insert with SOC2 column tag should pass: %v", err)
	}
	var ssn string
	if err := db.QueryRow(`SELECT ssn FROM patients WHERE id = ?`, 1).Scan(&ssn); err != nil {
		t.Fatalf("select ssn: %v", err)
	}
	if ssn == "123-45-6789" || !strings.Contains(ssn, "*") {
		t.Fatalf("expected masked ssn, got %q", ssn)
	}

	blocked, _ := openComplianceSQLDB(t, "column_block", func(ctm *velocity.ComplianceTagManager) {
		if err := ctm.TagResource(ctx, velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceSQLColumn, SQLTable: "cards", SQLColumn: "pan"}, &velocity.ComplianceTag{
			Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkHIPAA},
			DataClass:     velocity.DataClassRestricted,
			EncryptionReq: true,
			CreatedBy:     "test",
		}); err != nil {
			t.Fatalf("tag blocked column: %v", err)
		}
	})
	if _, err := blocked.Exec(`CREATE TABLE cards (id BIGINT PRIMARY KEY, pan TEXT)`); err != nil {
		t.Fatalf("create cards: %v", err)
	}
	if _, err := blocked.Exec(`INSERT INTO cards (id, pan) VALUES (?, ?)`, 1, "4111111111111111"); err == nil {
		t.Fatalf("expected HIPAA column tag to block unencrypted insert")
	}
}

func TestSQLComplianceRowTagMasksSelectedValues(t *testing.T) {
	ctx := context.Background()
	db, _ := openComplianceSQLDB(t, "row_mask", func(ctm *velocity.ComplianceTagManager) {
		if err := ctm.TagResource(ctx, velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceSQLRow, SQLTable: "patients", SQLRowKey: "1"}, &velocity.ComplianceTag{
			Frameworks: []velocity.ComplianceFramework{velocity.FrameworkSOC2},
			DataClass:  velocity.DataClassConfidential,
			CreatedBy:  "test",
		}); err != nil {
			t.Fatalf("tag row: %v", err)
		}
	})
	if _, err := db.Exec(`CREATE TABLE patients (id BIGINT PRIMARY KEY, name TEXT, email TEXT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO patients (id, name, email) VALUES (?, ?, ?)`, 1, "Alice", "alice@example.test"); err != nil {
		t.Fatalf("insert row: %v", err)
	}
	var email string
	if err := db.QueryRow(`SELECT email FROM patients WHERE id = ?`, 1).Scan(&email); err != nil {
		t.Fatalf("select email: %v", err)
	}
	if email == "alice@example.test" || !strings.Contains(email, "*") {
		t.Fatalf("expected row tag to mask email, got %q", email)
	}
}
