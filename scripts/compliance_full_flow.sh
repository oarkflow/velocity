#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/velocity-compliance-flow.XXXXXX")}"
BIN="${WORK_DIR}/velocity"
DB_PATH="${WORK_DIR}/velocity_data"

cleanup() {
  if [[ "${KEEP_COMPLIANCE_FLOW:-}" != "1" ]]; then
    rm -rf "${WORK_DIR}"
  else
    echo "Keeping demo workspace: ${WORK_DIR}"
  fi
}
trap cleanup EXIT

cd "${ROOT_DIR}"

run() {
  echo
  echo "+ $*"
  "$@"
}

section() {
  echo
  echo "== $1 =="
}

section "Build shipped CLI"
run go build -o "${BIN}" ./cmd/velocity
export VELOCITY_PATH="${DB_PATH}"

section "Tag every supported compliance resource through the CLI"
run "${BIN}" compliance tag --type kv --path /patients/1 --framework HIPAA --class restricted --encrypt --owner privacy
run "${BIN}" compliance tag --type bucket --bucket reports --framework SOC2 --class internal --owner platform
run "${BIN}" compliance tag --type folder --path reports/2026 --framework GDPR --class confidential --owner records
run "${BIN}" compliance tag --type object --path reports/2026/q1.pdf --framework GDPR,SOC2 --class confidential --encrypt
run "${BIN}" compliance tag --type secret --name api-key --framework GDPR --class confidential --encrypt
run "${BIN}" compliance tag --type secret_version --name api-key --version v1 --framework SOC2 --class restricted --encrypt
run "${BIN}" compliance tag --type sql_schema --schema main --framework HIPAA --class internal
run "${BIN}" compliance tag --type sql_table --table patients --framework HIPAA --class confidential
run "${BIN}" compliance tag --type sql_column --table patients --column ssn --framework HIPAA --class restricted --encrypt
run "${BIN}" compliance tag --type sql_row --table patients --row 123 --framework GDPR --class confidential

section "Read tags and validate operations through the CLI"
run "${BIN}" compliance get --type object --path reports/2026/q1.pdf
run "${BIN}" compliance get --type sql_column --table patients --column ssn
run "${BIN}" compliance get --type secret --name api-key
run "${BIN}" compliance check --type object --path reports/2026/q1.pdf --operation read --actor alice --encrypted
run "${BIN}" compliance check --type secret --name api-key --operation read --actor alice --encrypted
run "${BIN}" compliance check --type sql_table --table patients --operation read --actor analyst

section "Verify the shell wrapper dispatches compliance commands"
VELOCITY_BIN="${BIN}" VELOCITY_PATH="${DB_PATH}" run ./scripts/velocity.sh compliance get --type sql_table --table patients

section "Exercise Go API, KV, object, secret, and SQL enforcement"
cat > "${WORK_DIR}/compliance_flow.go" <<'GO'
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/sqldriver"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ctx := context.Background()
	base := os.Getenv("VELOCITY_PATH") + "_api"

	db, err := velocity.New(base)
	must(err)
	defer db.Close()

	ctm := db.ComplianceTagManager()

	must(ctm.TagResource(ctx, velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceKV, Path: "/patients/1"}, &velocity.ComplianceTag{
		Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkHIPAA},
		DataClass:     velocity.DataClassRestricted,
		EncryptionReq: true,
		CreatedBy:     "script",
	}))
	must(db.PutWithCompliance(ctx, &velocity.ComplianceOperationRequest{
		Path:      "/patients/1",
		Operation: "write",
		Actor:     "nurse.alice",
		Encrypted: true,
	}, []byte("patient email alice@example.test ssn 123-45-6789")))
	value, err := db.GetWithCompliance(ctx, &velocity.ComplianceOperationRequest{
		Path:      "/patients/1",
		Operation: "read",
		Actor:     "nurse.alice",
		Encrypted: true,
	})
	must(err)
	fmt.Printf("KV read is masked: %t\n", strings.Contains(string(value), "*"))

	must(ctm.TagResource(ctx, velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceBucket, Bucket: "reports"}, &velocity.ComplianceTag{
		Frameworks: []velocity.ComplianceFramework{velocity.FrameworkSOC2},
		DataClass:  velocity.DataClassInternal,
		CreatedBy:  "script",
	}))
	must(ctm.TagResource(ctx, velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceFolder, Path: "reports/2026"}, &velocity.ComplianceTag{
		Frameworks: []velocity.ComplianceFramework{velocity.FrameworkSOC2},
		DataClass:  velocity.DataClassConfidential,
		CreatedBy:  "script",
	}))
	_, err = db.StoreObject("reports/2026/q1.txt", "text/plain", "alice", []byte("board report alice@example.test"), &velocity.ObjectOptions{Encrypt: true})
	must(err)
	objectResult, err := ctm.ValidateResourceOperation(ctx, velocity.ComplianceResourceRef{
		Type:   velocity.ComplianceResourceObject,
		Path:   "reports/2026/q1.txt",
		Bucket: "reports",
		Key:    "2026/q1.txt",
	}, &velocity.ComplianceOperationRequest{
		Operation: "read",
		Actor:     "alice",
		Encrypted: true,
	})
	must(err)
	fmt.Printf("Object operation allowed by inherited bucket/folder tags: %t\n", objectResult.Allowed)

	must(ctm.TagResource(ctx, velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceSecret, SecretName: "api-key"}, &velocity.ComplianceTag{
		Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkGDPR},
		DataClass:     velocity.DataClassConfidential,
		EncryptionReq: true,
		CreatedBy:     "script",
	}))
	secret, err := db.CreateSecret(ctx, velocity.SecretRequest{Name: "api-key", Value: []byte("sk-live-demo"), Owner: "alice"})
	must(err)
	must(ctm.TagResource(ctx, velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceSecretVersion, SecretName: "api-key", SecretVersion: secret.Version}, &velocity.ComplianceTag{
		Frameworks: []velocity.ComplianceFramework{velocity.FrameworkSOC2},
		DataClass:  velocity.DataClassConfidential,
		CreatedBy:  "script",
	}))
	_, _, err = db.GetSecretValue(ctx, velocity.SecretRef{Name: "api-key", Version: secret.Version})
	must(err)
	fmt.Printf("Secret version enforced: %s\n", secret.Version)

	sqlPath := filepath.Join(base, "sql")
	sqlSeed, err := velocity.NewWithConfig(velocity.Config{Path: sqlPath, DisableEncryption: true})
	must(err)
	sqlCTM := sqlSeed.ComplianceTagManager()
	must(sqlCTM.TagResource(ctx, velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceSQLSchema, SQLSchema: "main"}, &velocity.ComplianceTag{
		Frameworks: []velocity.ComplianceFramework{velocity.FrameworkSOC2},
		DataClass:  velocity.DataClassInternal,
		CreatedBy:  "script",
	}))
	must(sqlCTM.TagResource(ctx, velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceSQLTable, SQLTable: "patients"}, &velocity.ComplianceTag{
		Frameworks: []velocity.ComplianceFramework{velocity.FrameworkSOC2},
		DataClass:  velocity.DataClassInternal,
		CreatedBy:  "script",
	}))
	must(sqlCTM.TagResource(ctx, velocity.ComplianceResourceRef{Type: velocity.ComplianceResourceSQLColumn, SQLTable: "patients", SQLColumn: "ssn"}, &velocity.ComplianceTag{
		Frameworks: []velocity.ComplianceFramework{velocity.FrameworkSOC2},
		DataClass:  velocity.DataClassRestricted,
		CreatedBy:  "script",
	}))
	must(sqlSeed.Close())

	sqldriver.DSNConfigs[sqlPath] = velocity.Config{Path: sqlPath, DisableEncryption: true}
	defer delete(sqldriver.DSNConfigs, sqlPath)
	sdb, err := sql.Open(sqldriver.DriverName, sqlPath)
	must(err)
	defer sdb.Close()
	_, err = sdb.Exec(`CREATE TABLE patients (id BIGINT PRIMARY KEY, name TEXT, ssn TEXT)`)
	must(err)
	_, err = sdb.Exec(`INSERT INTO patients (id, name, ssn) VALUES (?, ?, ?)`, 1, "Alice", "123-45-6789")
	must(err)
	var ssn string
	must(sdb.QueryRow(`SELECT ssn FROM patients WHERE id = ?`, 1).Scan(&ssn))
	fmt.Printf("SQL column read is masked: %t\n", ssn != "123-45-6789" && strings.Contains(ssn, "*"))
}
GO
run go run "${WORK_DIR}/compliance_flow.go"

section "Run focused automated tests for the changed areas"
run go test -run 'TestComplianceResource|TestComplianceSecretTags' .
run go test ./pkg/sqldriver -run 'TestSQLCompliance' -count=1
run go test ./cmd/velocity -run TestComplianceCLI_TagGetCheck -count=1

section "Compliance full flow completed"
echo "Database path used: ${DB_PATH}"
