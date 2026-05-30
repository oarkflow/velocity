# Code And Command Cookbook

This cookbook gives practical examples for the major Velocity surfaces. The shipped command line is intentionally small, so command examples use three forms:

- `./velocity ...` when the current `cmd/velocity` binary supports the workflow.
- `curl ...` when the HTTP or S3 API exposes the workflow.
- `go run ./examples/...` or a small `go run` program when the feature is currently a library/API feature without a shipped CLI command.

## Embedded KV

Go:

```go
package main

import (
	"fmt"
	"log"

	"github.com/oarkflow/velocity"
)

func main() {
	db, err := velocity.New("./velocity_data")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := db.Put([]byte("app:name"), []byte("Velocity")); err != nil {
		log.Fatal(err)
	}
	value, err := db.Get([]byte("app:name"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(value))
}
```

Command:

```bash
go build -o velocity ./cmd/velocity
VELOCITY_PATH=./velocity_data ./velocity data put app:name Velocity
VELOCITY_PATH=./velocity_data ./velocity data get app:name
```

## TTL, Counters, Keys, And Scans

Go:

```go
_ = db.PutWithTTL([]byte("session:123"), []byte("active"), 15*time.Minute)
ttl, _ := db.TTL([]byte("session:123"))
_, _ = db.Incr([]byte("metrics:login"), 1)
_, _ = db.Decr([]byte("quota:remaining"), 1)
keys, _ := db.Keys("session:*")
page, total := db.KeysPage(0, 25)
_ = db.Scan([]byte("session:"), func(key, value []byte) bool {
	fmt.Printf("%s=%s\n", key, value)
	return true
})
fmt.Println(ttl, keys, page, total)
```

Command:

```bash
go test -run 'Example_putWithTTL|Example_keys|Example_incrDecr|Example_keysPage' .
```

## Indexed Search

Go:

```go
schema := &velocity.SearchSchema{
	Fields: []velocity.SearchSchemaField{
		{Name: "title", Type: "text"},
		{Name: "kind", Type: "value"},
		{Name: "owner", Type: "hash"},
	},
}

_ = db.PutIndexed(
	[]byte("docs:1"),
	[]byte(`{"title":"Velocity compliance guide","kind":"guide","owner":"alice"}`),
	schema,
)

results, err := db.Search(velocity.SearchQuery{
	Prefix: "docs:",
	Text:   "compliance",
	Limit:  10,
})
if err != nil {
	log.Fatal(err)
}
fmt.Println(len(results))
```

Command:

```bash
go run ./examples/kv_search_cookbook
go run ./examples/encrypted_search_demo
go run ./examples/fulltext_demo
```

## SQL Driver

Go:

```go
package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/oarkflow/velocity/pkg/sqldriver"
)

func main() {
	db, err := sql.Open("velocity", "./sql_data")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, _ = db.Exec(`CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT UNIQUE, name TEXT NOT NULL)`)
	_, _ = db.Exec(`INSERT INTO users (id, email, name) VALUES (?, ?, ?)`, 1, "alice@example.test", "Alice")

	var name string
	if err := db.QueryRow(`SELECT name FROM users WHERE id = ?`, 1).Scan(&name); err != nil {
		log.Fatal(err)
	}
	fmt.Println(name)
}
```

Command:

```bash
go run ./examples/sql_crud_demo
go run ./examples/sql_complete_demo
go test ./pkg/sqldriver
```

## Native Objects And Folders

Go:

```go
meta, err := db.StoreObject(
	"reports/q1.txt",
	"text/plain",
	"alice",
	[]byte("quarterly report"),
	&velocity.ObjectOptions{
		Encrypt: true,
		Tags: map[string]string{
			"class": "internal",
		},
	},
)
if err != nil {
	log.Fatal(err)
}

data, gotMeta, err := db.GetObject("reports/q1.txt", "alice")
fmt.Println(meta.Path, gotMeta.ContentType, string(data))
```

Command:

```bash
VELOCITY_PATH=./velocity_data ./velocity object preview ./README.md docs/readme.md
go run ./examples/object_storage_cookbook
go run ./examples/folder_management_demo
go run ./examples/hardened_object_workflow
```

HTTP command:

```bash
curl -X POST 'http://localhost:8081/api/objects/reports/q1.txt?public=true' \
  -H "Authorization: Bearer $TOKEN" \
  -F 'file=@README.md'

curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8081/api/objects/reports/q1.txt
```

## S3-Compatible API

Go:

```go
bucketMgr := velocity.NewBucketManager(db)
_ = bucketMgr.CreateBucket("archive", "alice", "us-east-1")

_ = db.PutObjectTagging("archive", "reports/q1.txt", map[string]string{
	"class": "internal",
})
tags, _ := db.GetObjectTagging("archive", "reports/q1.txt")
fmt.Println(tags)
```

Command:

```bash
go run ./examples/s3_demo
go run ./examples/s3_bucket_cookbook
go test -run 'TestS3CredentialStore|TestSigV4Auth|TestBucketManager|TestMultipartManager|TestPresignedURLGenerator|TestS3ObjectOps' .
```

HTTP command shape:

```bash
curl -X PUT http://localhost:8081/s3/archive \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=VK.../20260530/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=..."
```

Use the project's S3 credential and presigned URL helpers to generate real SigV4 headers or URLs.

## Secrets

Go:

```go
rec, err := db.CreateSecret(context.Background(), velocity.SecretRequest{
	Name:  "api-key",
	Value: []byte("sk_live_example"),
	Owner: "alice",
	Tags: map[string]string{
		"env": "prod",
	},
})
if err != nil {
	log.Fatal(err)
}

value, _, err := db.GetSecretValue(context.Background(), velocity.SecretRef{
	Name:    rec.Name,
	Version: rec.Version,
})
fmt.Println(string(value))
```

Command:

```bash
VELOCITY_PATH=./velocity_data ./velocity secret set api_key sk_test
VELOCITY_PATH=./velocity_data ./velocity secret get api_key
go run ./examples/security_auth
```

## Secure Envelopes

Go:

```go
env, err := db.CreateEnvelope(context.Background(), &velocity.EnvelopeRequest{
	Label:     "Case 001",
	Type:      velocity.EnvelopeType("court_evidence"),
	CreatedBy: "alice",
	Payload: velocity.EnvelopePayload{
		Kind:       "kv",
		Key:        "evidence:note",
		Value:      json.RawMessage(`{"note":"sealed evidence note"}`),
		InlineData: []byte("sealed evidence note"),
	},
})
if err != nil {
	log.Fatal(err)
}

env, _ = db.AppendCustodyEvent(context.Background(), env.ID, &velocity.CustodyEvent{
	Actor:  "alice",
	Action: "created",
	Notes:  "initial evidence intake",
})
fmt.Println(env.ID)
```

Command:

```bash
VELOCITY_PATH=./velocity_data ./velocity envelope create --label "Case 001" --type court_evidence
VELOCITY_PATH=./velocity_data ./velocity envelope export --id "$ENVELOPE_ID" --path case.sec
VELOCITY_PATH=./velocity_data ./velocity envelope import --path case.sec
go run ./examples/envelope_workflow
go run ./examples/envelope_bundle_demo
go run ./examples/envelope_audit_chain_demo
```

## Compliance Tags And Enforcement

Go:

```go
ctx := context.Background()
ctm := velocity.NewComplianceTagManager(db)
db.SetComplianceTagManager(ctm)

err := ctm.TagPath(ctx, &velocity.ComplianceTag{
	Path:          "/patients",
	Frameworks:    []velocity.ComplianceFramework{velocity.FrameworkHIPAA, velocity.FrameworkGDPR},
	DataClass:     velocity.DataClassRestricted,
	Owner:         "privacy",
	Custodian:     "platform",
	RetentionDays: 2555,
	EncryptionReq: true,
	AuditLevel:    "high",
	CreatedBy:     "admin",
})
if err != nil {
	log.Fatal(err)
}

req := &velocity.ComplianceOperationRequest{
	Path:            "/patients/123",
	Operation:       "write",
	Actor:           "nurse.alice",
	Region:          "US",
	SubjectID:       "patient-123",
	Purpose:         "treatment",
	Encrypted:       true,
	MFAVerified:     true,
	CryptoAlgorithm: "AES-256-GCM",
}

result, err := ctm.ValidateOperation(ctx, req)
if err != nil {
	log.Fatal(err)
}
fmt.Println(result.Allowed, result.RequiredActions)

if err := db.PutWithCompliance(ctx, req, []byte("MRN: 123456 diagnosis note")); err != nil {
	log.Fatal(err)
}
masked, _ := db.GetWithCompliance(ctx, &velocity.ComplianceOperationRequest{
	Path:      "/patients/123",
	Operation: "read",
	Actor:     "nurse.alice",
	SubjectID: "patient-123",
	Purpose:   "treatment",
})
fmt.Println(string(masked))
```

Command:

```bash
go run ./examples/compliance_demo
go run ./examples/compliance_full_demo
go run ./examples/compliance_governance_cookbook
go run ./examples/enterprise_compliance_demo
go test -run 'TestComplianceTagManager|TestCompliancePutGetWithConsentAndMasking|TestRetentionAnonymizeObject|TestDataResidencyBlocksObjectWrite|TestBreachIncidentOnCriticalViolation' .
```

There is no shipped `./velocity compliance ...` command in `cmd/velocity` today. The richer `pkg/cli` framework also does not currently include a compliance command builder.

## Retention, Residency, And Lineage

Go:

```go
retention := velocity.NewRetentionManager(db)
_ = retention.AddPolicy(ctx, velocity.RetentionPolicy{
	PolicyID:        "restricted-7y",
	DataType:        string(velocity.DataClassRestricted),
	RetentionPeriod: 7 * 365 * 24 * time.Hour,
	DeletionMethod:  "cryptographic_erase",
	ReviewInterval:  90 * 24 * time.Hour,
})

residency := velocity.NewDataResidencyManager(db)
_ = residency.AddPolicy(ctx, &velocity.DataResidencyPolicy{
	PathPrefix: "/patients",
	Regions:    []string{"US"},
	Framework:  string(velocity.FrameworkHIPAA),
	Enabled:    true,
})
allowed, policy, _ := residency.ValidateResidency(ctx, "/patients/123", "EU")
fmt.Println(allowed, policy.PolicyID)

lineage := velocity.NewLineageManager(db)
_ = lineage.RecordEvent(ctx, &velocity.LineageEvent{
	Path:   "/patients/123",
	Action: "read",
	Actor:  "nurse.alice",
})
events, _ := lineage.GetLineage(ctx, "/patients/123")
fmt.Println(len(events))
```

Command:

```bash
go test -run 'TestRetentionAnonymizeObject|TestDataResidencyBlocksObjectWrite' .
```

## Compliance Reports And Violations

Go:

```go
audit := velocity.NewAuditLogManager(db)
violations := velocity.NewViolationsManager(db)
reports := velocity.NewReportingManager(db, audit, violations)

report, err := reports.GenerateReport(ctx, "all", velocity.ReportPeriod{
	StartDate: time.Now().Add(-30 * 24 * time.Hour),
	EndDate:   time.Now(),
	Duration:  "monthly",
}, "auditor")
if err != nil {
	log.Fatal(err)
}

jsonBytes, _ := reports.ExportReport(ctx, report, "json")
fmt.Println(string(jsonBytes))
```

Command:

```bash
go test -run 'TestComplianceTagManager|TestPolicyPacksInstall' .
```

## Master Keys And Crypto

Go:

```go
db, err := velocity.NewWithConfig(velocity.Config{
	Path: "./secure_data",
	MasterKeyConfig: velocity.MasterKeyConfig{
		Source: velocity.SystemFile,
	},
})
if err != nil {
	log.Fatal(err)
}
defer db.Close()

fmt.Println(len(db.MasterKey()))
```

Command:

```bash
go run ./examples/master_key_demo
go run ./examples/interactive_key_demo
go test -run 'TestMasterKeyManager|TestFIPSCryptoProvider|TestDeriveKey' .
```

Admin HTTP command:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8081/admin/masterkey/cache/info
```

## Knowledge Graph

Go:

```go
kg := db.KnowledgeGraph()
resp, err := kg.Ingest(context.Background(), &velocity.KGIngestRequest{
	Source:    "note-1",
	Title:     "Velocity note",
	MediaType: "text/plain",
	Content:   []byte("Alice works at Acme and uses Velocity for search."),
})
if err != nil {
	log.Fatal(err)
}

search, _ := kg.Search(context.Background(), &velocity.KGSearchRequest{
	Query: "Velocity search",
	Limit: 5,
})
fmt.Println(resp.DocID, len(search.Hits))
```

Command:

```bash
go run ./examples/kg_cookbook
go run ./examples/kg_batch_demo
go run ./examples/kg_ner_demo
go run ./examples/kg_search_demo
```

HTTP command:

```bash
curl -X POST http://localhost:8081/api/v1/kg/ingest \
  -H 'Content-Type: application/json' \
  -d '{"source":"note-1","title":"Velocity note","media_type":"text/plain","content":"VmVsb2NpdHkgc2VhcmNoIG5vdGU="}'
```

## HTTP Server

Go:

```go
userDB, err := web.NewSQLiteUserStorage("./users.db")
if err != nil {
	log.Fatal(err)
}
srv := web.NewHTTPServer(db, "8081", userDB)
log.Fatal(srv.Start())
```

Command:

```bash
cd pkg/web
VELOCITY_BOOTSTRAP_ADMIN_USER=admin \
VELOCITY_BOOTSTRAP_ADMIN_PASS='change-me' \
go run ./cmd serve --http 8081 --tcp 8080 --dir ./velocitydb_server --users ./users.db
```

Login command:

```bash
curl -s -X POST http://localhost:8081/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"change-me"}'
```

## Backup And Restore

Go:

```go
err := db.Backup(velocity.BackupOptions{
	OutputPath:  "./backups/snapshot.velbak",
	Compress:    true,
	Encrypt:     true,
	Description: "nightly snapshot",
	User:        "operator",
})
if err != nil {
	log.Fatal(err)
}

err = db.Restore(velocity.RestoreOptions{
	BackupPath: "./backups/snapshot.velbak",
	Overwrite:  true,
	User:       "operator",
})
```

Command:

```bash
go run ./examples/backup_resilience_cookbook
go test -run 'TestProductionBackupRestoreDisasterRecovery|TestProductionBackupTamperRejected' .
```
