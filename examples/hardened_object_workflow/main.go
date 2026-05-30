package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/oarkflow/velocity/pkg/s3"
	"log"
	"net/url"
	"os"
	"time"

	"github.com/oarkflow/velocity"
)

func main() {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "velocity-hardened-object-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	db, err := velocity.NewWithConfig(velocity.Config{
		Path:          dir,
		EncryptionKey: bytes.Repeat([]byte{42}, 32),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	buckets := s3.NewBucketManager(db, db)
	if err := buckets.CreateBucket("cases", "investigator", "us-east-1"); err != nil {
		log.Fatal(err)
	}
	if err := buckets.SetBucketEncryption("cases", &s3.BucketEncryption{SSEAlgorithm: "AES256"}); err != nil {
		log.Fatal(err)
	}

	locks := velocity.NewObjectLockManager(db)
	if err := locks.SetBucketObjectLock("cases", velocity.ObjectLockConfig{
		Enabled: true,
		DefaultRetention: &velocity.ObjectLockRetentionRule{
			Mode: velocity.LockModeGovernance,
			Days: 1,
		},
	}); err != nil {
		log.Fatal(err)
	}

	record, err := db.PutObject(ctx, velocity.PutObjectRequest{
		Bucket:      "cases",
		Key:         "evidence/report.txt",
		ContentType: "text/plain",
		User:        "investigator",
		Reader:      bytes.NewReader([]byte("sealed evidence payload")),
		Options: &velocity.ObjectOptions{
			Encrypt:      true,
			StorageClass: s3.S3StorageStandard,
			Tags:         map[string]string{"case": "A-100", "kind": "report"},
		},
		EnforceBucket: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("object committed: path=%s version=%s sha256=%s etag=%s\n", record.Path, record.VersionID, record.SHA256, record.ETag)

	stream, err := db.GetObjectStreamV2(ctx, velocity.GetObjectRequest{
		Bucket: "cases",
		Key:    "evidence/report.txt",
		User:   "investigator",
	})
	if err != nil {
		log.Fatal(err)
	}
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(stream); err != nil {
		_ = stream.Close()
		log.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("verified read: %q\n", buf.String())

	secret, err := db.CreateSecret(ctx, velocity.SecretRequest{
		Name:  "case-signing-key",
		Value: []byte("super-secret-signing-material"),
		Owner: "investigator",
		Tags:  map[string]string{"case": "A-100"},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("secret created: name=%s version=%s checksum=%s\n", secret.Name, secret.Version, secret.Checksum)

	envelope, err := db.CreateEnvelope(ctx, &velocity.EnvelopeRequest{
		Label:     "A-100 evidence bundle",
		Type:      velocity.EnvelopeTypeInvestigationRecord,
		CreatedBy: "investigator",
		Payload: velocity.EnvelopePayload{
			Kind:            "bundle",
			ObjectPath:      record.Path,
			ObjectVersion:   record.VersionID,
			SecretReference: secret.Name,
			Metadata: map[string]string{
				"object_sha256":   record.SHA256,
				"object_etag":     record.ETag,
				"secret_version":  secret.Version,
				"secret_checksum": secret.Checksum,
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	report, err := db.ValidateEnvelopeReferences(ctx, envelope.EnvelopeID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("envelope references valid: %v\n", report.Valid)

	creds := s3.NewS3CredentialStore(db, db)
	cred, err := creds.GenerateCredentials("investigator", "demo presigned access")
	if err != nil {
		log.Fatal(err)
	}
	presigner := s3.NewPresignedURLGenerator(creds, "us-east-1", "http://localhost:8080")
	signedURL, err := presigner.GeneratePresignedGetURL(cred.AccessKeyID, "cases", "evidence/report.txt", 15*time.Minute)
	if err != nil {
		log.Fatal(err)
	}
	bucket, key, err := presigner.ValidatePresignedURL(signedURL)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("presigned URL validates for %s/%s\n", bucket, key)

	tampered, _ := url.Parse(signedURL)
	tampered.Path = "/s3/cases/evidence/tampered.txt"
	if _, _, err := presigner.ValidatePresignedURL(tampered.String()); err != nil {
		fmt.Printf("tampered URL rejected: %v\n", err)
	}

	repair, err := db.RepairObjectStorage(ctx, velocity.RepairOptions{DryRun: true})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("repair dry-run: missing=%d orphan=%d rebuilt=%d\n", repair.MissingFiles, repair.OrphanFilesRemoved, repair.IndexesRebuilt)
}
