package velocity

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func newHardeningTestDB(t *testing.T, encrypted bool) *DB {
	t.Helper()
	cfg := Config{Path: t.TempDir(), DisableEncryption: !encrypted}
	if encrypted {
		cfg.EncryptionKey = bytes.Repeat([]byte{7}, 32)
	}
	db, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestObjectHardeningChecksumCorruptionFailsClosed(t *testing.T) {
	db := newHardeningTestDB(t, false)
	rec, err := db.PutObject(context.Background(), PutObjectRequest{
		Path:        "bucket/doc.txt",
		ContentType: "text/plain",
		User:        "alice",
		Reader:      strings.NewReader("known-good"),
		Options:     &ObjectOptions{Encrypt: false},
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if err := os.WriteFile(objectFilePath(db, rec.ObjectID, rec.VersionID), []byte("corrupted"), 0600); err != nil {
		t.Fatalf("corrupt object file: %v", err)
	}
	_, _, err = db.GetObject("bucket/doc.txt", "alice")
	if !errors.Is(err, ErrObjectIntegrity) {
		t.Fatalf("expected ErrObjectIntegrity, got %v", err)
	}
}

func TestObjectHardeningObjectLockEnforcedOnDelete(t *testing.T) {
	db := newHardeningTestDB(t, false)
	_, err := db.StoreObject("locked-bucket/file.txt", "text/plain", "alice", []byte("locked"), &ObjectOptions{Encrypt: false})
	if err != nil {
		t.Fatalf("StoreObject: %v", err)
	}
	olm := NewObjectLockManager(db)
	if err := olm.SetObjectRetention("locked-bucket", "file.txt", ObjectRetention{
		Mode:            LockModeCompliance,
		RetainUntilDate: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SetObjectRetention: %v", err)
	}
	if err := db.DeleteObject("locked-bucket/file.txt", "alice"); err == nil {
		t.Fatal("expected delete to be denied by object lock")
	}
	if _, _, err := db.GetObject("locked-bucket/file.txt", "alice"); err != nil {
		t.Fatalf("locked object should still be readable: %v", err)
	}
}

func TestObjectHardeningHardDeleteRemovesVersionRecords(t *testing.T) {
	db := newHardeningTestDB(t, false)
	for _, body := range []string{"v1", "v2"} {
		if _, err := db.StoreObject("bucket/versioned.txt", "text/plain", "alice", []byte(body), &ObjectOptions{Encrypt: false}); err != nil {
			t.Fatalf("StoreObject: %v", err)
		}
	}
	versions, err := db.ListObjectVersions("bucket/versioned.txt")
	if err != nil {
		t.Fatalf("ListObjectVersions: %v", err)
	}
	if len(versions) < 2 {
		t.Fatalf("expected at least 2 versions, got %d", len(versions))
	}
	if err := db.HardDeleteObject("bucket/versioned.txt", "alice"); err != nil {
		t.Fatalf("HardDeleteObject: %v", err)
	}
	versions, err = db.ListObjectVersions("bucket/versioned.txt")
	if err != nil {
		t.Fatalf("ListObjectVersions after delete: %v", err)
	}
	if len(versions) != 0 {
		t.Fatalf("expected no version records after hard delete, got %d", len(versions))
	}
}

func TestS3CredentialStoreDoesNotPersistPlaintextSecretWhenEncrypted(t *testing.T) {
	db := newHardeningTestDB(t, true)
	store := NewS3CredentialStore(db)
	cred, err := store.GenerateCredentials("alice", "test")
	if err != nil {
		t.Fatalf("GenerateCredentials: %v", err)
	}
	raw, err := db.Get([]byte(credPrefix + cred.AccessKeyID))
	if err != nil {
		t.Fatalf("raw credential get: %v", err)
	}
	if bytes.Contains(raw, []byte(cred.SecretAccessKey)) {
		t.Fatal("stored credential record contains plaintext secret")
	}
	got, err := store.GetCredential(cred.AccessKeyID)
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if got.SecretAccessKey != cred.SecretAccessKey {
		t.Fatal("decrypted credential secret mismatch")
	}
}

func TestPresignedURLValidationRejectsTampering(t *testing.T) {
	db := newHardeningTestDB(t, false)
	store := NewS3CredentialStore(db)
	cred, err := store.GenerateCredentials("alice", "test")
	if err != nil {
		t.Fatalf("GenerateCredentials: %v", err)
	}
	pg := NewPresignedURLGenerator(store, "us-east-1", "http://localhost:8080")
	rawURL, err := pg.GeneratePresignedGetURL(cred.AccessKeyID, "bucket", "file.txt", time.Minute)
	if err != nil {
		t.Fatalf("GeneratePresignedGetURL: %v", err)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	parsed.Path = "/s3/bucket/other.txt"
	if _, _, err := pg.ValidatePresignedURL(parsed.String()); err == nil {
		t.Fatal("expected tampered URL path to fail signature validation")
	}
}

func TestEnvelopeReferenceValidationPinnedObjectAndSecret(t *testing.T) {
	db := newHardeningTestDB(t, true)
	obj, err := db.StoreObject("bucket/evidence.txt", "text/plain", "alice", []byte("evidence"), &ObjectOptions{Encrypt: true})
	if err != nil {
		t.Fatalf("StoreObject: %v", err)
	}
	secret, err := db.CreateSecret(context.Background(), SecretRequest{Name: "api-key", Value: []byte("secret-value"), Owner: "alice"})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	env, err := db.CreateEnvelope(context.Background(), &EnvelopeRequest{
		Label:     "case file",
		Type:      EnvelopeTypeInvestigationRecord,
		CreatedBy: "alice",
		Payload: EnvelopePayload{
			Kind:            "bundle",
			ObjectPath:      obj.Path,
			ObjectVersion:   obj.VersionID,
			SecretReference: secret.Name,
			Metadata: map[string]string{
				"object_sha256":   obj.Checksum,
				"object_etag":     obj.ETag,
				"secret_version":  secret.Version,
				"secret_checksum": secret.Checksum,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateEnvelope: %v", err)
	}
	report, err := db.ValidateEnvelopeReferences(context.Background(), env.EnvelopeID)
	if err != nil {
		t.Fatalf("ValidateEnvelopeReferences: %v", err)
	}
	if !report.Valid {
		t.Fatalf("expected valid references, problems=%v", report.Problems)
	}
}
