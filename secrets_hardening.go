package velocity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	SecretRecordPrefix = "secret:record:"
	SecretLatestPrefix = "secret:latest:"
)

type SecretRef struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type SecretRequest struct {
	Name      string            `json:"name"`
	Value     []byte            `json:"-"`
	Owner     string            `json:"owner,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
}

type SecretRecord struct {
	SecretID       string            `json:"secret_id"`
	Name           string            `json:"name"`
	Version        string            `json:"version"`
	EncryptedValue string            `json:"encrypted_value,omitempty"`
	Value          []byte            `json:"value,omitempty"`
	KeyID          string            `json:"key_id,omitempty"`
	KeyVersion     int               `json:"key_version,omitempty"`
	Checksum       string            `json:"checksum"`
	Owner          string            `json:"owner,omitempty"`
	Tags           map[string]string `json:"tags,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	RotatedAt      time.Time         `json:"rotated_at,omitempty"`
	ExpiresAt      *time.Time        `json:"expires_at,omitempty"`
}

type EnvelopeValidationReport struct {
	EnvelopeID string   `json:"envelope_id"`
	Valid      bool     `json:"valid"`
	Problems   []string `json:"problems,omitempty"`
}

func (db *DB) CreateSecret(ctx context.Context, req SecretRequest) (*SecretRecord, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("secret name is required")
	}
	if err := db.validateSecretCompliance(ctx, "write", req.Name, "", req.Owner, true); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	rec := &SecretRecord{
		SecretID:   "sec-" + generateVersionID(),
		Name:       req.Name,
		Version:    generateVersionID(),
		Owner:      req.Owner,
		Tags:       cloneStringMap(req.Tags),
		CreatedAt:  now,
		RotatedAt:  now,
		ExpiresAt:  req.ExpiresAt,
		KeyVersion: 1,
	}
	if err := db.sealSecretRecord(rec, req.Value); err != nil {
		return nil, err
	}
	if err := db.saveSecretRecord(rec); err != nil {
		return nil, err
	}
	if err := db.PutWithTTL([]byte(SecretLatestPrefix+req.Name), []byte(rec.Version), 0); err != nil {
		return nil, err
	}
	return rec, nil
}

func (db *DB) RotateSecret(ctx context.Context, ref SecretRef) (*SecretRecord, error) {
	value, old, err := db.GetSecretValue(ctx, ref)
	if err != nil {
		return nil, err
	}
	if err := db.validateSecretCompliance(ctx, "write", old.Name, old.Version, old.Owner, true); err != nil {
		return nil, err
	}
	return db.CreateSecret(ctx, SecretRequest{
		Name:      old.Name,
		Value:     value,
		Owner:     old.Owner,
		Tags:      old.Tags,
		ExpiresAt: old.ExpiresAt,
	})
}

func (db *DB) GetSecretValue(ctx context.Context, ref SecretRef) ([]byte, *SecretRecord, error) {
	rec, err := db.GetSecretRecord(ref)
	if err != nil {
		legacyKey := "secret:" + ref.Name
		data, legacyErr := db.Get([]byte(legacyKey))
		if legacyErr != nil {
			return nil, nil, err
		}
		sum := sha256.Sum256(data)
		return data, &SecretRecord{Name: ref.Name, Version: "legacy", Checksum: hex.EncodeToString(sum[:])}, nil
	}
	if rec.ExpiresAt != nil && time.Now().After(*rec.ExpiresAt) {
		return nil, nil, fmt.Errorf("secret expired")
	}
	if err := db.validateSecretCompliance(ctx, "read", rec.Name, rec.Version, rec.Owner, true); err != nil {
		return nil, nil, err
	}
	value, err := db.openSecretRecord(rec)
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(value)
	if rec.Checksum != "" && rec.Checksum != hex.EncodeToString(sum[:]) {
		return nil, nil, fmt.Errorf("%w: secret checksum mismatch", ErrObjectIntegrity)
	}
	return value, rec, nil
}

func (db *DB) GetSecretRecord(ref SecretRef) (*SecretRecord, error) {
	if ref.Name == "" {
		return nil, fmt.Errorf("secret name is required")
	}
	version := ref.Version
	if version == "" {
		data, err := db.Get([]byte(SecretLatestPrefix + ref.Name))
		if err != nil {
			return nil, err
		}
		version = string(data)
	}
	data, err := db.Get([]byte(secretRecordKey(ref.Name, version)))
	if err != nil {
		return nil, err
	}
	var rec SecretRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	if err := db.validateSecretCompliance(context.Background(), "read", rec.Name, rec.Version, rec.Owner, true); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (db *DB) validateSecretCompliance(ctx context.Context, operation, name, version, actor string, encrypted bool) error {
	if db.complianceTagManager == nil || name == "" {
		return nil
	}
	ref := ComplianceResourceRef{Type: ComplianceResourceSecret, SecretName: name}
	if version != "" {
		ref = ComplianceResourceRef{Type: ComplianceResourceSecretVersion, SecretName: name, SecretVersion: version}
	}
	result, err := db.complianceTagManager.ValidateResourceOperation(ctx, ref, &ComplianceOperationRequest{
		Operation: operation,
		Actor:     actor,
		Encrypted: encrypted,
		Timestamp: time.Now(),
	})
	if err != nil {
		return err
	}
	if !result.Allowed {
		return fmt.Errorf("compliance violation: %s", strings.Join(result.ViolatedRules, "; "))
	}
	return nil
}

func (db *DB) ValidateEnvelopeReferences(ctx context.Context, envelopeID string) (*EnvelopeValidationReport, error) {
	_ = ctx
	env, err := db.loadEnvelope(envelopeID)
	if err != nil {
		return nil, err
	}
	report := &EnvelopeValidationReport{EnvelopeID: envelopeID, Valid: true}
	checkObject := func(path, version, wantChecksum, wantETag string) {
		if path == "" {
			return
		}
		rec, err := db.getObjectRecord(path)
		if err != nil {
			report.Problems = append(report.Problems, "missing object: "+path)
			return
		}
		if version != "" && rec.VersionID != version {
			if v, err := db.getObjectVersion(path, version); err == nil {
				rec.VersionID = v.VersionID
				rec.SHA256 = v.Hash
				rec.ETag = v.ETag
			} else {
				report.Problems = append(report.Problems, "missing object version: "+path+"@"+version)
				return
			}
		}
		if wantChecksum != "" && rec.SHA256 != wantChecksum {
			report.Problems = append(report.Problems, "object checksum mismatch: "+path)
		}
		if wantETag != "" && rec.ETag != wantETag {
			report.Problems = append(report.Problems, "object etag mismatch: "+path)
		}
	}
	checkSecret := func(ref, version, checksum string) {
		if ref == "" {
			return
		}
		_, rec, err := db.GetSecretValue(ctx, SecretRef{Name: ref, Version: version})
		if err != nil {
			report.Problems = append(report.Problems, "missing secret: "+ref)
			return
		}
		if checksum != "" && rec.Checksum != checksum {
			report.Problems = append(report.Problems, "secret checksum mismatch: "+ref)
		}
	}
	checkObject(env.Payload.ObjectPath, env.Payload.ObjectVersion, env.Payload.Metadata["object_sha256"], env.Payload.Metadata["object_etag"])
	checkSecret(env.Payload.SecretReference, env.Payload.Metadata["secret_version"], env.Payload.Metadata["secret_checksum"])
	for _, res := range env.Payload.Resources {
		checkObject(res.Path, res.Version, res.Metadata["object_sha256"], res.Metadata["object_etag"])
		checkSecret(res.SecretRef, res.Metadata["secret_version"], res.Metadata["secret_checksum"])
	}
	if len(report.Problems) > 0 {
		report.Valid = false
	}
	return report, nil
}

func (db *DB) sealSecretRecord(rec *SecretRecord, value []byte) error {
	sum := sha256.Sum256(value)
	rec.Checksum = hex.EncodeToString(sum[:])
	if db.crypto != nil {
		nonce, ciphertext, err := db.crypto.Encrypt(value, []byte(rec.Name+":"+rec.Version))
		if err != nil {
			return err
		}
		sealed := make([]byte, 0, len(nonce)+len(ciphertext))
		sealed = append(sealed, nonce...)
		sealed = append(sealed, ciphertext...)
		rec.EncryptedValue = hex.EncodeToString(sealed)
		rec.Value = nil
		rec.KeyID = "db-master"
		return nil
	}
	rec.Value = append([]byte(nil), value...)
	return nil
}

func (db *DB) openSecretRecord(rec *SecretRecord) ([]byte, error) {
	if rec.EncryptedValue == "" {
		return append([]byte(nil), rec.Value...), nil
	}
	if db.crypto == nil {
		return nil, fmt.Errorf("secret is encrypted but database crypto is unavailable")
	}
	sealed, err := hex.DecodeString(rec.EncryptedValue)
	if err != nil {
		return nil, err
	}
	if len(sealed) < 24 {
		return nil, fmt.Errorf("secret record is malformed")
	}
	return db.crypto.Decrypt(sealed[:24], sealed[24:], []byte(rec.Name+":"+rec.Version))
}

func (db *DB) saveSecretRecord(rec *SecretRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return db.PutWithTTL([]byte(secretRecordKey(rec.Name, rec.Version)), data, 0)
}

func secretRecordKey(name, version string) string {
	return SecretRecordPrefix + name + ":" + version
}
