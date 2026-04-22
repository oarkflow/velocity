package velocity

import (
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// BackupSignature provides tamper-proof verification
type BackupSignature struct {
	Algorithm   string    `json:"algorithm"`
	Hash        string    `json:"hash"`         // SHA-512 of content
	HMAC        string    `json:"hmac"`         // HMAC-SHA512 signature
	SignedAt    time.Time `json:"signed_at"`
	SignedBy    string    `json:"signed_by"`
	Fingerprint string    `json:"fingerprint"` // Device/system fingerprint
	ChainID     string    `json:"chain_id"`    // Links to previous operation
}

// AuditRecord tracks all backup/restore operations
type AuditRecord struct {
	ID          string                 `json:"id"`           // Unique operation ID
	Operation   string                 `json:"operation"`    // backup, restore, export, import
	Type        string                 `json:"type"`         // full, partial, selective
	User        string                 `json:"user"`
	Timestamp   time.Time              `json:"timestamp"`
	FilePath    string                 `json:"file_path"`
	ItemCount   int                    `json:"item_count"`
	Success     bool                   `json:"success"`
	ErrorMsg    string                 `json:"error_msg,omitempty"`
	Signature   BackupSignature        `json:"signature"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	PreviousID  string                 `json:"previous_id,omitempty"` // Chain link
	Fingerprint string                 `json:"fingerprint"`           // System fingerprint
}

// SecureBackupMetadata extends BackupMetadata with security features
type SecureBackupMetadata struct {
	BackupMetadata
	Signature       BackupSignature `json:"signature"`
	AuditID         string          `json:"audit_id"`
	IntegrityCheck  string          `json:"integrity_check"`  // Overall file hash
	VerificationKey string          `json:"verification_key"` // Public key for verification
	ChainLinks      []string        `json:"chain_links"`      // Previous backup IDs
}

// generateHMAC creates HMAC-SHA512 signature
func (db *DB) generateHMAC(data []byte) (string, error) {
	if db.masterKey == nil || len(db.masterKey) == 0 {
		return "", fmt.Errorf("master key not initialized")
	}

	h := hmac.New(sha512.New, db.masterKey)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifyHMAC verifies HMAC-SHA512 signature
func (db *DB) verifyHMAC(data []byte, signature string) error {
	expectedMAC, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature format: %w", err)
	}

	if db.masterKey == nil || len(db.masterKey) == 0 {
		return fmt.Errorf("master key not initialized")
	}

	h := hmac.New(sha512.New, db.masterKey)
	h.Write(data)
	actualMAC := h.Sum(nil)

	if !hmac.Equal(actualMAC, expectedMAC) {
		return fmt.Errorf("HMAC verification failed: signature mismatch")
	}

	return nil
}

// hashData creates SHA-512 hash
func hashData(data []byte) string {
	h := sha512.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// createSignature generates cryptographic signature for backup
func (db *DB) createSignature(data []byte, user string) (BackupSignature, error) {
	hash := hashData(data)
	hmacSig, err := db.generateHMAC(data)
	if err != nil {
		return BackupSignature{}, err
	}

	fingerprint, _ := GetCurrentDeviceFingerprint()

	return BackupSignature{
		Algorithm:   "HMAC-SHA512",
		Hash:        hash,
		HMAC:        hmacSig,
		SignedAt:    time.Now(),
		SignedBy:    user,
		Fingerprint: fingerprint,
		ChainID:     db.getLastAuditID(),
	}, nil
}

// verifySignature validates backup signature
func (db *DB) verifySignature(data []byte, signature BackupSignature) error {
	// Verify hash
	expectedHash := hashData(data)
	if subtle.ConstantTimeCompare([]byte(expectedHash), []byte(signature.Hash)) != 1 {
		return fmt.Errorf("integrity check failed: hash mismatch")
	}

	// Verify HMAC
	if err := db.verifyHMAC(data, signature.HMAC); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Check signature age (prevent replay attacks)
	age := time.Since(signature.SignedAt)
	if age > 365*24*time.Hour {
		return fmt.Errorf("signature expired (age: %s)", age)
	}

	return nil
}

// recordAudit logs operation to audit trail
func (db *DB) recordAudit(record AuditRecord) error {
	record.ID = generateAuditID()
	record.Timestamp = time.Now()
	record.PreviousID = db.getLastAuditID()

	fingerprint, _ := GetCurrentDeviceFingerprint()
	record.Fingerprint = fingerprint

	// Store in database
	key := []byte(fmt.Sprintf("audit:%s:%s", record.Timestamp.Format("20060102"), record.ID))
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal audit record: %w", err)
	}

	if err := db.Put(key, data); err != nil {
		return fmt.Errorf("failed to store audit record: %w", err)
	}

	// Update last audit ID
	db.setLastAuditID(record.ID)

	return nil
}

// getLastAuditID retrieves the last audit record ID for chain linking
func (db *DB) getLastAuditID() string {
	data, err := db.Get([]byte("audit:last_id"))
	if err != nil {
		return ""
	}
	return string(data)
}

// setLastAuditID stores the last audit record ID
func (db *DB) setLastAuditID(id string) {
	_ = db.Put([]byte("audit:last_id"), []byte(id))
}

// generateAuditID creates unique audit ID
func generateAuditID() string {
	return fmt.Sprintf("audit-%d-%s", time.Now().UnixNano(), randomHex(8))
}

// randomHex generates random hex string
func randomHex(n int) string {
	return hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))[:n]
}

// GetAuditTrail retrieves audit records with optional filtering
func (db *DB) GetAuditTrail(startDate, endDate time.Time, operation string) ([]AuditRecord, error) {
	records := make([]AuditRecord, 0)

	// Scan through audit records
	keys, _ := db.KeysPage(0, 10000)

	for _, key := range keys {
		keyStr := string(key)
		if len(keyStr) < 6 || keyStr[:6] != "audit:" {
			continue
		}

		data, err := db.Get(key)
		if err != nil {
			continue
		}

		var record AuditRecord
		if err := json.Unmarshal(data, &record); err != nil {
			continue
		}

		// Apply filters
		if !startDate.IsZero() && record.Timestamp.Before(startDate) {
			continue
		}
		if !endDate.IsZero() && record.Timestamp.After(endDate) {
			continue
		}
		if operation != "" && record.Operation != operation {
			continue
		}

		records = append(records, record)
	}

	return records, nil
}

// VerifyBackupIntegrity performs comprehensive integrity check
func (db *DB) VerifyBackupIntegrity(backupPath string) (*BackupMetadata, error) {
	// Read backup file
	f, err := os.Open(backupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup: %w", err)
	}
	defer f.Close()

	var reader io.Reader = f

	// Try gzip decompression
	gzReader, err := gzip.NewReader(f)
	if err == nil {
		defer gzReader.Close()
		reader = gzReader
	} else {
		// Reset file pointer if not gzip
		if _, err := f.Seek(0, 0); err != nil {
			return nil, fmt.Errorf("failed to reset file: %w", err)
		}
		reader = f
	}

	// Read all data
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup data: %w", err)
	}

	// Parse backup
	var backup map[string]json.RawMessage
	if err := json.Unmarshal(data, &backup); err != nil {
		return nil, fmt.Errorf("failed to parse backup: %w", err)
	}

	// Extract metadata
	var metadata BackupMetadata
	if err := json.Unmarshal(backup["metadata"], &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	// Verify signature of items data
	contentData := backup["items"]
	if err := db.verifySignature(contentData, metadata.Signature); err != nil {
		return nil, fmt.Errorf("integrity verification failed: %w", err)
	}

	// The integrity check was calculated before the integrity field was added,
	// so we need to recalculate it the same way for comparison
	tempBackup := map[string]any{
		"metadata": BackupMetadata{
			Version:        metadata.Version,
			CreatedAt:      metadata.CreatedAt,
			DBPath:         metadata.DBPath,
			Compressed:     metadata.Compressed,
			Encrypted:      metadata.Encrypted,
			ItemCount:      metadata.ItemCount,
			TotalSize:      metadata.TotalSize,
			User:           metadata.User,
			Description:    metadata.Description,
			Signature:      metadata.Signature,
			AuditID:        metadata.AuditID,
			ChainLinks:     metadata.ChainLinks,
			IntegrityCheck: "", // Empty for first hash calculation
		},
		"items": json.RawMessage(contentData),
	}

	tempData, err := json.Marshal(tempBackup)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal for integrity check: %w", err)
	}

	// Verify overall integrity check
	overallHash := hashData(tempData)
	if subtle.ConstantTimeCompare([]byte(overallHash), []byte(metadata.IntegrityCheck)) != 1 {
		return nil, fmt.Errorf("file integrity check failed")
	}

	return &metadata, nil
}

// ExportAuditTrail exports audit trail to file
func (db *DB) ExportAuditTrail(outputPath string, startDate, endDate time.Time) error {
	records, err := db.GetAuditTrail(startDate, endDate, "")
	if err != nil {
		return err
	}

	export := map[string]interface{}{
		"version":      "1.0",
		"exported_at":  time.Now(),
		"record_count": len(records),
		"records":      records,
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0600)
}

// VerifyAuditChain verifies the integrity of the audit trail chain
func (db *DB) VerifyAuditChain() (bool, []string, error) {
	records, err := db.GetAuditTrail(time.Time{}, time.Time{}, "")
	if err != nil {
		return false, nil, err
	}

	if len(records) == 0 {
		return true, nil, nil
	}

	issues := make([]string, 0)
	recordMap := make(map[string]*AuditRecord)

	// Build map
	for i := range records {
		recordMap[records[i].ID] = &records[i]
	}

	// Verify chain
	for i := range records {
		record := &records[i]
		if record.PreviousID != "" {
			prev, exists := recordMap[record.PreviousID]
			if !exists {
				issues = append(issues, fmt.Sprintf("Record %s references missing previous record %s", record.ID, record.PreviousID))
			} else if prev.Timestamp.After(record.Timestamp) {
				issues = append(issues, fmt.Sprintf("Record %s timestamp (%s) is before previous record %s (%s)",
					record.ID, record.Timestamp, record.PreviousID, prev.Timestamp))
			}
		}
	}

	return len(issues) == 0, issues, nil
}

// getBackupChainLinks retrieves recent backup IDs for chain linking
func (db *DB) getBackupChainLinks(count int) []string {
	keys, _ := db.KeysPage(0, 1000)
	links := make([]string, 0, count)

	for _, key := range keys {
		keyStr := string(key)
		if len(keyStr) > 14 && keyStr[:14] == "backup:ref:id:" {
			backupID := keyStr[14:]
			links = append(links, backupID)
			if len(links) >= count {
				break
			}
		}
	}

	return links
}

// storeBackupReference stores backup reference for chain linking
func (db *DB) storeBackupReference(auditID, path string) {
	key := []byte(fmt.Sprintf("backup:ref:id:%s", auditID))
	data := map[string]string{
		"audit_id":  auditID,
		"path":      path,
		"timestamp": time.Now().Format(time.RFC3339),
	}
	jsonData, _ := json.Marshal(data)
	_ = db.Put(key, jsonData)
}
