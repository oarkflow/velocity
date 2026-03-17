package velocity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var (
	ErrEnvelopeNotFound = errors.New("envelope not found")
	ErrTimeLockActive   = errors.New("time-lock is still active")
)

// EnvelopeType describes evidence presets for the secure cabinet.
type EnvelopeType string

const (
	EnvelopeTypeCourtEvidence       EnvelopeType = "court_evidence"
	EnvelopeTypeInvestigationRecord EnvelopeType = "investigation_record"
	EnvelopeTypeCustodyProof        EnvelopeType = "custody_proof"
	EnvelopeTypeCCTVArchive         EnvelopeType = "cctv_forensic_archive"
)

// Envelope models a secure evidence wrapper persisted as JSON.
type Envelope struct {
	EnvelopeID           string            `json:"envelope_id"`
	Label                string            `json:"label"`
	Type                 EnvelopeType      `json:"type"`
	EvidenceClass        string            `json:"evidence_class,omitempty"`
	Status               string            `json:"status"`
	CreatedAt            time.Time         `json:"created_at"`
	CreatedBy            string            `json:"created_by"`
	LastUpdatedAt        time.Time         `json:"last_updated_at"`
	FingerprintSignature string            `json:"fingerprint_signature,omitempty"`
	CaseReference        string            `json:"case_reference,omitempty"`
	Payload              EnvelopePayload   `json:"payload"`
	Policies             EnvelopePolicies  `json:"policies"`
	Integrity            EnvelopeIntegrity `json:"integrity"`
	CustodyLedger        []*CustodyEvent   `json:"custody_ledger"`
	AuditLog             []*AuditEntry     `json:"audit_log"`
	ColdStorage          ColdStorageStatus `json:"cold_storage"`
	TamperSignals        []*TamperSignal   `json:"tamper_signals,omitempty"`
	TimeLockStatus       TimeLockStatus    `json:"time_lock_status"`
	Tags                 map[string]string `json:"tags,omitempty"`
	Notes                string            `json:"notes,omitempty"`
}

// EnvelopePayload specifies what is being sealed.
type EnvelopePayload struct {
	Kind            string            `json:"kind"` // file | kv | secret
	ObjectPath      string            `json:"object_path,omitempty"`
	ObjectVersion   string            `json:"object_version,omitempty"`
	InlineData      []byte            `json:"inline_data,omitempty"`
	Key             string            `json:"key,omitempty"`
	Value           json.RawMessage   `json:"value,omitempty"`
	SecretReference string            `json:"secret_reference,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	EncodingHint    string            `json:"encoding_hint,omitempty"`
}

// Digest derives a deterministic payload hash for integrity tracking.
func (p EnvelopePayload) Digest() string {
	h := sha256.New()
	h.Write([]byte(p.Kind))
	h.Write([]byte(p.ObjectPath))
	h.Write([]byte(p.ObjectVersion))
	h.Write(p.InlineData)
	h.Write([]byte(p.Key))
	h.Write([]byte(p.SecretReference))
	if len(p.Value) > 0 {
		h.Write(p.Value)
	}
	if len(p.Metadata) > 0 {
		meta, _ := json.Marshal(p.Metadata)
		h.Write(meta)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// EnvelopePolicies bundles access, storage, and tamper controls.
type EnvelopePolicies struct {
	Fingerprint FingerprintPolicy `json:"fingerprint"`
	TimeLock    TimeLockPolicy    `json:"time_lock"`
	ColdStorage ColdStoragePolicy `json:"cold_storage"`
	Tamper      TamperPolicy      `json:"tamper"`
}

// FingerprintPolicy governs biometric gating.
type FingerprintPolicy struct {
	Required               bool     `json:"required"`
	MatchingStrategy       string   `json:"matching_strategy,omitempty"`
	AuthorizedFingerprints []string `json:"authorized_fingerprints,omitempty"`
}

// TimeLockPolicy enforces legal/time-based unlocks.
type TimeLockPolicy struct {
	Mode            string    `json:"mode"`
	UnlockNotBefore time.Time `json:"unlock_not_before"`
	MinDelaySeconds int64     `json:"min_delay_seconds"`
	LegalCondition  string    `json:"legal_condition,omitempty"`
	EscrowSigners   []string  `json:"escrow_signers,omitempty"`
}

// ColdStoragePolicy handles offline sealing schedules.
type ColdStoragePolicy struct {
	Enabled      bool   `json:"enabled"`
	StorageClass string `json:"storage_class,omitempty"`
	Interval     string `json:"interval,omitempty"`
}

// TamperPolicy defines offline AI scanning parameters.
type TamperPolicy struct {
	Analyzer    string `json:"analyzer,omitempty"`
	Sensitivity string `json:"sensitivity,omitempty"`
	Offline     bool   `json:"offline"`
}

// EnvelopeIntegrity snapshots supply-chain hashes.
type EnvelopeIntegrity struct {
	PayloadHash      string        `json:"payload_hash"`
	LedgerRoot       string        `json:"ledger_root"`
	AuditRoot        string        `json:"audit_root"`
	TimeSeal         TimeSealProof `json:"time_seal"`
	LastLedgerUpdate time.Time     `json:"last_ledger_update"`
	LastTamperState  string        `json:"last_tamper_state,omitempty"`
	ColdStorageHash  string        `json:"cold_storage_hash,omitempty"`
}

// TimeSealProof documents the delayed-hash commitment.
type TimeSealProof struct {
	Hash         string    `json:"hash"`
	GeneratedAt  time.Time `json:"generated_at"`
	DelaySeconds int64     `json:"delay_seconds"`
	LegalBinding string    `json:"legal_binding,omitempty"`
}

// ColdStorageStatus tracks offline vault pushes.
type ColdStorageStatus struct {
	State           string    `json:"state"`
	LastArchivedAt  time.Time `json:"last_archived_at"`
	ArchiveLocation string    `json:"archive_location,omitempty"`
	LastHash        string    `json:"last_hash,omitempty"`
}

// CustodyEvent forms the append-only chain-of-custody ledger.
type CustodyEvent struct {
	EventID          string            `json:"event_id"`
	Sequence         int               `json:"sequence"`
	Timestamp        time.Time         `json:"timestamp"`
	Actor            string            `json:"actor"`
	ActorFingerprint string            `json:"actor_fingerprint,omitempty"`
	Action           string            `json:"action"`
	Location         string            `json:"location,omitempty"`
	Notes            string            `json:"notes,omitempty"`
	EvidenceState    string            `json:"evidence_state,omitempty"`
	PrevHash         string            `json:"prev_hash"`
	EventHash        string            `json:"event_hash"`
	Attachments      map[string]string `json:"attachments,omitempty"`
}

// AuditEntry records administrative or access actions.
type AuditEntry struct {
	EntryID   string    `json:"entry_id"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Reason    string    `json:"reason,omitempty"`
	Signature string    `json:"signature,omitempty"`
	PrevHash  string    `json:"prev_hash"`
	EntryHash string    `json:"entry_hash"`
}

// TamperSignal captures offline AI verdicts.
type TamperSignal struct {
	ReportID        string    `json:"report_id"`
	Analyzer        string    `json:"analyzer"`
	AnalyzerVersion string    `json:"analyzer_version"`
	Score           float64   `json:"score"`
	Threshold       float64   `json:"threshold"`
	Offline         bool      `json:"offline"`
	GeneratedAt     time.Time `json:"generated_at"`
	Notes           []string  `json:"notes,omitempty"`
}

// TimeLockStatus reflects runtime unlock posture.
type TimeLockStatus struct {
	Active           bool      `json:"active"`
	UnlockNotBefore  time.Time `json:"unlock_not_before"`
	UnlockApprovedAt time.Time `json:"unlock_approved_at"`
	UnlockApprovedBy string    `json:"unlock_approved_by,omitempty"`
	UnlockReason     string    `json:"unlock_reason,omitempty"`
}

// EnvelopeRequest collects inputs for CreateEnvelope.
type EnvelopeRequest struct {
	Label                string            `json:"label"`
	Type                 EnvelopeType      `json:"type"`
	EvidenceClass        string            `json:"evidence_class"`
	CreatedBy            string            `json:"created_by"`
	CaseReference        string            `json:"case_reference"`
	FingerprintSignature string            `json:"fingerprint_signature"`
	IntakeLocation       string            `json:"intake_location"`
	Notes                string            `json:"notes"`
	Payload              EnvelopePayload   `json:"payload"`
	Policies             EnvelopePolicies  `json:"policies"`
	Tags                 map[string]string `json:"tags"`
}

// CreateEnvelope seals a payload inside an auditable envelope backed by JSON.
func (db *DB) CreateEnvelope(ctx context.Context, req *EnvelopeRequest) (*Envelope, error) {
	if req == nil {
		return nil, fmt.Errorf("envelope request is nil")
	}
	if req.Label == "" {
		return nil, fmt.Errorf("envelope label is required")
	}
	if req.Payload.Kind == "" {
		return nil, fmt.Errorf("envelope payload kind is required")
	}

	payloadHash := req.Payload.Digest()
	now := time.Now().UTC()
	env := &Envelope{
		EnvelopeID:           generateEnvelopeID(),
		Label:                req.Label,
		Type:                 req.Type,
		EvidenceClass:        req.EvidenceClass,
		Status:               "sealed",
		CreatedAt:            now,
		CreatedBy:            req.CreatedBy,
		LastUpdatedAt:        now,
		FingerprintSignature: req.FingerprintSignature,
		CaseReference:        req.CaseReference,
		Payload:              req.Payload,
		Policies:             req.Policies,
		Integrity: EnvelopeIntegrity{
			PayloadHash: payloadHash,
			TimeSeal:    buildTimeSeal(payloadHash, req.Policies.TimeLock),
		},
		CustodyLedger: []*CustodyEvent{},
		AuditLog:      []*AuditEntry{},
		ColdStorage:   ColdStorageStatus{State: coldStorageStateFromPolicy(req.Policies.ColdStorage)},
		TimeLockStatus: TimeLockStatus{
			Active:          req.Policies.TimeLock.isActive(now),
			UnlockNotBefore: req.Policies.TimeLock.UnlockNotBefore,
		},
		Tags:  req.Tags,
		Notes: req.Notes,
	}

	genesis := &CustodyEvent{
		Actor:            req.CreatedBy,
		ActorFingerprint: req.FingerprintSignature,
		Action:           "envelope.created",
		Location:         req.IntakeLocation,
		Notes:            req.Notes,
		EvidenceState:    "secured",
		Timestamp:        now,
	}
	env.appendCustodyEvent(genesis)
	env.recordAudit("envelope.init", req.CreatedBy, "envelope initialized", req.FingerprintSignature)

	if err := db.saveEnvelope(env); err != nil {
		return nil, err
	}
	return env, nil
}

// AppendCustodyEvent extends the chain-of-custody ledger and emits audit trails.
func (db *DB) AppendCustodyEvent(ctx context.Context, envelopeID string, event *CustodyEvent) (*Envelope, error) {
	if event == nil {
		return nil, fmt.Errorf("custody event is nil")
	}

	env, err := db.loadEnvelope(envelopeID)
	if err != nil {
		return nil, err
	}

	env.appendCustodyEvent(event)
	env.recordAudit("custody.update", event.Actor, event.Action, event.ActorFingerprint)
	if err := db.saveEnvelope(env); err != nil {
		return nil, err
	}
	return env, nil
}

// RecordTamperSignal stores offline AI verification outputs for an envelope.
func (db *DB) RecordTamperSignal(ctx context.Context, envelopeID string, signal *TamperSignal) (*Envelope, error) {
	if signal == nil {
		return nil, fmt.Errorf("tamper signal is nil")
	}

	env, err := db.loadEnvelope(envelopeID)
	if err != nil {
		return nil, err
	}

	if signal.ReportID == "" {
		signal.ReportID = generateEnvelopeAuditID()
	}
	if signal.GeneratedAt.IsZero() {
		signal.GeneratedAt = time.Now().UTC()
	}
	signal.Offline = true

	env.TamperSignals = append(env.TamperSignals, signal)
	env.Integrity.LastTamperState = fmt.Sprintf("%s:%0.4f", signal.Analyzer, signal.Score)
	env.recordAudit("tamper.analysis", signal.Analyzer, "offline tamper scan", "")

	if err := db.saveEnvelope(env); err != nil {
		return nil, err
	}
	return env, nil
}

// ApproveTimeLockUnlock releases a time-lock after legal checks.
func (db *DB) ApproveTimeLockUnlock(ctx context.Context, envelopeID, approver, reason string) (*Envelope, error) {
	env, err := db.loadEnvelope(envelopeID)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if env.TimeLockStatus.Active {
		policy := env.Policies.TimeLock
		if policy.UnlockNotBefore.After(now) {
			return nil, ErrTimeLockActive
		}
		if policy.MinDelaySeconds > 0 {
			readyAt := env.CreatedAt.Add(time.Duration(policy.MinDelaySeconds) * time.Second)
			if readyAt.After(now) {
				return nil, ErrTimeLockActive
			}
		}
		env.TimeLockStatus.Active = false
		env.TimeLockStatus.UnlockApprovedAt = now
		env.TimeLockStatus.UnlockApprovedBy = approver
		env.TimeLockStatus.UnlockReason = reason
		env.recordAudit("timelock.unlock", approver, reason, "")
		if err := db.saveEnvelope(env); err != nil {
			return nil, err
		}
	}
	return env, nil
}

// LoadEnvelope retrieves an envelope for reading (public method for recipients)
func (db *DB) LoadEnvelope(ctx context.Context, envelopeID string) (*Envelope, error) {
	return db.loadEnvelope(envelopeID)
}

// loadEnvelope fetches and unmarshals the JSON envelope.
func (db *DB) loadEnvelope(envelopeID string) (*Envelope, error) {
	if envelopeID == "" {
		return nil, fmt.Errorf("envelope id is required")
	}

	db.envelopeMu.RLock()
	defer db.envelopeMu.RUnlock()

	path := db.envelopePath(envelopeID)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrEnvelopeNotFound
		}
		return nil, err
	}

	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// saveEnvelope writes envelope state to disk atomically as JSON.
func (db *DB) saveEnvelope(env *Envelope) error {
	if env == nil {
		return fmt.Errorf("envelope is nil")
	}

	if db.envelopeDir == "" {
		return fmt.Errorf("envelope directory not configured")
	}

	env.LastUpdatedAt = time.Now().UTC()

	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(db.envelopeDir, "env-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	db.envelopeMu.Lock()
	defer db.envelopeMu.Unlock()

	finalPath := db.envelopePath(env.EnvelopeID)
	if err := os.Rename(tmpPath, finalPath); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// envelopePath returns the JSON filename for an envelope id.
func (db *DB) envelopePath(envelopeID string) string {
	return filepath.Join(db.envelopeDir, fmt.Sprintf("%s.json", envelopeID))
}

func (env *Envelope) appendCustodyEvent(event *CustodyEvent) {
	if event.EventID == "" {
		event.EventID = generateLedgerEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	} else {
		event.Timestamp = event.Timestamp.UTC()
	}

	prevHash := ""
	seq := 0
	if len(env.CustodyLedger) > 0 {
		prev := env.CustodyLedger[len(env.CustodyLedger)-1]
		prevHash = prev.EventHash
		seq = prev.Sequence + 1
	}
	event.Sequence = seq
	event.PrevHash = prevHash
	event.EventHash = hashCustodyEvent(event)
	env.CustodyLedger = append(env.CustodyLedger, event)
	env.Integrity.LedgerRoot = event.EventHash
	env.Integrity.LastLedgerUpdate = event.Timestamp
}

func (env *Envelope) recordAudit(action, actor, reason, signature string) {
	entry := &AuditEntry{
		EntryID:   generateEnvelopeAuditID(),
		Timestamp: time.Now().UTC(),
		Actor:     actor,
		Action:    action,
		Reason:    reason,
		Signature: signature,
	}
	if len(env.AuditLog) > 0 {
		entry.PrevHash = env.AuditLog[len(env.AuditLog)-1].EntryHash
	}
	entry.EntryHash = hashAuditEntry(entry)
	env.AuditLog = append(env.AuditLog, entry)
	env.Integrity.AuditRoot = entry.EntryHash
}

func hashCustodyEvent(event *CustodyEvent) string {
	h := sha256.New()
	h.Write([]byte(event.EventID))
	h.Write([]byte(event.Actor))
	h.Write([]byte(event.Action))
	h.Write([]byte(event.Location))
	h.Write([]byte(event.EvidenceState))
	h.Write([]byte(event.PrevHash))
	h.Write([]byte(event.Notes))
	if len(event.Attachments) > 0 {
		b, _ := json.Marshal(event.Attachments)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashAuditEntry(entry *AuditEntry) string {
	h := sha256.New()
	h.Write([]byte(entry.EntryID))
	h.Write([]byte(entry.Actor))
	h.Write([]byte(entry.Action))
	h.Write([]byte(entry.Reason))
	h.Write([]byte(entry.PrevHash))
	h.Write([]byte(entry.Signature))
	h.Write([]byte(entry.Timestamp.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(h.Sum(nil))
}

func buildTimeSeal(payloadHash string, policy TimeLockPolicy) TimeSealProof {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		copy(salt, []byte("velocity-time-lock"))
	}

	h := sha256.New()
	h.Write([]byte(payloadHash))
	h.Write(salt)
	h.Write([]byte(policy.LegalCondition))

	delay := policy.MinDelaySeconds
	if delay == 0 {
		delay = 3600 // default 1h sealing delay simulation
	}

	return TimeSealProof{
		Hash:         hex.EncodeToString(h.Sum(nil)),
		GeneratedAt:  time.Now().UTC(),
		DelaySeconds: delay,
		LegalBinding: policy.LegalCondition,
	}
}

func coldStorageStateFromPolicy(policy ColdStoragePolicy) string {
	if policy.Enabled {
		return "scheduled"
	}
	return "inactive"
}

func generateEnvelopeID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("env-%d", time.Now().UnixNano())
	}
	return "env-" + hex.EncodeToString(buf)
}

func generateLedgerEventID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("cst-%d", time.Now().UnixNano())
	}
	return "cst-" + hex.EncodeToString(buf)
}

func generateEnvelopeAuditID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("aud-%d", time.Now().UnixNano())
	}
	return "aud-" + hex.EncodeToString(buf)
}

func (p TimeLockPolicy) isActive(now time.Time) bool {
	if p.Mode == "" {
		return false
	}
	if p.UnlockNotBefore.IsZero() && p.MinDelaySeconds == 0 {
		return false
	}
	if !p.UnlockNotBefore.IsZero() {
		return now.Before(p.UnlockNotBefore)
	}
	return true
}

// ExportEnvelope exports an envelope to a portable JSON file that can be shared with recipients.
// The exported file contains the complete envelope with all custody events, audit logs, and integrity data.
func (db *DB) ExportEnvelope(ctx context.Context, envelopeID string, exportPath string) error {
	// Load the envelope
	envelope, err := db.LoadEnvelope(ctx, envelopeID)
	if err != nil {
		return fmt.Errorf("failed to load envelope: %w", err)
	}

	// Marshal to JSON with indentation for readability
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal envelope: %w", err)
	}

	// Create directory if needed
	if dir := filepath.Dir(exportPath); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create export directory: %w", err)
		}
	}

	// Write to file with restricted permissions
	if err := os.WriteFile(exportPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write envelope file: %w", err)
	}

	return nil
}

// ImportEnvelope imports an envelope from a JSON file into the database.
// This allows recipients to load envelopes that were exported and shared with them.
// The envelope is validated and stored in the local envelope directory.
func (db *DB) ImportEnvelope(ctx context.Context, importPath string) (*Envelope, error) {
	// Read the file
	data, err := os.ReadFile(importPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read envelope file: %w", err)
	}

	// Unmarshal the envelope
	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal envelope: %w", err)
	}

	// Validate envelope ID
	if envelope.EnvelopeID == "" {
		return nil, errors.New("invalid envelope: missing envelope_id")
	}

	// Check if envelope already exists
	envelopePath := filepath.Join(db.envelopeDir, envelope.EnvelopeID+".json")
	if _, err := os.Stat(envelopePath); err == nil {
		// Envelope already exists, load and return it
		return db.LoadEnvelope(ctx, envelope.EnvelopeID)
	}

	// Save to local envelope directory
	db.envelopeMu.Lock()
	defer db.envelopeMu.Unlock()

	if err := os.MkdirAll(db.envelopeDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create envelope directory: %w", err)
	}

	envelopeJSON, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal envelope: %w", err)
	}

	if err := os.WriteFile(envelopePath, envelopeJSON, 0600); err != nil {
		return nil, fmt.Errorf("failed to save envelope: %w", err)
	}

	return &envelope, nil
}
