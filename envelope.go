package velocity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type envelopeActorContextKey string
type envelopeAccessContextKey string

const envelopeActorKey envelopeActorContextKey = "velocity:envelope:actor"
const envelopeAccessKey envelopeAccessContextKey = "velocity:envelope:access"

const (
	envelopeSecureFileMagic = "VSEC1"
	envelopeSecureExtension = ".sec"
)

const (
	EnvelopeAuditCategoryCustody  = "custody"
	EnvelopeAuditCategoryAccess   = "access"
	EnvelopeAuditCategoryActivity = "activity"
)

const (
	EnvelopeAuditOutcomeSuccess = "success"
	EnvelopeAuditOutcomeDenied  = "denied"
)

// WithEnvelopeActor annotates context so envelope operations can auto-log actor identity.
func WithEnvelopeActor(ctx context.Context, actor string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, envelopeActorKey, actor)
}

func envelopeActorFromContext(ctx context.Context, fallback string) (string, bool) {
	if ctx != nil {
		if v, ok := ctx.Value(envelopeActorKey).(string); ok && v != "" {
			return v, true
		}
	}
	if fallback != "" {
		return fallback, true
	}
	return "", false
}

// EnvelopeAccessContext carries runtime information needed to enforce envelope access rules.
type EnvelopeAccessContext struct {
	APIEndpoint string `json:"api_endpoint,omitempty"`
	ClientIP    string `json:"client_ip,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	RecipientID string `json:"recipient_id,omitempty"`
	RequestID   string `json:"request_id,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
	TrustLevel  string `json:"trust_level,omitempty"`
	MFAVerified bool   `json:"mfa_verified"`
}

// WithEnvelopeAccessContext annotates context so envelope operations can enforce access rules.
func WithEnvelopeAccessContext(ctx context.Context, access EnvelopeAccessContext) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, envelopeAccessKey, access)
}

func envelopeAccessFromContext(ctx context.Context) EnvelopeAccessContext {
	if ctx != nil {
		if v, ok := ctx.Value(envelopeAccessKey).(EnvelopeAccessContext); ok {
			return v
		}
	}
	return EnvelopeAccessContext{}
}

var (
	ErrEnvelopeNotFound     = errors.New("envelope not found")
	ErrTimeLockActive       = errors.New("time-lock is still active")
	ErrEnvelopeAccessDenied = errors.New("envelope access denied")
)

// EnvelopeType describes evidence presets for the secure cabinet.
type EnvelopeType string

const (
	EnvelopeTypeCourtEvidence       EnvelopeType = "court_evidence"
	EnvelopeTypeInvestigationRecord EnvelopeType = "investigation_record"
	EnvelopeTypeCustodyProof        EnvelopeType = "custody_proof"
	EnvelopeTypeCCTVArchive         EnvelopeType = "cctv_forensic_archive"
)

// Envelope models a secure evidence wrapper persisted as an encrypted secure file.
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
	Kind            string            `json:"kind"` // file | kv | secret | bundle
	ObjectPath      string            `json:"object_path,omitempty"`
	ObjectVersion   string            `json:"object_version,omitempty"`
	InlineData      []byte            `json:"inline_data,omitempty"`
	Key             string            `json:"key,omitempty"`
	Value           json.RawMessage   `json:"value,omitempty"`
	SecretReference string            `json:"secret_reference,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	EncodingHint    string            `json:"encoding_hint,omitempty"`
	Resources      []EnvelopeResource `json:"resources,omitempty"`
}

// EnvelopeResource represents an individual resource within an envelope bundle.
type EnvelopeResource struct {
	ID          string            `json:"id"`
	Type       string            `json:"type"` // file | secret | kv
	Name       string            `json:"name"`
	Path       string            `json:"path,omitempty"`          // Object storage path for files
	Version    string            `json:"version,omitempty"`    // Object version for files
	SecretRef  string            `json:"secret_ref,omitempty"`  // Secret reference (e.g., "secret:category:name")
	Key        string            `json:"key,omitempty"`        // Key for KV type
	Value     json.RawMessage   `json:"value,omitempty"`     // Value for KV type
	Content   []byte            `json:"content,omitempty"`   // Inline content for files
	Metadata  map[string]string `json:"metadata,omitempty"`
	Encoding  string            `json:"encoding,omitempty"`  // base64, gzip, etc.
}

// EnvelopePayloadBundle groups multiple resources into a single envelope.
type EnvelopePayloadBundle struct {
	Resources     []EnvelopeResource `json:"resources"`
	BundleHash    string             `json:"bundle_hash"`
	ResourceCount int                `json:"resource_count"`
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
	h.Write([]byte(p.EncodingHint))
	if len(p.Value) > 0 {
		h.Write(p.Value)
	}
	if len(p.Metadata) > 0 {
		meta, _ := json.Marshal(p.Metadata)
		h.Write(meta)
	}
	for _, r := range p.Resources {
		h.Write([]byte(r.ID))
		h.Write([]byte(r.Type))
		h.Write([]byte(r.Name))
		h.Write([]byte(r.Path))
		h.Write([]byte(r.Version))
		h.Write([]byte(r.SecretRef))
		h.Write([]byte(r.Key))
		h.Write([]byte(r.Encoding))
		if len(r.Value) > 0 {
			h.Write(r.Value)
		}
		if len(r.Content) > 0 {
			h.Write(r.Content)
		}
		if len(r.Metadata) > 0 {
			meta, _ := json.Marshal(r.Metadata)
			h.Write(meta)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeBundleHash computes a SHA256 hash of all resources in the bundle.
func (b EnvelopePayloadBundle) ComputeBundleHash() string {
	h := sha256.New()
	for _, r := range b.Resources {
		h.Write([]byte(r.ID))
		h.Write([]byte(r.Type))
		h.Write([]byte(r.Name))
		h.Write([]byte(r.Path))
		h.Write([]byte(r.SecretRef))
		h.Write([]byte(r.Key))
		if len(r.Value) > 0 {
			h.Write(r.Value)
		}
		if len(r.Content) > 0 {
			h.Write(r.Content)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

const (
	ResourceTypeFile   = "file"
	ResourceTypeSecret = "secret"
	ResourceTypeKV     = "kv"
)

// ResolveResource resolves a single resource based on its type.
// For files, it fetches content from object storage.
// For secrets, it fetches from the secret store.
// For KV, it returns the value as-is.
func (db *DB) ResolveResource(resource EnvelopeResource) ([]byte, error) {
	switch resource.Type {
	case ResourceTypeFile:
		if resource.Path == "" {
			return nil, fmt.Errorf("resource %s: missing path for file type", resource.Name)
		}
		data, _, err := db.GetObject(resource.Path, "system")
		if err != nil {
			return nil, fmt.Errorf("resource %s: failed to get object: %w", resource.Name, err)
		}
		return data, nil

	case ResourceTypeSecret:
		if resource.SecretRef == "" {
			return nil, fmt.Errorf("resource %s: missing secret_ref for secret type", resource.Name)
		}
		data, err := db.Get([]byte(resource.SecretRef))
		if err != nil {
			return nil, fmt.Errorf("resource %s: failed to get secret: %w", resource.Name, err)
		}
		return data, nil

	case ResourceTypeKV:
		return resource.Value, nil

	default:
		return nil, fmt.Errorf("unknown resource type: %s", resource.Type)
	}
}

// ResolveResources resolves all resources in the envelope payload.
// Returns a map of resource ID to resolved content.
func (db *DB) ResolveResources(payload EnvelopePayload) (map[string][]byte, error) {
	result := make(map[string][]byte)

	for _, resource := range payload.Resources {
		data, err := db.ResolveResource(resource)
		if err != nil {
			return nil, err
		}
		result[resource.ID] = data
	}

	return result, nil
}

// ToEnvelopePayload converts a bundle to an EnvelopePayload with resolved content.
// The inline resource content is embedded for portability.
// This only works for resources that have inline content available.
func (b EnvelopePayloadBundle) ToEnvelopePayload() EnvelopePayload {
	resources := make([]EnvelopeResource, len(b.Resources))
	copy(resources, b.Resources)

	return EnvelopePayload{
		Kind:       "bundle",
		Resources:  resources,
		Metadata: map[string]string{
			"bundle_hash":    b.BundleHash,
			"resource_count": fmt.Sprintf("%d", b.ResourceCount),
		},
	}
}

// AddResource adds a resource to the bundle and updates the hash.
func (b *EnvelopePayloadBundle) AddResource(resource EnvelopeResource) {
	if resource.ID == "" {
		resource.ID = fmt.Sprintf("res-%d", len(b.Resources)+1)
	}
	b.Resources = append(b.Resources, resource)
	b.ResourceCount = len(b.Resources)
	b.BundleHash = b.ComputeBundleHash()
}

// EnvelopePolicies bundles access, storage, and tamper controls.
type EnvelopePolicies struct {
	Fingerprint FingerprintPolicy `json:"fingerprint"`
	TimeLock    TimeLockPolicy    `json:"time_lock"`
	Access      AccessPolicy      `json:"access"`
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

// AccessPolicy defines runtime access constraints that must be satisfied before envelope access.
type AccessPolicy struct {
	RequireAPIEndpoint  bool             `json:"require_api_endpoint,omitempty"`
	AllowedAPIEndpoints []string         `json:"allowed_api_endpoints,omitempty"`
	AllowedIPRanges     []string         `json:"allowed_ip_ranges,omitempty"`
	RequiredTrustLevel  string           `json:"required_trust_level,omitempty"`
	RequireMFA          bool             `json:"require_mfa,omitempty"`
	MaxAccessCount      int              `json:"max_access_count,omitempty"`
	CentralAPI          CentralAPIPolicy `json:"central_api,omitempty"`
}

// CentralAPIPolicy governs server-side authorization and audit forwarding.
type CentralAPIPolicy struct {
	Required             bool   `json:"required,omitempty"`
	CheckURL             string `json:"check_url,omitempty"`
	AuditLogURL          string `json:"audit_log_url,omitempty"`
	RequireAuditDelivery bool   `json:"require_audit_delivery,omitempty"`
	TimeoutSeconds       int    `json:"timeout_seconds,omitempty"`
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
	References       []string          `json:"references,omitempty"`
	Tags             map[string]string `json:"tags,omitempty"`
}

// AuditEntry records administrative or access actions.
type AuditEntry struct {
	EntryID        string            `json:"entry_id"`
	Timestamp      time.Time         `json:"timestamp"`
	Actor          string            `json:"actor"`
	Category       string            `json:"category,omitempty"`
	Action         string            `json:"action"`
	Outcome        string            `json:"outcome,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	Signature      string            `json:"signature,omitempty"`
	References     []string          `json:"references,omitempty"`
	RuleReferences []string          `json:"rule_references,omitempty"`
	Tags           map[string]string `json:"tags,omitempty"`
	PrevHash       string            `json:"prev_hash"`
	EntryHash      string            `json:"entry_hash"`
}

type envelopeAuditRecord struct {
	Category       string
	Action         string
	Actor          string
	Outcome        string
	Reason         string
	Signature      string
	References     []string
	RuleReferences []string
	Tags           map[string]string
}

type envelopeCentralAccessRequest struct {
	EnvelopeID    string            `json:"envelope_id"`
	Label         string            `json:"label,omitempty"`
	Action        string            `json:"action"`
	Actor         string            `json:"actor"`
	RecipientID   string            `json:"recipient_id,omitempty"`
	RequestID     string            `json:"request_id,omitempty"`
	SessionID     string            `json:"session_id,omitempty"`
	CaseReference string            `json:"case_reference,omitempty"`
	Fingerprint   string            `json:"fingerprint,omitempty"`
	ClientIP      string            `json:"client_ip,omitempty"`
	APIEndpoint   string            `json:"api_endpoint,omitempty"`
	TrustLevel    string            `json:"trust_level,omitempty"`
	MFAVerified   bool              `json:"mfa_verified"`
	Tags          map[string]string `json:"tags,omitempty"`
}

type envelopeCentralAccessResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

type envelopeAuditDeliveryRequest struct {
	EnvelopeID    string            `json:"envelope_id"`
	Action        string            `json:"action"`
	Category      string            `json:"category,omitempty"`
	Outcome       string            `json:"outcome,omitempty"`
	Actor         string            `json:"actor,omitempty"`
	RecipientID   string            `json:"recipient_id,omitempty"`
	RequestID     string            `json:"request_id,omitempty"`
	SessionID     string            `json:"session_id,omitempty"`
	CaseReference string            `json:"case_reference,omitempty"`
	Entry         *AuditEntry       `json:"entry"`
	Tags          map[string]string `json:"tags,omitempty"`
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

// CreateEnvelope seals a payload inside an auditable envelope backed by an encrypted secure file.
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
	if err := env.appendCustodyEventWithAudit(ctx, genesis); err != nil {
		return nil, err
	}
	if err := env.recordAudit(ctx, envelopeAuditRecord{
		Category:  EnvelopeAuditCategoryActivity,
		Action:    "envelope.init",
		Actor:     req.CreatedBy,
		Outcome:   EnvelopeAuditOutcomeSuccess,
		Reason:    "envelope initialized",
		Signature: req.FingerprintSignature,
		References: []string{
			"custody:event:" + genesis.EventID,
		},
	}); err != nil {
		return nil, err
	}

	if err := db.saveEnvelope(env); err != nil {
		return nil, err
	}
	return env, nil
}

// UpdateEnvelope saves changes to an existing envelope.
func (db *DB) UpdateEnvelope(ctx context.Context, env *Envelope) error {
	if env == nil {
		return fmt.Errorf("envelope is nil")
	}
	env.LastUpdatedAt = time.Now().UTC()
	if err := db.saveEnvelope(env); err != nil {
		return fmt.Errorf("failed to save envelope: %w", err)
	}
	return nil
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
	if err := db.enforceEnvelopeAccess(ctx, env, "custody.update"); err != nil {
		return nil, err
	}

	if err := env.appendCustodyEventWithAudit(ctx, event); err != nil {
		return nil, err
	}
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
	if err := db.enforceEnvelopeAccess(ctx, env, "tamper.analysis"); err != nil {
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
	if err := env.recordAudit(ctx, envelopeAuditRecord{
		Category: EnvelopeAuditCategoryActivity,
		Action:   "tamper.analysis",
		Actor:    signal.Analyzer,
		Outcome:  EnvelopeAuditOutcomeSuccess,
		Reason:   "offline tamper scan",
		References: []string{
			"tamper:report:" + signal.ReportID,
			"tamper:analyzer:" + signal.Analyzer,
		},
		RuleReferences: []string{"rule.tamper.offline_analysis"},
		Tags: map[string]string{
			"tamper.offline": fmt.Sprintf("%t", signal.Offline),
		},
	}); err != nil {
		return nil, err
	}

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
	if err := db.enforceEnvelopeAccess(ctx, env, "timelock.unlock"); err != nil {
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
		actor, _ := envelopeActorFromContext(ctx, approver)
		custodyEvent := &CustodyEvent{
			Actor:         actor,
			Action:        "timelock.unlock.approved",
			Location:      "policy-engine",
			EvidenceState: "unlock_approved",
			Notes:         reason,
			References: []string{
				"timelock:approver:" + approver,
			},
		}
		if err := env.appendCustodyEventWithAudit(ctx, custodyEvent); err != nil {
			return nil, err
		}
		if err := env.recordAudit(ctx, envelopeAuditRecord{
			Category: EnvelopeAuditCategoryActivity,
			Action:   "timelock.unlock",
			Actor:    actor,
			Outcome:  EnvelopeAuditOutcomeSuccess,
			Reason:   reason,
			References: []string{
				"custody:event:" + custodyEvent.EventID,
				"timelock:approver:" + approver,
			},
			RuleReferences: []string{"rule.timelock.release"},
		}); err != nil {
			return nil, err
		}
		if err := db.saveEnvelope(env); err != nil {
			return nil, err
		}
	}
	return env, nil
}

// LoadEnvelope retrieves an envelope for reading (public method for recipients)
func (db *DB) LoadEnvelope(ctx context.Context, envelopeID string) (*Envelope, error) {
	env, err := db.loadEnvelope(envelopeID)
	if err != nil {
		return nil, err
	}
	if err := db.enforceEnvelopeAccess(ctx, env, "envelope.load"); err != nil {
		return nil, err
	}

	actor, _ := envelopeActorFromContext(ctx, "unknown")
	access := envelopeAccessFromContext(ctx)
	custodyEvent := &CustodyEvent{
		Actor:            actor,
		ActorFingerprint: access.Fingerprint,
		Action:           "envelope.loaded",
		Location:         defaultEnvelopeLocation(access.APIEndpoint, "runtime"),
		EvidenceState:    "accessed",
		Notes:            "automatic access log",
		References: []string{
			"access:fingerprint:" + access.Fingerprint,
			"access:client_ip:" + access.ClientIP,
			"access:recipient_id:" + access.RecipientID,
			"access:request_id:" + access.RequestID,
			"access:session_id:" + access.SessionID,
		},
	}
	if err := env.appendCustodyEventWithAudit(ctx, custodyEvent); err != nil {
		return nil, err
	}
	if err := env.recordAudit(ctx, envelopeAuditRecord{
		Category:  EnvelopeAuditCategoryAccess,
		Action:    "envelope.load",
		Actor:     actor,
		Outcome:   EnvelopeAuditOutcomeSuccess,
		Reason:    "envelope loaded",
		Signature: access.Fingerprint,
		References: []string{
			"custody:event:" + custodyEvent.EventID,
			"access:api_endpoint:" + access.APIEndpoint,
			"access:client_ip:" + access.ClientIP,
			"access:fingerprint:" + access.Fingerprint,
			"access:recipient_id:" + access.RecipientID,
			"access:request_id:" + access.RequestID,
			"access:session_id:" + access.SessionID,
		},
		RuleReferences: []string{"rule.envelope.read"},
		Tags: map[string]string{
			"access.central_verified": fmt.Sprintf("%t", env.Policies.Access.CentralAPI.Required),
			"access.mfa_verified":     fmt.Sprintf("%t", access.MFAVerified),
			"access.trust_level":      access.TrustLevel,
		},
	}); err != nil {
		return nil, err
	}
	if err := db.saveEnvelope(env); err != nil {
		return nil, err
	}
	return env, nil
}

func (db *DB) enforceEnvelopeAccess(ctx context.Context, env *Envelope, action string) error {
	if env == nil {
		return fmt.Errorf("envelope is nil")
	}

	access := envelopeAccessFromContext(ctx)
	actor, _ := envelopeActorFromContext(ctx, "unknown")
	if reason := env.accessDeniedReason(action, access); reason != "" {
		if err := db.persistEnvelopeAccessDecision(ctx, env, action, actor, access, reason, []string{"rule.envelope.access_control"}); err != nil {
			return fmt.Errorf("%w: %s (failed to persist denial log: %v)", ErrEnvelopeAccessDenied, reason, err)
		}
		return fmt.Errorf("%w: %s", ErrEnvelopeAccessDenied, reason)
	}

	if reason, err := env.centralAccessDeniedReason(ctx, action, actor, access); err != nil {
		return err
	} else if reason != "" {
		if err := db.persistEnvelopeAccessDecision(ctx, env, action, actor, access, reason, []string{"rule.envelope.access_control", "rule.envelope.central_api"}); err != nil {
			return fmt.Errorf("%w: %s (failed to persist central denial log: %v)", ErrEnvelopeAccessDenied, reason, err)
		}
		return fmt.Errorf("%w: %s", ErrEnvelopeAccessDenied, reason)
	}
	return nil
}

func (db *DB) persistEnvelopeAccessDecision(ctx context.Context, env *Envelope, action, actor string, access EnvelopeAccessContext, reason string, extraRules []string) error {
	custodyEvent := &CustodyEvent{
		Actor:            actor,
		ActorFingerprint: access.Fingerprint,
		Action:           action + ".denied",
		Location:         defaultEnvelopeLocation(access.APIEndpoint, "policy-engine"),
		EvidenceState:    "access_denied",
		Notes:            reason,
		References: []string{
			"access:api_endpoint:" + access.APIEndpoint,
			"access:client_ip:" + access.ClientIP,
			"access:fingerprint:" + access.Fingerprint,
			"access:recipient_id:" + access.RecipientID,
			"access:request_id:" + access.RequestID,
			"access:session_id:" + access.SessionID,
		},
	}
	if err := env.appendCustodyEventWithAudit(ctx, custodyEvent); err != nil {
		return err
	}
	if err := env.recordAudit(ctx, envelopeAuditRecord{
		Category:  EnvelopeAuditCategoryAccess,
		Action:    action + ".denied",
		Actor:     actor,
		Outcome:   EnvelopeAuditOutcomeDenied,
		Reason:    reason,
		Signature: access.Fingerprint,
		References: []string{
			"custody:event:" + custodyEvent.EventID,
			"access:api_endpoint:" + access.APIEndpoint,
			"access:client_ip:" + access.ClientIP,
			"access:fingerprint:" + access.Fingerprint,
			"access:recipient_id:" + access.RecipientID,
			"access:request_id:" + access.RequestID,
			"access:session_id:" + access.SessionID,
		},
		RuleReferences: extraRules,
		Tags: map[string]string{
			"access.central_verified": fmt.Sprintf("%t", env.Policies.Access.CentralAPI.Required),
			"access.mfa_verified":     fmt.Sprintf("%t", access.MFAVerified),
			"access.trust_level":      access.TrustLevel,
		},
	}); err != nil {
		return err
	}
	return db.saveEnvelope(env)
}

func (env *Envelope) accessDeniedReason(action string, access EnvelopeAccessContext) string {
	if action == "envelope.load" {
		if env.TimeLockStatus.Active {
			return ErrTimeLockActive.Error()
		}

		if env.Policies.Fingerprint.Required {
			if access.Fingerprint == "" {
				return "fingerprint verification required"
			}
			if !containsString(env.Policies.Fingerprint.AuthorizedFingerprints, access.Fingerprint) {
				return "fingerprint not authorized"
			}
		}
	}

	policy := env.Policies.Access
	if action == "envelope.load" && policy.MaxAccessCount > 0 && env.accessCount("envelope.load") >= policy.MaxAccessCount {
		return "maximum envelope access count reached"
	}
	if policy.RequireMFA && !access.MFAVerified {
		return "MFA verification required"
	}
	if policy.RequiredTrustLevel != "" && !strings.EqualFold(policy.RequiredTrustLevel, access.TrustLevel) {
		return fmt.Sprintf("required trust level %q not met", policy.RequiredTrustLevel)
	}
	if (policy.RequireAPIEndpoint || len(policy.AllowedAPIEndpoints) > 0) && access.APIEndpoint == "" {
		return "api endpoint required"
	}
	if len(policy.AllowedAPIEndpoints) > 0 && !matchesAllowedAPIEndpoint(access.APIEndpoint, policy.AllowedAPIEndpoints) {
		return "api endpoint not allowed"
	}
	if len(policy.AllowedIPRanges) > 0 && !matchesAllowedIP(access.ClientIP, policy.AllowedIPRanges) {
		return "client IP not allowed"
	}

	return ""
}

func (env *Envelope) centralAccessDeniedReason(ctx context.Context, action, actor string, access EnvelopeAccessContext) (string, error) {
	policy := env.Policies.Access.CentralAPI
	if !policy.Required {
		return "", nil
	}

	checkURL := strings.TrimSpace(policy.CheckURL)
	if checkURL == "" {
		return "central api access check url is required", nil
	}

	payload := envelopeCentralAccessRequest{
		EnvelopeID:    env.EnvelopeID,
		Label:         env.Label,
		Action:        action,
		Actor:         actor,
		RecipientID:   access.RecipientID,
		RequestID:     access.RequestID,
		SessionID:     access.SessionID,
		CaseReference: env.CaseReference,
		Fingerprint:   access.Fingerprint,
		ClientIP:      access.ClientIP,
		APIEndpoint:   access.APIEndpoint,
		TrustLevel:    access.TrustLevel,
		MFAVerified:   access.MFAVerified,
		Tags:          env.auditBaseTags(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal central api access request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctxOrBackground(ctx), http.MethodPost, checkURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build central api access request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Envelope-ID", env.EnvelopeID)
	if access.RequestID != "" {
		req.Header.Set("X-Request-ID", access.RequestID)
	}

	resp, err := (&http.Client{Timeout: time.Duration(policy.timeoutSeconds()) * time.Second}).Do(req)
	if err != nil {
		return fmt.Sprintf("central api access check failed: %v", err), nil
	}
	defer resp.Body.Close()

	var decision envelopeCentralAccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil && err.Error() != "EOF" {
		return "", fmt.Errorf("decode central api access response: %w", err)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		if strings.TrimSpace(decision.Reason) != "" {
			return fmt.Sprintf("central api denied access: %s", decision.Reason), nil
		}
		return fmt.Sprintf("central api denied access with status %d", resp.StatusCode), nil
	}
	if !decision.Allowed {
		if strings.TrimSpace(decision.Reason) != "" {
			return decision.Reason, nil
		}
		return "central api denied access", nil
	}

	return "", nil
}

func (env *Envelope) accessCount(action string) int {
	count := 0
	for _, entry := range env.AuditLog {
		if entry != nil && entry.Action == action {
			count++
		}
	}
	return count
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func defaultEnvelopeLocation(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

func matchesAllowedAPIEndpoint(candidate string, allowed []string) bool {
	if candidate == "" {
		return false
	}

	candidateURL, err := url.Parse(candidate)
	if err != nil || candidateURL.Scheme == "" || candidateURL.Host == "" {
		return false
	}
	candidatePath := normalizedURLPath(candidateURL.Path)

	for _, rule := range allowed {
		ruleURL, err := url.Parse(rule)
		if err != nil || ruleURL.Scheme == "" || ruleURL.Host == "" {
			continue
		}
		if !strings.EqualFold(candidateURL.Scheme, ruleURL.Scheme) || !strings.EqualFold(candidateURL.Host, ruleURL.Host) {
			continue
		}
		if ruleURL.RawQuery != "" && candidateURL.RawQuery != ruleURL.RawQuery {
			continue
		}
		rulePath := normalizedURLPath(ruleURL.Path)
		if rulePath == "/" || candidatePath == rulePath || strings.HasPrefix(candidatePath+"/", rulePath+"/") {
			return true
		}
	}

	return false
}

func normalizedURLPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		return "/"
	}
	return path
}

func matchesAllowedIP(candidate string, allowed []string) bool {
	ip := net.ParseIP(strings.TrimSpace(candidate))
	if ip == nil {
		return false
	}

	for _, rule := range allowed {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		if allowedIP := net.ParseIP(rule); allowedIP != nil && allowedIP.Equal(ip) {
			return true
		}
		if _, ipNet, err := net.ParseCIDR(rule); err == nil && ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

// loadEnvelope fetches and unmarshals an encrypted envelope.
func (db *DB) loadEnvelope(envelopeID string) (*Envelope, error) {
	if envelopeID == "" {
		return nil, fmt.Errorf("envelope id is required")
	}

	var lastErr error
	for attempt := 0; attempt < 20; attempt++ {
		db.envelopeMu.RLock()
		data, err := os.ReadFile(db.envelopePath(envelopeID))
		db.envelopeMu.RUnlock()
		if err != nil {
			if os.IsNotExist(err) {
				return nil, ErrEnvelopeNotFound
			}
			lastErr = err
		} else {
			env, decodeErr := db.unmarshalEnvelopeFile(data, db.envelopeStorageAAD(envelopeID))
			if decodeErr == nil {
				return env, nil
			}
			lastErr = decodeErr
			if !isRetryableEnvelopeLoadError(decodeErr) {
				return nil, decodeErr
			}
		}
		time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
	}
	return nil, lastErr
}

// saveEnvelope writes envelope state to disk atomically as an encrypted secure file.
func (db *DB) saveEnvelope(env *Envelope) error {
	if env == nil {
		return fmt.Errorf("envelope is nil")
	}

	if db.envelopeDir == "" {
		return fmt.Errorf("envelope directory not configured")
	}

	env.LastUpdatedAt = time.Now().UTC()

	data, err := db.marshalEnvelopeFile(env, db.envelopeStorageAAD(env.EnvelopeID))
	if err != nil {
		return err
	}

	finalPath := db.envelopePath(env.EnvelopeID)
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

	if err := os.Rename(tmpPath, finalPath); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := syncDirectory(filepath.Dir(finalPath)); err != nil {
		return err
	}
	return nil
}

// envelopePath returns the secure filename for an envelope id.
func (db *DB) envelopePath(envelopeID string) string {
	return filepath.Join(db.envelopeDir, fmt.Sprintf("%s%s", envelopeID, envelopeSecureExtension))
}

func (db *DB) envelopeStorageAAD(envelopeID string) []byte {
	return []byte("velocity:envelope:storage:" + envelopeID)
}

func (db *DB) envelopeExportAAD() []byte {
	return []byte("velocity:envelope:export:v1")
}

func (db *DB) marshalEnvelopeFile(env *Envelope, aad []byte) ([]byte, error) {
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, err
	}
	return db.encryptEnvelopeBytes(data, aad)
}

func (db *DB) unmarshalEnvelopeFile(data, aad []byte) (*Envelope, error) {
	var lastErr error
	for attempt := 0; attempt < 20; attempt++ {
		plaintext, err := db.decryptEnvelopeBytes(data, aad)
		if err != nil {
			lastErr = err
			if !isRetryableEnvelopeLoadError(err) {
				return nil, err
			}
			time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
			continue
		}

		var env Envelope
		if err := json.Unmarshal(plaintext, &env); err != nil {
			return nil, err
		}
		return &env, nil
	}
	return nil, lastErr
}

func (db *DB) encryptEnvelopeBytes(plaintext, aad []byte) ([]byte, error) {
	if db.crypto == nil {
		return nil, fmt.Errorf("envelope encryption unavailable")
	}

	ciphertext, err := db.crypto.EncryptStream(plaintext, aad)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(envelopeSecureFileMagic)+len(ciphertext))
	copy(out, envelopeSecureFileMagic)
	copy(out[len(envelopeSecureFileMagic):], ciphertext)
	return out, nil
}

func (db *DB) decryptEnvelopeBytes(data, aad []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty envelope file")
	}

	if bytes.HasPrefix(trimmed, []byte(envelopeSecureFileMagic)) {
		if db.crypto == nil {
			return nil, fmt.Errorf("envelope decryption unavailable")
		}
		plaintext, err := db.crypto.DecryptStream(trimmed[len(envelopeSecureFileMagic):], aad)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt envelope: %w", err)
		}
		return plaintext, nil
	}

	return nil, fmt.Errorf("invalid envelope file format")
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
	event.References = compactSortedStrings(event.References)
	event.Tags = compactStringMap(event.Tags)

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

func (env *Envelope) appendCustodyEventWithAudit(ctx context.Context, event *CustodyEvent) error {
	env.appendCustodyEvent(event)
	return env.recordAudit(ctx, envelopeAuditRecord{
		Category:  EnvelopeAuditCategoryCustody,
		Action:    event.Action,
		Actor:     event.Actor,
		Outcome:   EnvelopeAuditOutcomeSuccess,
		Reason:    firstNonEmpty(strings.TrimSpace(event.Notes), event.Action),
		Signature: event.ActorFingerprint,
		References: append([]string{
			"custody:event:" + event.EventID,
			fmt.Sprintf("custody:sequence:%d", event.Sequence),
			"custody:state:" + event.EvidenceState,
			"custody:location:" + event.Location,
		}, event.References...),
		RuleReferences: []string{"rule.custody.append_only", "rule.audit.hash_chain"},
		Tags:           event.Tags,
	})
}

func (env *Envelope) recordAudit(ctx context.Context, record envelopeAuditRecord) error {
	category := strings.TrimSpace(record.Category)
	if category == "" {
		category = EnvelopeAuditCategoryActivity
	}
	outcome := strings.TrimSpace(record.Outcome)
	if outcome == "" {
		outcome = EnvelopeAuditOutcomeSuccess
	}
	entry := &AuditEntry{
		EntryID:        generateEnvelopeAuditID(),
		Timestamp:      time.Now().UTC(),
		Actor:          record.Actor,
		Category:       category,
		Action:         record.Action,
		Outcome:        outcome,
		Reason:         record.Reason,
		Signature:      record.Signature,
		References:     compactSortedStrings(append(env.auditBaseReferences(), record.References...)),
		RuleReferences: compactSortedStrings(append(env.auditPolicyReferences(), record.RuleReferences...)),
		Tags:           mergeStringMaps(env.auditBaseTags(), record.Tags),
	}
	if len(env.AuditLog) > 0 {
		entry.PrevHash = env.AuditLog[len(env.AuditLog)-1].EntryHash
	}
	entry.EntryHash = hashAuditEntry(entry)
	if err := env.deliverAuditEntry(ctx, entry); err != nil {
		return err
	}
	env.AuditLog = append(env.AuditLog, entry)
	env.Integrity.AuditRoot = entry.EntryHash
	return nil
}

func (env *Envelope) deliverAuditEntry(ctx context.Context, entry *AuditEntry) error {
	if env == nil || entry == nil {
		return nil
	}

	policy := env.Policies.Access.CentralAPI
	auditURL := strings.TrimSpace(policy.AuditLogURL)
	if auditURL == "" {
		return nil
	}

	access := envelopeAccessFromContext(ctx)
	payload := envelopeAuditDeliveryRequest{
		EnvelopeID:    env.EnvelopeID,
		Action:        entry.Action,
		Category:      entry.Category,
		Outcome:       entry.Outcome,
		Actor:         entry.Actor,
		RecipientID:   access.RecipientID,
		RequestID:     access.RequestID,
		SessionID:     access.SessionID,
		CaseReference: env.CaseReference,
		Entry:         entry,
		Tags:          entry.Tags,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		if policy.RequireAuditDelivery {
			return fmt.Errorf("marshal audit delivery payload: %w", err)
		}
		return nil
	}

	req, err := http.NewRequestWithContext(ctxOrBackground(ctx), http.MethodPost, auditURL, bytes.NewReader(body))
	if err != nil {
		if policy.RequireAuditDelivery {
			return fmt.Errorf("build audit delivery request: %w", err)
		}
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Envelope-ID", env.EnvelopeID)
	if access.RequestID != "" {
		req.Header.Set("X-Request-ID", access.RequestID)
	}

	resp, err := (&http.Client{Timeout: time.Duration(policy.timeoutSeconds()) * time.Second}).Do(req)
	if err != nil {
		if policy.RequireAuditDelivery {
			return fmt.Errorf("deliver audit entry: %w", err)
		}
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest && policy.RequireAuditDelivery {
		return fmt.Errorf("deliver audit entry: unexpected status %d", resp.StatusCode)
	}
	return nil
}

func hashCustodyEvent(event *CustodyEvent) string {
	h := sha256.New()
	h.Write([]byte(event.EventID))
	h.Write([]byte(fmt.Sprintf("%d", event.Sequence)))
	h.Write([]byte(event.Timestamp.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte(event.Actor))
	h.Write([]byte(event.ActorFingerprint))
	h.Write([]byte(event.Action))
	h.Write([]byte(event.Location))
	h.Write([]byte(event.EvidenceState))
	h.Write([]byte(event.PrevHash))
	h.Write([]byte(event.Notes))
	if len(event.Attachments) > 0 {
		b, _ := json.Marshal(event.Attachments)
		h.Write(b)
	}
	if len(event.References) > 0 {
		b, _ := json.Marshal(event.References)
		h.Write(b)
	}
	if len(event.Tags) > 0 {
		b, _ := json.Marshal(event.Tags)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashAuditEntry(entry *AuditEntry) string {
	h := sha256.New()
	h.Write([]byte(entry.EntryID))
	h.Write([]byte(entry.Actor))
	h.Write([]byte(entry.Category))
	h.Write([]byte(entry.Action))
	h.Write([]byte(entry.Outcome))
	h.Write([]byte(entry.Reason))
	h.Write([]byte(entry.PrevHash))
	h.Write([]byte(entry.Signature))
	if len(entry.References) > 0 {
		b, _ := json.Marshal(entry.References)
		h.Write(b)
	}
	if len(entry.RuleReferences) > 0 {
		b, _ := json.Marshal(entry.RuleReferences)
		h.Write(b)
	}
	if len(entry.Tags) > 0 {
		b, _ := json.Marshal(entry.Tags)
		h.Write(b)
	}
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

// ExportEnvelope exports an envelope to a portable encrypted secure file that can be shared with recipients.
// The exported file contains the complete envelope with all custody events, audit logs, and integrity data.
func (db *DB) ExportEnvelope(ctx context.Context, envelopeID string, exportPath string) error {
	// Load the envelope
	envelope, err := db.loadEnvelope(envelopeID)
	if err != nil {
		return fmt.Errorf("failed to load envelope: %w", err)
	}
	if err := db.enforceEnvelopeAccess(ctx, envelope, "envelope.export"); err != nil {
		return err
	}

	actor, _ := envelopeActorFromContext(ctx, "unknown")
	access := envelopeAccessFromContext(ctx)
	custodyEvent := &CustodyEvent{
		Actor:            actor,
		ActorFingerprint: access.Fingerprint,
		Action:           "envelope.exported",
		Location:         defaultEnvelopeLocation(access.APIEndpoint, "exporter"),
		EvidenceState:    "exported",
		Notes:            exportPath,
		References: []string{
			"export:path:" + exportPath,
		},
	}
	if err := envelope.appendCustodyEventWithAudit(ctx, custodyEvent); err != nil {
		return err
	}
	if err := envelope.recordAudit(ctx, envelopeAuditRecord{
		Category:  EnvelopeAuditCategoryAccess,
		Action:    "envelope.export",
		Actor:     actor,
		Outcome:   EnvelopeAuditOutcomeSuccess,
		Reason:    "export envelope",
		Signature: access.Fingerprint,
		References: []string{
			"custody:event:" + custodyEvent.EventID,
			"export:path:" + exportPath,
			"access:api_endpoint:" + access.APIEndpoint,
		},
		RuleReferences: []string{"rule.envelope.export"},
	}); err != nil {
		return err
	}
	if err := db.saveEnvelope(envelope); err != nil {
		return fmt.Errorf("failed to persist export audit trail: %w", err)
	}

	data, err := db.marshalEnvelopeFile(envelope, db.envelopeExportAAD())
	if err != nil {
		return fmt.Errorf("failed to serialize envelope: %w", err)
	}

	// Create directory if needed
	dir := filepath.Dir(exportPath)
	if dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create export directory: %w", err)
		}
	}

	tmp, err := os.CreateTemp(dir, "envelope-export-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create export temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write envelope file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to sync envelope file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to close envelope file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to set envelope file permissions: %w", err)
	}
	if err := os.Rename(tmpPath, exportPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to finalize envelope file: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("failed to sync export directory: %w", err)
	}

	return nil
}

// ImportEnvelope imports an envelope from an encrypted secure file into the database.
// This allows recipients to load envelopes that were exported and shared with them.
// The envelope is validated and stored in the local envelope directory.
func (db *DB) ImportEnvelope(ctx context.Context, importPath string) (*Envelope, error) {
	// Read the file
	data, err := os.ReadFile(importPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read envelope file: %w", err)
	}

	envelope, err := db.unmarshalEnvelopeFile(data, db.envelopeExportAAD())
	if err != nil {
		return nil, fmt.Errorf("failed to decode envelope: %w", err)
	}

	// Validate envelope ID
	if envelope.EnvelopeID == "" {
		return nil, errors.New("invalid envelope: missing envelope_id")
	}

	// Check if envelope already exists
	envelopePath := db.envelopePath(envelope.EnvelopeID)
	if _, err := os.Stat(envelopePath); err == nil {
		// Envelope already exists, load and return it
		return db.LoadEnvelope(ctx, envelope.EnvelopeID)
	}

	actor, _ := envelopeActorFromContext(ctx, "unknown")
	access := envelopeAccessFromContext(ctx)
	custodyEvent := &CustodyEvent{
		Actor:            actor,
		ActorFingerprint: access.Fingerprint,
		Action:           "envelope.imported",
		Location:         defaultEnvelopeLocation(access.APIEndpoint, "importer"),
		EvidenceState:    "imported",
		Notes:            importPath,
		References: []string{
			"import:path:" + importPath,
		},
	}
	if err := envelope.appendCustodyEventWithAudit(ctx, custodyEvent); err != nil {
		return nil, err
	}
	if err := envelope.recordAudit(ctx, envelopeAuditRecord{
		Category:  EnvelopeAuditCategoryActivity,
		Action:    "envelope.import",
		Actor:     actor,
		Outcome:   EnvelopeAuditOutcomeSuccess,
		Reason:    "import envelope",
		Signature: access.Fingerprint,
		References: []string{
			"custody:event:" + custodyEvent.EventID,
			"import:path:" + importPath,
			"access:api_endpoint:" + access.APIEndpoint,
		},
		RuleReferences: []string{"rule.envelope.import"},
	}); err != nil {
		return nil, err
	}

	if err := db.saveEnvelope(envelope); err != nil {
		return nil, fmt.Errorf("failed to save envelope: %w", err)
	}

	return envelope, nil
}

func (env *Envelope) auditBaseReferences() []string {
	if env == nil {
		return nil
	}

	refs := []string{
		"envelope:id:" + env.EnvelopeID,
		"envelope:type:" + string(env.Type),
		"payload:kind:" + env.Payload.Kind,
	}
	if env.CaseReference != "" {
		refs = append(refs, "case:"+env.CaseReference)
	}
	if env.Payload.ObjectPath != "" {
		refs = append(refs, "payload:object:"+env.Payload.ObjectPath)
	}
	if env.Payload.ObjectVersion != "" {
		refs = append(refs, "payload:object_version:"+env.Payload.ObjectVersion)
	}
	if env.Payload.Key != "" {
		refs = append(refs, "payload:key:"+env.Payload.Key)
	}
	if env.Payload.SecretReference != "" {
		refs = append(refs, "payload:secret:"+env.Payload.SecretReference)
	}
	for key, value := range env.Payload.Metadata {
		switch {
		case strings.HasPrefix(key, "dependency_"):
			refs = append(refs, "dependency:"+key+":"+value)
		case strings.Contains(key, "policy") || strings.Contains(key, "file") || strings.Contains(key, "secret"):
			refs = append(refs, "payload:metadata:"+key+":"+value)
		default:
			refs = append(refs, "payload:metadata_key:"+key)
		}
	}

	return compactSortedStrings(refs)
}

func (env *Envelope) auditPolicyReferences() []string {
	if env == nil {
		return nil
	}

	var refs []string
	if env.Policies.Fingerprint.Required {
		refs = append(refs, "policy.fingerprint.required")
	}
	if len(env.Policies.Fingerprint.AuthorizedFingerprints) > 0 {
		refs = append(refs, "policy.fingerprint.authorized")
	}
	if env.Policies.TimeLock.Mode != "" {
		refs = append(refs, "policy.timelock.mode")
	}
	if !env.Policies.TimeLock.UnlockNotBefore.IsZero() {
		refs = append(refs, "policy.timelock.unlock_not_before")
	}
	if env.Policies.TimeLock.MinDelaySeconds > 0 {
		refs = append(refs, "policy.timelock.min_delay")
	}
	if env.Policies.Access.RequireAPIEndpoint {
		refs = append(refs, "policy.access.require_api_endpoint")
	}
	if len(env.Policies.Access.AllowedAPIEndpoints) > 0 {
		refs = append(refs, "policy.access.allowed_api_endpoints")
	}
	if len(env.Policies.Access.AllowedIPRanges) > 0 {
		refs = append(refs, "policy.access.allowed_ip_ranges")
	}
	if env.Policies.Access.RequiredTrustLevel != "" {
		refs = append(refs, "policy.access.required_trust_level")
	}
	if env.Policies.Access.RequireMFA {
		refs = append(refs, "policy.access.require_mfa")
	}
	if env.Policies.Access.MaxAccessCount > 0 {
		refs = append(refs, "policy.access.max_access_count")
	}
	if env.Policies.Access.CentralAPI.Required {
		refs = append(refs, "policy.access.central_api_required")
	}
	if env.Policies.Access.CentralAPI.CheckURL != "" {
		refs = append(refs, "policy.access.central_api_check_url")
	}
	if env.Policies.Access.CentralAPI.AuditLogURL != "" {
		refs = append(refs, "policy.access.central_api_audit_log_url")
	}
	if env.Policies.Access.CentralAPI.RequireAuditDelivery {
		refs = append(refs, "policy.access.central_api_require_audit_delivery")
	}
	if env.Policies.ColdStorage.Enabled {
		refs = append(refs, "policy.cold_storage.enabled")
	}
	if env.Policies.Tamper.Analyzer != "" || env.Policies.Tamper.Offline {
		refs = append(refs, "policy.tamper.analysis")
	}

	return compactSortedStrings(refs)
}

func (env *Envelope) auditBaseTags() map[string]string {
	if env == nil {
		return nil
	}

	return mergeStringMaps(
		env.Tags,
		map[string]string{
			"system.envelope_id":          env.EnvelopeID,
			"system.envelope_type":        string(env.Type),
			"system.status":               env.Status,
			"system.case_reference":       env.CaseReference,
			"system.evidence_class":       env.EvidenceClass,
			"system.central_api_required": fmt.Sprintf("%t", env.Policies.Access.CentralAPI.Required),
		},
	)
}

func compactSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func compactStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}

	out := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mergeStringMaps(maps ...map[string]string) map[string]string {
	merged := make(map[string]string)
	for _, current := range maps {
		for key, value := range compactStringMap(current) {
			merged[key] = value
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func (p CentralAPIPolicy) timeoutSeconds() int {
	if p.TimeoutSeconds <= 0 {
		return 5
	}
	return p.TimeoutSeconds
}

func ctxOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func isRetryableEnvelopeLoadError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "message authentication failed") || strings.Contains(msg, "failed to decrypt envelope")
}

func syncDirectory(path string) error {
	if path == "" || path == "." {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
