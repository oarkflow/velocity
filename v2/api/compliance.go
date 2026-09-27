package api

import (
	"context"
	"time"
)

// AuditEvent is one immutable audit record.
type AuditEvent struct {
	Timestamp time.Time
	Actor     string
	Action    string
	Resource  string
	Detail    map[string]any
}

// AuditSink records audit events into a tamper-evident chain (ported from
// v1's audit_immutable.go hash-chain + Merkle tree) and lets that chain be
// independently verified.
type AuditSink interface {
	Record(ctx context.Context, ev AuditEvent) error
	VerifyChain(ctx context.Context) error
}

// PolicyDecision is the result of evaluating a PolicyEngine rule set.
type PolicyDecision struct {
	Allowed bool
	Reason  string
}

// PolicyEngine evaluates access/compliance rules against a classification
// label (e.g. "PII", "confidential") rather than a specific resource type,
// so it applies uniformly across KV/Object/Secret.
type PolicyEngine interface {
	Evaluate(ctx context.Context, subject Principal, action, resource, classification string) (PolicyDecision, error)
}

// ClassificationRecord is a resource's currently managed classification
// level (e.g. "public"/"internal"/"confidential"/"restricted"), ported
// from v1's data_classification.go as a managed taxonomy rather than a
// caller-supplied string on every call. v1's much larger PII/PHI/PCI
// regex auto-scanning engine (DataClassificationEngine) is NOT ported
// here — this is deliberately the simpler "set/get a classification for a
// resource" capability; auto-detection is a natural, larger follow-up.
type ClassificationRecord struct {
	Resource string
	Level    string
	SetAt    time.Time
}

// ResidencyRule restricts resources under ResourcePrefix to a single
// allowed Region, ported from v1's data_residency.go.
type ResidencyRule struct {
	ResourcePrefix string
	Region         string
}

// LineageEvent records one step in a resource's lifecycle (create/read/
// update/delete/move), ported from v1's data_lineage.go.
type LineageEvent struct {
	Resource string
	Action   string
	Source   string
	At       time.Time
}

// MaskStrategy selects how MaskWithStrategy rewrites a resource's stored
// value, ported from v1's data_masking.go DataMaskingEngine strategies.
type MaskStrategy string

const (
	MaskFull    MaskStrategy = "full"    // replace every character with '*'
	MaskPartial MaskStrategy = "partial" // mask all but the last 4 characters
	MaskRedact  MaskStrategy = "redact"  // replace the whole value with "[REDACTED]"
)

// Violation is a queryable record of a denied PolicyEngine.Evaluate call,
// ported from v1's violations.go — distinct from the PolicyDecision
// returned inline to the caller that triggered it, so violations remain
// visible/auditable after the fact instead of only at the call site.
type Violation struct {
	ID       string
	Rule     string
	Resource string
	Severity string
	At       time.Time
}

// ComplianceService is the surface plugins/compliance exposes. It
// subscribes to TopicKVPut/TopicObjectPut/etc. from the event bus rather
// than being called directly by KV/Object/Secret, so those plugins never
// need to know compliance exists.
//
// ApplyRetention/RecordConsent/Anonymize MUST return an error if their
// underlying manager isn't wired, rather than silently succeeding — this
// is the explicit fix for v1's gdpr_consent.go/gdpr_retention.go bug where
// a nil manager caused calls to silently no-op. The same rule applies to
// every method added below.
type ComplianceService interface {
	AuditSink
	PolicyEngine
	ApplyRetention(ctx context.Context, resource string) error
	RecordConsent(ctx context.Context, subject, purpose string, granted bool) error
	Anonymize(ctx context.Context, resource string) error

	// SetClassification/GetClassification manage the taxonomy described
	// on ClassificationRecord above, independent of the classification
	// string a caller happens to pass into PolicyEngine.Evaluate.
	SetClassification(ctx context.Context, resource, level string) error
	GetClassification(ctx context.Context, resource string) (ClassificationRecord, error)

	// SetResidencyRule/CheckResidency enforce ResidencyRule above.
	// CheckResidency returns (false, reason) rather than an error when a
	// rule is violated — that is an expected, common outcome callers
	// branch on, not an exceptional one.
	SetResidencyRule(ctx context.Context, rule ResidencyRule) error
	CheckResidency(ctx context.Context, resource, currentRegion string) (bool, string, error)

	// RecordLineage/GetLineage manage LineageEvent history for a
	// resource, returned in the order recorded.
	RecordLineage(ctx context.Context, ev LineageEvent) error
	GetLineage(ctx context.Context, resource string) ([]LineageEvent, error)

	// MaskWithStrategy is Anonymize's configurable sibling: Anonymize
	// always applies MaskFull, MaskWithStrategy lets a caller choose.
	MaskWithStrategy(ctx context.Context, resource string, strategy MaskStrategy) error

	// ImportRulePack adds rules (in the JSON schema documented on
	// plugins/compliance) to the same PolicyEngine.Evaluate rule set
	// loadRules builds by default — ported from v1's
	// policy_rule_packs.go, minus its GDPR/HIPAA/PCI named-pack presets,
	// which are a natural follow-up once real pack content is defined.
	ImportRulePack(ctx context.Context, packJSON []byte) error

	// ListViolations returns recorded Violations for resource (or every
	// violation if resource is "").
	ListViolations(ctx context.Context, resource string) ([]Violation, error)
}
