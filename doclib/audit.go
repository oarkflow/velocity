package doclib

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/oarkflow/velocity"
)

const (
	docAuditChainPrefix = "doc:audit:"
	docAuditGlobalKey   = "doclib:audit:global:"
)

// ── Action constants used across the package ─────────────────────────────────

const (
	ActionDocCreated         = "doc.created"
	ActionDocRead            = "doc.read"
	ActionDocContentAccessed = "doc.content.accessed"
	ActionDocUpdated         = "doc.updated"
	ActionDocDeleted         = "doc.deleted"
	ActionDocAccessDenied    = "doc.access.denied"
	ActionDocDispatched      = "doc.dispatched"

	ActionShareCreated      = "share.created"
	ActionShareApproved     = "share.approved"
	ActionShareRejected     = "share.rejected"
	ActionShareRevoked      = "share.revoked"
	ActionShareAutoApproved = "share.auto_approved"

	ActionLifecycleTransition = "lifecycle.transition"

	ActionDispatchAcknowledged = "dispatch.acknowledged"
	ActionDispatchRecalled     = "dispatch.recalled"

	OutcomeSuccess = "success"
	OutcomeDenied  = "denied"
	OutcomeFailed  = "failed"
)

// ── DocAccessEvent ────────────────────────────────────────────────────────────

// DocAccessEvent is a single, hash-linked entry in a document's access chain.
// All entries for a document form an append-only, tamper-evident log stored
// under the key doc:audit:{docID} in the Velocity KV store.
type DocAccessEvent struct {
	EventID   string            `json:"event_id"`
	DocID     string            `json:"doc_id"`
	Actor     string            `json:"actor"`
	ActorRole string            `json:"actor_role,omitempty"`
	Action    string            `json:"action"`
	Outcome   string            `json:"outcome"` // success | denied | failed
	IPAddress string            `json:"ip_address,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	Detail    string            `json:"detail,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	PrevHash  string            `json:"prev_hash"`
	EventHash string            `json:"event_hash"`
}

// ── AccessChainSummary ────────────────────────────────────────────────────────

// AccessChainSummary provides aggregate statistics over a document's access chain.
type AccessChainSummary struct {
	DocID          string         `json:"doc_id"`
	TotalEvents    int            `json:"total_events"`
	UniqueActors   int            `json:"unique_actors"`
	EventsByAction map[string]int `json:"events_by_action"`
	EventsByActor  map[string]int `json:"events_by_actor"`
	EventsByOutcome map[string]int `json:"events_by_outcome"`
	FirstEventAt   *time.Time     `json:"first_event_at,omitempty"`
	LastEventAt    *time.Time     `json:"last_event_at,omitempty"`
	ChainIntegrity string         `json:"chain_integrity"` // verified | tampered | empty
}

// ── AuditManager ─────────────────────────────────────────────────────────────

// AuditManager handles the per-document hash-linked access chain plus the
// global immutable AuditLogManager (Merkle-tree backed).
type AuditManager struct {
	db     *velocity.DB
	global *velocity.AuditLogManager
}

// NewAuditManager returns a wired AuditManager.
func NewAuditManager(db *velocity.DB) *AuditManager {
	return &AuditManager{
		db:     db,
		global: velocity.NewAuditLogManager(db),
	}
}

// Log records a DocAccessEvent in both:
//  1. The per-document hash-linked chain (doc:audit:{docID})
//  2. The global immutable Velocity AuditLogManager
func (m *AuditManager) Log(event DocAccessEvent) {
	if event.EventID == "" {
		event.EventID = uuid.NewString()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Per-document chain (non-fatal: best effort).
	_ = m.appendToDocChain(event)

	// Global immutable chain.
	_ = m.global.LogEvent(velocity.AuditEvent{
		Actor:      event.Actor,
		ActorRole:  event.ActorRole,
		Action:     event.Action,
		Resource:   "doclib:doc:" + event.DocID,
		ResourceID: event.DocID,
		Result:     event.Outcome,
		IPAddress:  event.IPAddress,
		Reason:     event.Detail,
		Timestamp:  event.Timestamp,
		Metadata: func() map[string]interface{} {
			m := make(map[string]interface{}, len(event.Metadata))
			for k, v := range event.Metadata {
				m[k] = v
			}
			return m
		}(),
	})
}

// GetChain returns the full access chain for docID.
// Callers must verify permission before calling this.
func (m *AuditManager) GetChain(docID string) ([]*DocAccessEvent, error) {
	return m.loadChain(docID)
}

// GetChainSummary returns aggregate statistics over the access chain.
func (m *AuditManager) GetChainSummary(docID string) (*AccessChainSummary, error) {
	chain, err := m.loadChain(docID)
	if err != nil {
		return nil, err
	}
	summary := &AccessChainSummary{
		DocID:           docID,
		TotalEvents:     len(chain),
		EventsByAction:  make(map[string]int),
		EventsByActor:   make(map[string]int),
		EventsByOutcome: make(map[string]int),
		ChainIntegrity:  "empty",
	}
	if len(chain) == 0 {
		return summary, nil
	}
	actors := make(map[string]struct{})
	for _, ev := range chain {
		actors[ev.Actor] = struct{}{}
		summary.EventsByAction[ev.Action]++
		summary.EventsByActor[ev.Actor]++
		summary.EventsByOutcome[ev.Outcome]++
	}
	summary.UniqueActors = len(actors)
	t0 := chain[0].Timestamp
	tN := chain[len(chain)-1].Timestamp
	summary.FirstEventAt = &t0
	summary.LastEventAt = &tN
	summary.ChainIntegrity = m.verifyChain(chain)
	return summary, nil
}

// GlobalAuditManager exposes the underlying velocity.AuditLogManager for
// forensic export and chain verification.
func (m *AuditManager) GlobalAuditManager() *velocity.AuditLogManager {
	return m.global
}

// ── internal ─────────────────────────────────────────────────────────────────

func (m *AuditManager) appendToDocChain(event DocAccessEvent) error {
	chain, _ := m.loadChain(event.DocID) // empty chain on first call is fine
	if len(chain) > 0 {
		event.PrevHash = chain[len(chain)-1].EventHash
	}
	event.EventHash = hashDocAccessEvent(event)
	chain = append(chain, &event)
	b, err := json.Marshal(chain)
	if err != nil {
		return err
	}
	return m.db.Put([]byte(docAuditChainPrefix+event.DocID), b)
}

func (m *AuditManager) loadChain(docID string) ([]*DocAccessEvent, error) {
	b, err := m.db.Get([]byte(docAuditChainPrefix + docID))
	if err != nil {
		return []*DocAccessEvent{}, nil
	}
	var chain []*DocAccessEvent
	if err := json.Unmarshal(b, &chain); err != nil {
		return nil, err
	}
	return chain, nil
}

// verifyChain walks the chain checking that every PrevHash links correctly
// and every EventHash matches the recomputed hash.
func (m *AuditManager) verifyChain(chain []*DocAccessEvent) string {
	if len(chain) == 0 {
		return "empty"
	}
	for i, ev := range chain {
		expected := hashDocAccessEvent(*ev)
		if expected != ev.EventHash {
			return fmt.Sprintf("tampered at event %d (hash mismatch)", i)
		}
		if i > 0 {
			if ev.PrevHash != chain[i-1].EventHash {
				return fmt.Sprintf("tampered at event %d (prev_hash mismatch)", i)
			}
		}
	}
	return "verified"
}

func hashDocAccessEvent(ev DocAccessEvent) string {
	h := sha256.New()
	h.Write([]byte(ev.EventID))
	h.Write([]byte(ev.DocID))
	h.Write([]byte(ev.Actor))
	h.Write([]byte(ev.Action))
	h.Write([]byte(ev.Outcome))
	h.Write([]byte(ev.Timestamp.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte(ev.PrevHash))
	h.Write([]byte(ev.Detail))
	if len(ev.Metadata) > 0 {
		b, _ := json.Marshal(ev.Metadata)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}
