// Package audit provides audit logging with hash-chained integrity.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

// Engine provides audit logging functionality
type Engine struct {
	mu          sync.RWMutex
	store       *storage.AuditStore
	ledger      *Ledger
	crypto      *crypto.Engine
	signerID    types.ID
	signerKey   []byte
	subscribers []func(*types.AuditEvent)
}

// EngineConfig configures the audit engine
type EngineConfig struct {
	Store               *storage.Store
	SignerID            types.ID
	SignerKey           []byte
	LedgerBlockInterval time.Duration
}

// NewEngine creates a new audit engine
func NewEngine(cfg EngineConfig) *Engine {
	ledger := NewLedger(LedgerConfig{
		Store:         cfg.Store,
		SignerKey:     cfg.SignerKey,
		BlockInterval: cfg.LedgerBlockInterval,
	})

	return &Engine{
		store:     storage.NewAuditStore(cfg.Store),
		ledger:    ledger,
		crypto:    crypto.NewEngine(""),
		signerID:  cfg.SignerID,
		signerKey: cfg.SignerKey,
	}
}

// GetChainProof gets the cryptographic proof of the ledger chain
func (e *Engine) GetChainProof(ctx context.Context) (*ChainProof, error) {
	if e.ledger == nil {
		return nil, nil
	}
	return e.ledger.ExportChainProof(ctx)
}

// Start starts the background processes
func (e *Engine) Start(ctx context.Context) {
	if e.ledger != nil {
		e.ledger.StartBlockProducer(ctx)
	}
}

// Log logs an audit event
func (e *Engine) Log(ctx context.Context, event AuditEventInput) error {
	id, err := e.crypto.GenerateRandomID()
	if err != nil {
		return err
	}

	auditEvent := &types.AuditEvent{
		ID:           id,
		Type:         event.Type,
		Action:       event.Action,
		ActorID:      event.ActorID,
		ActorType:    event.ActorType,
		ResourceID:   event.ResourceID,
		ResourceType: event.ResourceType,
		SessionID:    event.SessionID,
		DeviceID:     event.DeviceID,
		Timestamp:    types.Now(),
		Success:      event.Success,
		Details:      event.Details,
		IPAddress:    event.IPAddress,
		UserAgent:    event.UserAgent,
	}

	// Sign if key available
	if len(e.signerKey) > 0 {
		eventData, _ := json.Marshal(auditEvent)
		sig, _ := e.crypto.Sign(e.signerKey, eventData)
		auditEvent.Signature = sig
	}

	if err := e.store.Append(ctx, auditEvent); err != nil {
		return err
	}

	// Add to ledger for anchoring
	if e.ledger != nil {
		e.ledger.AddEvent(id)
	}

	// Notify subscribers
	e.mu.RLock()
	subs := e.subscribers
	e.mu.RUnlock()

	for _, sub := range subs {
		go sub(auditEvent)
	}

	return nil
}

// Subscribe adds a subscriber for audit events
func (e *Engine) Subscribe(sub func(*types.AuditEvent)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.subscribers = append(e.subscribers, sub)
}

// AuditEventInput represents input for logging an audit event
type AuditEventInput struct {
	Type         string
	Action       string
	ActorID      types.ID
	ActorType    string
	ResourceID   *types.ID
	ResourceType string
	SessionID    *types.ID
	DeviceID     *types.ID
	Success      bool
	Details      types.Metadata
	IPAddress    string
	UserAgent    string
}

// Query queries audit events
func (e *Engine) Query(ctx context.Context, opts QueryOptions) ([]*types.AuditEvent, error) {
	return e.store.Query(ctx, storage.AuditQueryOptions{
		ActorID:    opts.ActorID,
		ResourceID: opts.ResourceID,
		Action:     opts.Action,
		StartTime:  opts.StartTime.UnixNano(),
		EndTime:    opts.EndTime.UnixNano(),
		Limit:      opts.Limit,
	})
}

// QueryOptions defines query parameters
type QueryOptions struct {
	ActorID    types.ID
	ResourceID types.ID
	Action     string
	StartTime  time.Time
	EndTime    time.Time
	Limit      int
}

// VerifyIntegrity verifies the audit chain integrity
func (e *Engine) VerifyIntegrity(ctx context.Context) (bool, error) {
	return e.store.VerifyChain(ctx)
}

// VerifyLedgerIntegrity verifies the ledger block chain integrity
func (e *Engine) VerifyLedgerIntegrity(ctx context.Context) (bool, error) {
	if e.ledger == nil {
		return false, nil
	}
	res, err := e.ledger.VerifyChain(ctx)
	if err != nil {
		return false, err
	}
	return res.Valid, nil
}

// Export exports signed audit events
func (e *Engine) Export(ctx context.Context, opts ExportOptions) ([]byte, error) {
	events, err := e.Query(ctx, QueryOptions{
		StartTime: opts.StartTime,
		EndTime:   opts.EndTime,
		Limit:     opts.Limit,
	})
	if err != nil {
		return nil, err
	}

	export := AuditExport{
		Events:     events,
		ExportedAt: time.Now(),
		ExportedBy: opts.ExporterID,
	}

	data, err := json.Marshal(export)
	if err != nil {
		return nil, err
	}

	// Sign export
	if len(e.signerKey) > 0 {
		export.Signature, _ = e.crypto.Sign(e.signerKey, data)
	}

	return json.Marshal(export)
}

// ExportOptions defines export parameters
type ExportOptions struct {
	StartTime  time.Time
	EndTime    time.Time
	Limit      int
	ExporterID types.ID
}

// AuditExport represents an exported audit package
type AuditExport struct {
	Events     []*types.AuditEvent `json:"events"`
	ExportedAt time.Time           `json:"exported_at"`
	ExportedBy types.ID            `json:"exported_by"`
	Signature  []byte              `json:"signature,omitempty"`
}

// VerifyExport verifies an exported audit package
func (e *Engine) VerifyExport(export *AuditExport, signerPubKey []byte) error {
	data, _ := json.Marshal(AuditExport{
		Events:     export.Events,
		ExportedAt: export.ExportedAt,
		ExportedBy: export.ExportedBy,
	})
	return e.crypto.Verify(signerPubKey, data, export.Signature)
}

// LogSecretAccess logs secret access
func (e *Engine) LogSecretAccess(ctx context.Context, actorID types.ID, secretName string, action string, success bool) error {
	resourceID := types.ID(secretName)
	return e.Log(ctx, AuditEventInput{
		Type:         "secret",
		Action:       action,
		ActorID:      actorID,
		ActorType:    "identity",
		ResourceID:   &resourceID,
		ResourceType: "secret",
		Success:      success,
	})
}

// LogKeyOperation logs key operations
func (e *Engine) LogKeyOperation(ctx context.Context, actorID types.ID, keyID types.ID, action string, success bool) error {
	return e.Log(ctx, AuditEventInput{
		Type:         "key",
		Action:       action,
		ActorID:      actorID,
		ActorType:    "identity",
		ResourceID:   &keyID,
		ResourceType: "key",
		Success:      success,
	})
}

// LogAuthEvent logs authentication events
func (e *Engine) LogAuthEvent(ctx context.Context, actorID types.ID, action string, success bool, details types.Metadata) error {
	return e.Log(ctx, AuditEventInput{
		Type:      "auth",
		Action:    action,
		ActorID:   actorID,
		ActorType: "identity",
		Success:   success,
		Details:   details,
	})
}

// LogPolicyViolation logs policy violations
func (e *Engine) LogPolicyViolation(ctx context.Context, actorID types.ID, policyID types.ID, action string, details types.Metadata) error {
	return e.Log(ctx, AuditEventInput{
		Type:         "policy",
		Action:       fmt.Sprintf("violation:%s", action),
		ActorID:      actorID,
		ActorType:    "identity",
		ResourceID:   &policyID,
		ResourceType: "policy",
		Success:      false,
		Details:      details,
	})
}

// Close cleans up resources
func (e *Engine) Close() error {
	return e.crypto.Close()
}
