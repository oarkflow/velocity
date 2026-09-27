package compliance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// Break-glass emergency access, ported from v1's break_glass.go. Kept in
// its own file and behind the separate api.BreakGlassService interface
// (see api/breakglass.go) rather than added to ComplianceService or
// plugin.go directly, so it doesn't collide with other in-flight edits to
// this plugin — it only adds new methods to the existing *Plugin type.

const defaultBreakGlassTTL = time.Hour

type breakGlassRecord struct {
	ID        string    `json:"id"`
	Requestor string    `json:"requestor"`
	Approver  string    `json:"approver"`
	Reason    string    `json:"reason"`
	Resource  string    `json:"resource"`
	GrantedAt time.Time `json:"granted_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
}

func breakGlassKey(id string) string { return "compliance/breakglass/" + id }

func newGrantID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// BreakGlassGrant approves an emergency-access request. Segregation of
// duties is enforced here, not left to the caller: a requestor cannot
// approve their own request. Both the grant and (via Record) an audit
// entry are always written together — there is no code path that grants
// access without also auditing it.
func (p *Plugin) BreakGlassGrant(ctx context.Context, req api.BreakGlassRequest, approver api.Principal) (api.BreakGlassGrant, error) {
	if p.storage == nil {
		return api.BreakGlassGrant{}, errNotInitialized
	}
	if req.Requestor == "" || req.Resource == "" {
		return api.BreakGlassGrant{}, fmt.Errorf("compliance: break-glass request requires Requestor and Resource")
	}
	if approver.Subject == "" {
		return api.BreakGlassGrant{}, fmt.Errorf("compliance: break-glass grant requires an approver")
	}
	if approver.Subject == req.Requestor {
		return api.BreakGlassGrant{}, fmt.Errorf("compliance: break-glass grant denied — approver %q cannot approve their own request (segregation of duties)", approver.Subject)
	}

	id, err := newGrantID()
	if err != nil {
		return api.BreakGlassGrant{}, fmt.Errorf("compliance: generating break-glass grant id: %w", err)
	}
	now := time.Now().UTC()
	rec := breakGlassRecord{
		ID:        id,
		Requestor: req.Requestor,
		Approver:  approver.Subject,
		Reason:    req.Reason,
		Resource:  req.Resource,
		GrantedAt: now,
		ExpiresAt: now.Add(defaultBreakGlassTTL),
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return api.BreakGlassGrant{}, fmt.Errorf("compliance: marshal break-glass grant: %w", err)
	}
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(breakGlassKey(id)), Value: data}); err != nil {
		return api.BreakGlassGrant{}, fmt.Errorf("compliance: persisting break-glass grant: %w", err)
	}

	if err := p.Record(ctx, api.AuditEvent{
		Timestamp: now,
		Actor:     approver.Subject,
		Action:    "breakglass.grant",
		Resource:  req.Resource,
		Detail: map[string]any{
			"grant_id":  id,
			"requestor": req.Requestor,
			"reason":    req.Reason,
			"expiresAt": rec.ExpiresAt,
		},
	}); err != nil {
		return api.BreakGlassGrant{}, fmt.Errorf("compliance: break-glass grant %q was persisted but auditing it failed, treating as a failure: %w", id, err)
	}

	return api.BreakGlassGrant{ID: id, ExpiresAt: rec.ExpiresAt}, nil
}

// BreakGlassRevoke revokes an outstanding grant before it naturally
// expires, auditing the revocation the same way BreakGlassGrant audits
// the grant itself.
func (p *Plugin) BreakGlassRevoke(ctx context.Context, grantID string) error {
	if p.storage == nil {
		return errNotInitialized
	}
	data, ok, err := p.storage.Get(ctx, []byte(breakGlassKey(grantID)))
	if err != nil {
		return fmt.Errorf("compliance: reading break-glass grant %q: %w", grantID, err)
	}
	if !ok {
		return fmt.Errorf("compliance: break-glass grant %q not found", grantID)
	}
	var rec breakGlassRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return fmt.Errorf("compliance: corrupt break-glass grant %q: %w", grantID, err)
	}
	if rec.Revoked {
		return fmt.Errorf("compliance: break-glass grant %q already revoked", grantID)
	}

	rec.Revoked = true
	rec.RevokedAt = time.Now().UTC()
	updated, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("compliance: marshal revoked break-glass grant: %w", err)
	}
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(breakGlassKey(grantID)), Value: updated}); err != nil {
		return fmt.Errorf("compliance: persisting break-glass revocation: %w", err)
	}

	return p.Record(ctx, api.AuditEvent{
		Timestamp: rec.RevokedAt,
		Actor:     rec.Approver,
		Action:    "breakglass.revoke",
		Resource:  rec.Resource,
		Detail:    map[string]any{"grant_id": grantID, "requestor": rec.Requestor},
	})
}

var _ api.BreakGlassService = (*Plugin)(nil)
