package api

import (
	"context"
	"time"
)

// BreakGlassRequest describes an emergency-access request: who wants
// access, why, and to what resource. Ported from v1's break_glass.go.
type BreakGlassRequest struct {
	Requestor string
	Reason    string
	Resource  string
}

// BreakGlassGrant is the result of an approved break-glass request: an
// opaque ID (used to revoke it later) and an expiry — break-glass access
// is always time-limited, never open-ended.
type BreakGlassGrant struct {
	ID        string
	ExpiresAt time.Time
}

// BreakGlassService is kept as its own interface rather than folded into
// ComplianceService, so a deployment that wants audited emergency-access
// workflows can add it without every ComplianceService implementer
// needing to grow these methods.
//
// Segregation-of-duties is enforced structurally, not left to caller
// discipline: BreakGlassGrant MUST reject a request where approver.Subject
// == req.Requestor (nobody can approve their own emergency access), and
// every grant/revoke MUST be recorded via AuditSink.Record — a break-glass
// path that isn't audited defeats the entire point of the feature.
type BreakGlassService interface {
	BreakGlassGrant(ctx context.Context, req BreakGlassRequest, approver Principal) (BreakGlassGrant, error)
	BreakGlassRevoke(ctx context.Context, grantID string) error
}
