package authz

import (
	"context"

	licclient "github.com/oarkflow/licensing-go"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

type DeniedBy string

const (
	DeniedByAuth        DeniedBy = "auth"
	DeniedByRBAC        DeniedBy = "rbac"
	DeniedByEntitlement DeniedBy = "entitlement"
	DeniedByACL         DeniedBy = "acl"
	DeniedByPolicy      DeniedBy = "policy"
	DeniedBySpec        DeniedBy = "spec"
)

type Request struct {
	Session        *types.Session
	ActorID        types.ID
	Operation      string
	RequiredScopes []types.Scope
	ResourceType   string
	ResourceID     string
	UsageContext   licclient.UsageContext
	Metadata       map[string]any
	AllowUnauth    bool
	RequireACL     bool
}

type Decision struct {
	Allowed          bool
	DeniedBy         DeniedBy
	MissingScopes    []types.Scope
	EntitlementScope string
	RestrictionHit   string
	ACLReason        string
	Reason           string
}

type EntitlementProvider interface {
	GetLicenseData(ctx context.Context, actorID types.ID) (*licclient.LicenseData, error)
}

type ACLChecker interface {
	Check(ctx context.Context, identityID types.ID, resourceID types.ID, requiredScopes []types.Scope) error
}

type PolicyChecker interface {
	Evaluate(ctx context.Context, actorID types.ID, resourceID types.ID, resourceType string, action string, metadata map[string]any) (allowed bool, reason string, err error)
}

type AuditLogger interface {
	Log(ctx context.Context, eventType, action string, actorID types.ID, success bool, details map[string]any)
}

// UsageCounter tracks entitlement usage for scoped/windowed limits.
type UsageCounter interface {
	Consume(ctx context.Context, scope string, subjectType licclient.SubjectType, subjectID string, amount int, windowSeconds int, limit int) error
}
