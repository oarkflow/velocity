package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	licclient "github.com/oarkflow/licensing-go"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

type Authorizer struct {
	entitlements EntitlementProvider
	acl          ACLChecker
	policy       PolicyChecker
	audit        AuditLogger
	counter      UsageCounter
}

func NewAuthorizer(entitlements EntitlementProvider, acl ACLChecker, audit AuditLogger) *Authorizer {
	return &Authorizer{
		entitlements: entitlements,
		acl:          acl,
		audit:        audit,
		counter:      NewMemoryUsageCounter(),
	}
}

func NewAuthorizerWithCounter(entitlements EntitlementProvider, acl ACLChecker, audit AuditLogger, counter UsageCounter) *Authorizer {
	a := NewAuthorizer(entitlements, acl, audit)
	if counter != nil {
		a.counter = counter
	}
	return a
}

func (a *Authorizer) SetPolicyChecker(policyChecker PolicyChecker) {
	a.policy = policyChecker
}

func (a *Authorizer) AuditSpecDenied(ctx context.Context, req Request, reason string) {
	dec := Decision{
		Allowed:  false,
		DeniedBy: DeniedBySpec,
		Reason:   reason,
	}
	a.log(ctx, req, dec)
}

func (a *Authorizer) Authorize(ctx context.Context, req Request) (Decision, error) {
	dec := Decision{Allowed: false}

	if req.Session == nil || !req.Session.IsActive() {
		if !req.AllowUnauth {
			dec.DeniedBy = DeniedByAuth
			dec.Reason = "no active session"
			a.log(ctx, req, dec)
			return dec, types.NewError(types.ErrCodeUnauthorized, "No active session")
		}
	}

	if req.Session != nil {
		missing := make([]types.Scope, 0)
		for _, scope := range req.RequiredScopes {
			if !req.Session.Scopes.Has(scope) {
				missing = append(missing, scope)
			}
		}
		if len(missing) > 0 {
			dec.DeniedBy = DeniedByRBAC
			dec.MissingScopes = missing
			dec.Reason = "missing required scopes"
			a.log(ctx, req, dec)
			return dec, types.NewError(types.ErrCodeScopeRequired, "Missing required scopes", types.Metadata{"missing_scopes": missing})
		}
	}

	if err := a.checkEntitlements(ctx, req); err != nil {
		dec.DeniedBy = DeniedByEntitlement
		dec.Reason = err.Error()
		dec.EntitlementScope = firstScope(req.RequiredScopes)
		a.log(ctx, req, dec)
		var te *types.Error
		if errors.As(err, &te) {
			return dec, te
		}
		return dec, types.NewError(types.ErrCodeEntitlementDenied, err.Error())
	}

	if req.RequireACL {
		if req.ResourceID == "" {
			dec.DeniedBy = DeniedByACL
			dec.Reason = "resource id required for ACL evaluation"
			a.log(ctx, req, dec)
			return dec, types.NewError(types.ErrCodeACLDenied, "resource id required for ACL evaluation")
		}

		actorID := req.ActorID
		if actorID == "" && req.Session != nil {
			actorID = req.Session.IdentityID
		}
		aclCtx := enrichACLContext(ctx, req)
		if a.acl == nil {
			dec.DeniedBy = DeniedByACL
			dec.Reason = "acl checker not configured"
			a.log(ctx, req, dec)
			return dec, types.NewError(types.ErrCodeACLDenied, "ACL checker not configured")
		}
		if err := a.acl.Check(aclCtx, actorID, types.ID(req.ResourceID), req.RequiredScopes); err != nil {
			dec.DeniedBy = DeniedByACL
			dec.ACLReason = err.Error()
			dec.Reason = "acl denied"
			a.log(ctx, req, dec)
			return dec, types.NewError(types.ErrCodeACLDenied, "ACL denied", types.Metadata{"reason": err.Error()})
		}
	}
	if req.ResourceID != "" && a.policy != nil {
		actorID := req.ActorID
		if actorID == "" && req.Session != nil {
			actorID = req.Session.IdentityID
		}
		action := req.Operation
		if len(req.RequiredScopes) > 0 {
			action = string(req.RequiredScopes[0])
		}
		allowed, reason, err := a.policy.Evaluate(ctx, actorID, types.ID(req.ResourceID), req.ResourceType, action, req.Metadata)
		if err != nil {
			dec.DeniedBy = DeniedByPolicy
			dec.Reason = err.Error()
			a.log(ctx, req, dec)
			return dec, types.NewError(types.ErrCodePolicy, "policy evaluation failed", types.Metadata{"reason": err.Error()})
		}
		if !allowed {
			if reason == "" {
				reason = "denied by policy"
			}
			dec.DeniedBy = DeniedByPolicy
			dec.Reason = reason
			a.log(ctx, req, dec)
			return dec, types.NewError(types.ErrCodePolicy, reason)
		}
	}

	dec.Allowed = true
	a.log(ctx, req, dec)
	return dec, nil
}

func (a *Authorizer) checkEntitlements(ctx context.Context, req Request) error {
	if len(req.RequiredScopes) == 0 {
		return nil
	}

	if req.UsageContext.Amount <= 0 {
		req.UsageContext.Amount = 1
	}

	if a.entitlements == nil {
		return types.NewError(types.ErrCodeEntitlementScopeRequired, "entitlement scope required: no entitlement provider configured")
	}
	lic, err := a.entitlements.GetLicenseData(ctx, req.ActorID)
	if err != nil {
		return types.NewError(types.ErrCodeEntitlementDenied, fmt.Sprintf("entitlement lookup failed: %v", err))
	}
	if lic == nil {
		return types.NewError(types.ErrCodeEntitlementScopeRequired, "entitlement scope required: license missing")
	}
	if lic.IsRevoked {
		return types.NewError(types.ErrCodeEntitlementDenied, "entitlement denied: license revoked")
	}
	if !lic.ExpiresAt.IsZero() && time.Now().After(lic.ExpiresAt) {
		return types.NewError(types.ErrCodeEntitlementDenied, "entitlement denied: license expired")
	}

	for _, scope := range req.RequiredScopes {
		scopeSlug := string(scope)
		feature := featureFromScope(scopeSlug)

		sg, ok := getScopeGrant(lic, feature, scopeSlug)
		if !ok {
			return types.NewError(types.ErrCodeEntitlementScopeRequired, fmt.Sprintf("entitlement scope required: %s", scopeSlug))
		}
		if sg.Permission == licclient.ScopePermissionDeny {
			return types.NewError(types.ErrCodeEntitlementDenied, fmt.Sprintf("entitlement denied for scope: %s", scopeSlug))
		}

		if err := a.enforceScopeLimits(ctx, req, scopeSlug, sg); err != nil {
			return err
		}

		if ok, _, reason := lic.CanPerformWithContext(feature, scopeSlug, req.UsageContext); !ok {
			if reason == "" {
				reason = fmt.Sprintf("entitlement denied for scope: %s", scopeSlug)
			}
			reasonLower := strings.ToLower(reason)
			switch {
			case strings.Contains(reasonLower, "scope not granted"):
				return types.NewError(types.ErrCodeEntitlementScopeRequired, reason)
			case strings.Contains(reasonLower, "exceed"), strings.Contains(reasonLower, "limit"):
				return types.NewError(types.ErrCodeEntitlementLimitExceeded, reason)
			default:
				return types.NewError(types.ErrCodeEntitlementDenied, reason)
			}
		}
	}

	return nil
}

func (a *Authorizer) enforceScopeLimits(ctx context.Context, req Request, scopeSlug string, sg licclient.ScopeGrant) error {
	if a.counter == nil {
		return nil
	}

	baseSubjectType := req.UsageContext.SubjectType
	baseSubjectID := req.UsageContext.SubjectID
	if baseSubjectType == "" {
		baseSubjectType = licclient.SubjectTypeUser
	}
	if baseSubjectID == "" {
		baseSubjectID = string(req.ActorID)
	}

	if sg.Permission == licclient.ScopePermissionLimit && sg.Limit > 0 && len(sg.Restrictions) == 0 {
		if req.UsageContext.Amount > sg.Limit {
			return types.NewError(types.ErrCodeEntitlementLimitExceeded, fmt.Sprintf("entitlement limit exceeded for scope: %s", scopeSlug))
		}
		if err := a.counter.Consume(ctx, scopeSlug, baseSubjectType, baseSubjectID, req.UsageContext.Amount, 0, sg.Limit); err != nil {
			return types.NewError(types.ErrCodeEntitlementLimitExceeded, err.Error())
		}
	}

	for _, rr := range sg.Restrictions {
		if rr.Limit <= 0 {
			continue
		}
		subjectType, subjectID := restrictionSubject(req, rr.Type)
		if subjectID == "" {
			return types.NewError(types.ErrCodeEntitlementDenied, fmt.Sprintf("restriction subject missing for scope: %s", scopeSlug))
		}
		if err := a.counter.Consume(ctx, scopeSlug, subjectType, subjectID, req.UsageContext.Amount, rr.WindowSeconds, rr.Limit); err != nil {
			return types.NewError(types.ErrCodeEntitlementLimitExceeded, err.Error())
		}
	}

	return nil
}

func restrictionSubject(req Request, restrictionType licclient.UsageRestrictionType) (licclient.SubjectType, string) {
	switch restrictionType {
	case licclient.UsageRestrictionStorage:
		if req.UsageContext.SubjectType == licclient.SubjectTypeStorage && req.UsageContext.SubjectID != "" {
			return licclient.SubjectTypeStorage, req.UsageContext.SubjectID
		}
		if req.ResourceID != "" {
			return licclient.SubjectTypeStorage, req.ResourceID
		}
	case licclient.UsageRestrictionDevice:
		if req.UsageContext.SubjectType == licclient.SubjectTypeDevice && req.UsageContext.SubjectID != "" {
			return licclient.SubjectTypeDevice, req.UsageContext.SubjectID
		}
		if req.Session != nil && req.Session.DeviceID != "" {
			return licclient.SubjectTypeDevice, string(req.Session.DeviceID)
		}
	case licclient.UsageRestrictionUser:
		if req.UsageContext.SubjectType == licclient.SubjectTypeUser && req.UsageContext.SubjectID != "" {
			return licclient.SubjectTypeUser, req.UsageContext.SubjectID
		}
		if req.ActorID != "" {
			return licclient.SubjectTypeUser, string(req.ActorID)
		}
		if req.Session != nil && req.Session.IdentityID != "" {
			return licclient.SubjectTypeUser, string(req.Session.IdentityID)
		}
	}
	return licclient.SubjectTypeUser, ""
}

func featureFromScope(scope string) string {
	parts := strings.SplitN(scope, ":", 2)
	if len(parts) == 2 {
		return parts[0]
	}
	return scope
}

func firstScope(scopes []types.Scope) string {
	if len(scopes) == 0 {
		return ""
	}
	return string(scopes[0])
}

func getScopeGrant(lic *licclient.LicenseData, featureSlug, scopeSlug string) (licclient.ScopeGrant, bool) {
	if lic == nil || lic.Entitlements == nil || lic.Entitlements.Features == nil {
		return licclient.ScopeGrant{}, false
	}
	feature, ok := lic.Entitlements.Features[featureSlug]
	if !ok || !feature.Enabled || feature.Scopes == nil {
		return licclient.ScopeGrant{}, false
	}
	sg, ok := feature.Scopes[scopeSlug]
	if !ok {
		return licclient.ScopeGrant{}, false
	}
	return sg, true
}

func enrichACLContext(ctx context.Context, req Request) context.Context {
	out := ctx
	for _, k := range []string{"device_id", "client_ip", "mfa_verified", "access_approved"} {
		if v, ok := req.Metadata[k]; ok {
			out = context.WithValue(out, k, v)
		}
	}
	return out
}

func (a *Authorizer) log(ctx context.Context, req Request, dec Decision) {
	if a.audit == nil {
		return
	}
	actor := req.ActorID
	if actor == "" && req.Session != nil {
		actor = req.Session.IdentityID
	}
	a.audit.Log(ctx, "authz", req.Operation, actor, dec.Allowed, map[string]any{
		"denied_by":       dec.DeniedBy,
		"reason":          dec.Reason,
		"resource_type":   req.ResourceType,
		"resource_id":     req.ResourceID,
		"required_scopes": req.RequiredScopes,
	})
}
