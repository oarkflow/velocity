package authz

import (
	"context"
	"strings"

	"github.com/oarkflow/velocity/internal/secretr/core/policy"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

type PolicyAdapter struct {
	Engine *policy.Engine
}

func (p *PolicyAdapter) Evaluate(ctx context.Context, actorID types.ID, resourceID types.ID, resourceType string, action string, metadata map[string]any) (bool, string, error) {
	if p == nil || p.Engine == nil {
		return true, "", nil
	}
	if resourceID == "" {
		return true, "", nil
	}
	result, err := p.Engine.Evaluate(ctx, policy.EvaluationRequest{
		ActorID:      actorID,
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Action:       normalizePolicyAction(action),
		Context:      metadata,
	})
	if err != nil {
		return false, "policy evaluation failed", err
	}
	if result == nil || result.Allowed {
		return true, "", nil
	}
	if len(result.Violations) > 0 {
		return false, result.Violations[0].Reason, nil
	}
	return false, "denied by policy", nil
}

func normalizePolicyAction(action string) string {
	a := strings.TrimSpace(strings.ToLower(action))
	if a == "" {
		return "unknown"
	}
	if idx := strings.Index(a, ":flag:"); idx > 0 {
		a = a[:idx]
	}
	if idx := strings.Index(a, ":arg:"); idx > 0 {
		a = a[:idx]
	}
	if strings.HasPrefix(a, "cli:") || strings.HasPrefix(a, "api:") {
		return a
	}
	return a
}
