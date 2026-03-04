package automation

import (
	"context"
	"fmt"
	"strings"

	"github.com/oarkflow/velocity/internal/secretr/types"
)

// Default handlers for common automation tasks

// SecretCreateHandler creates a new secret
func SecretCreateHandler(secretSetter func(ctx context.Context, name, value string) error) StepHandler {
	return func(ctx context.Context, params map[string]string) error {
		name := params["name"]
		value := params["value"]
		if name == "" || value == "" {
			return fmt.Errorf("secret:create requires 'name' and 'value' parameters")
		}
		return secretSetter(ctx, name, value)
	}
}

// OrgAddMemberHandler adds a member to an organization
func OrgAddMemberHandler(memberAdder func(ctx context.Context, orgID, identityID types.ID, role string) error) StepHandler {
	return func(ctx context.Context, params map[string]string) error {
		orgID := params["org_id"]
		identityID := params["identity_id"]
		role := params["role"]
		if orgID == "" || identityID == "" || role == "" {
			return fmt.Errorf("org:add_member requires 'org_id', 'identity_id', and 'role' parameters")
		}
		return memberAdder(ctx, types.ID(orgID), types.ID(identityID), role)
	}
}

// AccessGrantHandler grants access to a resource
func AccessGrantHandler(accessGranter func(ctx context.Context, resourceID types.ID, resourceType string, identityID types.ID, scopes []types.Scope) error) StepHandler {
	return func(ctx context.Context, params map[string]string) error {
		resourceID := params["resource_id"]
		resourceType := params["resource_type"]
		identityID := params["identity_id"]
		scopesStr := params["scopes"]

		if resourceID == "" || resourceType == "" || identityID == "" || scopesStr == "" {
			return fmt.Errorf("access:grant requires 'resource_id', 'resource_type', 'identity_id', and 'scopes' parameters")
		}

		parts := strings.Split(scopesStr, ",")
		scopes := make([]types.Scope, len(parts))
		for i, p := range parts {
			scopes[i] = types.Scope(strings.TrimSpace(p))
		}

		return accessGranter(ctx, types.ID(resourceID), resourceType, types.ID(identityID), scopes)
	}
}
