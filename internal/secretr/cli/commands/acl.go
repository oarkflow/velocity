package commands

import (
	"context"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/access"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// Access commands

func AccessGrant(ctx context.Context, cmd *cli.Command) error {
	granteeID := cmd.String("grantee")
	resourceID := cmd.String("resource")
	resourceType := cmd.String("type")
	scopeList := cmd.StringSlice("scopes")
	expiresIn := cmd.Duration("expires-in")
	resharing := cmd.Bool("resharing")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.RequireScope(types.ScopeAccessGrant); err != nil {
		return err
	}

	scopes := make([]types.Scope, len(scopeList))
	for i, s := range scopeList {
		scopes[i] = types.Scope(s)
	}

	grant, err := c.Access.Grant(ctx, access.GrantOptions{
		GrantorID:      c.CurrentIdentityID(),
		GranteeID:      types.ID(granteeID),
		ResourceID:     types.ID(resourceID),
		ResourceType:   resourceType,
		Scopes:         scopes,
		ExpiresIn:      expiresIn,
		AllowResharing: resharing,
	})
	if err != nil {
		return err
	}

	success("Access granted: %s", grant.ID)
	return nil
}

func AccessRevoke(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.RequireScope(types.ScopeAccessRevoke); err != nil {
		return err
	}

	if err := c.Access.Revoke(ctx, types.ID(id)); err != nil {
		return err
	}

	success("Access revoked: %s", id)
	return nil
}

func AccessCheck(ctx context.Context, cmd *cli.Command) error {
	identityID := cmd.String("identity")
	resourceID := cmd.String("resource")
	scopeList := cmd.StringSlice("scopes")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.RequireScope(types.ScopeAccessRead); err != nil { // Using Read for Check
		return err
	}

	scopes := make([]types.Scope, len(scopeList))
	for i, s := range scopeList {
		scopes[i] = types.Scope(s)
	}

	err = c.Access.Check(ctx, types.ID(identityID), types.ID(resourceID), scopes)
	if err != nil {
		return err
	}

	success("Access allowed")
	return nil
}

func AccessList(ctx context.Context, cmd *cli.Command) error {
	granteeID := cmd.String("grantee")
	resourceID := cmd.String("resource")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.RequireScope(types.ScopeAccessRead); err != nil { // Using Read for List
		return err
	}

	grants, err := c.Access.ListGrants(ctx, access.ListGrantsOptions{
		GranteeID:  types.ID(granteeID),
		ResourceID: types.ID(resourceID),
	})
	if err != nil {
		return err
	}

	return output(cmd, grants)
}

// Role commands

func RoleCreate(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	description := cmd.String("description")
	scopeList := cmd.StringSlice("scopes")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.RequireScope(types.ScopeRoleCreate); err != nil {
		return err
	}

	scopes := make([]types.Scope, len(scopeList))
	for i, s := range scopeList {
		scopes[i] = types.Scope(s)
	}

	role, err := c.Access.CreateRole(ctx, access.CreateRoleOptions{
		Name:        name,
		Description: description,
		Scopes:      scopes,
	})
	if err != nil {
		return err
	}

	success("Role created: %s", role.Name)
	return nil
}

func RoleList(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.RequireScope(types.ScopeRoleRead); err != nil {
		return err
	}

	roles, err := c.Access.ListRoles(ctx)
	if err != nil {
		return err
	}

	return output(cmd, roles)
}

func RoleAssign(ctx context.Context, cmd *cli.Command) error {
	roleID := cmd.String("role")
	identityID := cmd.String("identity")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.RequireScope(types.ScopeAccessGrant); err != nil {
		return err
	}

	// 1. Get Role to find its scopes
	role, err := c.Access.GetRole(ctx, types.ID(roleID))
	if err != nil {
		return err
	}

	// 2. Grant scopes to user (Global assignment by default if no resource specified)
	// Usually Role assignment is scoped to Org or Project.
	// For global role, we use empty resource or specific system resource.
	// We'll assume Global for now or use "*" string.
	// We'll use "*" as ResourceID for global roles.

	if _, err := c.Access.Grant(ctx, access.GrantOptions{
		GrantorID:    c.CurrentIdentityID(),
		GranteeID:    types.ID(identityID),
		ResourceID:   "*",
		ResourceType: "global",
		Scopes:       role.ScopeList,
	}); err != nil {
		return err
	}

	success("Role %s assigned to %s", role.Name, identityID)
	return nil
}
func AccessRequest(ctx context.Context, cmd *cli.Command) error {
	resourceID := cmd.String("resource")
	resourceType := cmd.String("type")
	justification := cmd.String("justification")
	duration := cmd.String("duration")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeAccessRequest); err != nil {
		return err
	}

	req, err := c.Access.CreateAccessRequest(ctx, access.CreateAccessRequestOptions{
		RequestorID:   c.CurrentIdentityID(),
		ResourceID:    types.ID(resourceID),
		ResourceType:  resourceType,
		Justification: justification,
		Duration:      duration,
	})
	if err != nil {
		return err
	}

	success("Access request created: %s", req.ID)
	return nil
}

func AccessApprove(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeAccessApprove); err != nil {
		return err
	}

	req, err := c.Access.ApproveAccessRequest(ctx, types.ID(id), c.CurrentIdentityID(), "Approved via CLI")
	if err != nil {
		return err
	}

	success("Access request approved: %s", req.ID)
	return nil
}
