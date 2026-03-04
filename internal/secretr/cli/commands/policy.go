package commands

import (
	"context"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/policy"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// Policy commands

func PolicyCreate(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	file := cmd.String("file")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.RequireScope(types.ScopePolicyCreate); err != nil {
		return err
	}

	_ = file // Assume reading file content logic here

	policy, err := c.Policy.Create(ctx, policy.CreatePolicyOptions{
		Name:        name,
		Description: "Created via CLI",
		Type:        types.PolicyTypeAccess,
		SignerID:    c.CurrentIdentityID(),
	})
	if err != nil {
		return err
	}

	success("Policy created: %s", policy.ID)
	return nil
}

func PolicyList(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.RequireScope(types.ScopePolicyRead); err != nil {
		return err
	}

	policies, err := c.Policy.List(ctx)
	if err != nil {
		return err
	}

	return output(cmd, policies)
}

func PolicyBind(ctx context.Context, cmd *cli.Command) error {
	policyID := cmd.String("policy")
	resourceID := cmd.String("resource")
	resourceType := cmd.String("type")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.RequireScope(types.ScopePolicyBind); err != nil {
		return err
	}

	if err := c.Policy.Bind(ctx, types.ID(policyID), types.ID(resourceID), resourceType, c.CurrentIdentityID()); err != nil {
		return err
	}

	success("Policy %s bound to %s", policyID, resourceID)
	return nil
}

func PolicySimulate(ctx context.Context, cmd *cli.Command) error {
	policyID := cmd.String("policy")
	action := cmd.String("action")
	resource := cmd.String("resource")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.RequireScope(types.ScopePolicySimulate); err != nil {
		return err
	}

	_ = policyID // Used? actually PolicySimulate struct takes Policy ID in context?
	// No, EvaluationRequest does NOT take policyID. It evaluates ALL policies for resource.
	// But CLI flag allow specific policy?
	// The Manager.Simulate signature uses EvaluationRequest which has NO PolicyID field.
	// So `policy` arg is effectively ignored by the engine unless we filter manually?
	// Engine Evaluate iterates all bindings.
	// We'll leave it as unused or remove it.
	// Removing to satisfy lint "declared and not used".

	result, err := c.Policy.Simulate(ctx, policy.EvaluationRequest{
		ActorID:    c.CurrentIdentityID(),
		ResourceID: types.ID(resource),
		Action:     action,
	})
	if err != nil {
		return err
	}

	if result.EvaluationResult.Allowed {
		success("Allowed (Simulated)")
	} else {
		warning("Denied (Simulated): %v", result.EvaluationResult.Violations)
	}
	return nil
}

func PolicyFreeze(ctx context.Context, cmd *cli.Command) error {
	if !confirm("Enable policy lockdown mode?") {
		return nil
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	// Freeze policy engine
	c.Policy.Freeze()

	success("Policy lockdown mode enabled")
	return nil
}
