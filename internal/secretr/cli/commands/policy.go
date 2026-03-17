package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/core/policy"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v3"
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

	description := "Created via CLI"
	pType := types.PolicyTypeAccess
	var rules []types.PolicyRule
	if strings.TrimSpace(file) != "" {
		definition, err := loadPolicyDefinition(file)
		if err != nil {
			return err
		}
		if strings.TrimSpace(definition.Description) != "" {
			description = definition.Description
		}
		if definition.Type != "" {
			pType = definition.Type
		}
		rules = definition.Rules
	}

	policy, err := c.Policy.Create(ctx, policy.CreatePolicyOptions{
		Name:        name,
		Description: description,
		Type:        pType,
		Rules:       rules,
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

	resourceType = strings.TrimSpace(resourceType)
	if resourceType == "" {
		return fmt.Errorf("resource type is required")
	}
	allowedTypes := []string{
		"secret", "file", "folder", "object", "key", "identity", "org",
		"session", "device", "share", "policy", "audit", "access", "admin", "global",
	}
	if !slices.Contains(allowedTypes, resourceType) {
		return fmt.Errorf("invalid resource type %q", resourceType)
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

	if strings.TrimSpace(policyID) != "" {
		if _, err := c.Policy.Get(ctx, types.ID(policyID)); err != nil {
			return fmt.Errorf("policy not found: %s", policyID)
		}
	}

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
	if err := c.RequireScope(types.ScopePolicyFreeze); err != nil {
		return err
	}

	// Freeze policy engine
	c.Policy.Freeze()

	success("Policy lockdown mode enabled")
	return nil
}

func PolicyDryRunEnable(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	if err := c.RequireScope(types.ScopePolicyUpdate); err != nil {
		return err
	}
	c.Policy.EnableDryRun()
	success("Policy dry-run enabled")
	return nil
}

func PolicyDryRunDisable(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	if err := c.RequireScope(types.ScopePolicyUpdate); err != nil {
		return err
	}
	c.Policy.DisableDryRun()
	success("Policy dry-run disabled")
	return nil
}

func PolicyDryRunReport(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	if err := c.RequireScope(types.ScopePolicyRead); err != nil {
		return err
	}
	enabled := c.Policy.DryRunEnabled()
	events, qErr := c.Audit.Query(ctx, audit.QueryOptions{
		Action: "policy:dryrun_violation",
		Limit:  100,
	})
	if qErr != nil {
		events = nil
	}
	report := map[string]any{
		"enabled":                enabled,
		"dryrun_violation_count": len(events),
		"events":                 events,
	}
	return output(cmd, report)
}

type policyDefinition struct {
	Description string             `json:"description" yaml:"description"`
	Type        types.PolicyType   `json:"type" yaml:"type"`
	Rules       []types.PolicyRule `json:"rules" yaml:"rules"`
}

func loadPolicyDefinition(path string) (*policyDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}
	var def policyDefinition
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &def); err != nil {
			return nil, fmt.Errorf("failed to parse policy YAML: %w", err)
		}
	default:
		if err := json.Unmarshal(data, &def); err != nil {
			return nil, fmt.Errorf("failed to parse policy JSON: %w", err)
		}
	}
	return &def, nil
}
