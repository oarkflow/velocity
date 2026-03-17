package commands

import (
	"context"

	"github.com/urfave/cli/v3"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/cicd"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

// CICD Commands

func CICDCreatePipeline(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	provider := cmd.String("provider")
	repo := cmd.String("repo")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}

	pipeline, token, err := c.CICD.CreatePipelineIdentity(ctx, cicd.PipelineIdentityOptions{
		Name:           name,
		Provider:       types.PipelineProvider(provider),
		RepositoryID:   repo,
		OrgID:          orgID,
		CreatorID:      c.CurrentIdentityID(),
		SecretPatterns: cmd.StringSlice("secret-patterns"),
	})
	if err != nil {
		return err
	}

	success("Pipeline created: %s", pipeline.ID)
	info("Token (SAVE THIS): %s", token)
	return nil
}

func CICDInject(ctx context.Context, cmd *cli.Command) error {
	// This command is intended to be run BY the pipeline, or for testing
	// If run by user, simulates injection
	pipelineID := cmd.String("pipeline-id")
	env := cmd.String("env")
	branch := cmd.String("branch")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	injections, err := c.CICD.InjectSecrets(ctx, types.ID(pipelineID), env, branch)
	if err != nil {
		return err
	}

	// Output in requested format (e.g., env vars or JSON)
	return output(cmd, injections)
}
