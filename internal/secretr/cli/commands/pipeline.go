package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// PipelineApply applies a pipeline configuration from a JSON file
func PipelineApply(ctx context.Context, cmd *cli.Command) error {
	path := cmd.String("file")
	if path == "" {
		return fmt.Errorf("file path is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var pipeline types.AutomationPipeline
	if err := json.Unmarshal(data, &pipeline); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if pipeline.OrgID == "" {
		orgID, err := GetOrgID(ctx, cmd)
		if err == nil {
			pipeline.OrgID = orgID
		} else {
			// If we can't find an org, we'll let it fail later or default to current identity ID if really needed
			pipeline.OrgID = types.ID(c.CurrentIdentityID())
		}
	}

	if err := c.Automation.CreatePipeline(ctx, &pipeline); err != nil {
		return fmt.Errorf("failed to create pipeline: %w", err)
	}

	success("Pipeline applied: %s (%s)", pipeline.Name, pipeline.ID)
	return nil
}

// PipelineList lists all automation pipelines
func PipelineList(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}

	pipelines, err := c.Automation.ListPipelines(ctx, orgID)
	if err != nil {
		return err
	}

	fmt.Printf("\nAutomation Pipelines for Org: %s\n", orgID)
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("%-24s | %-20s | %-15s | %-10s\n", "ID", "Name", "Trigger", "Status")
	fmt.Println(strings.Repeat("-", 60))

	for _, p := range pipelines {
		fmt.Printf("%-24s | %-20s | %-15s | %-10s\n", p.ID, p.Name, p.Trigger, p.Status)
	}

	return nil
}

// PipelineTrigger triggers a pipeline by its event name
func PipelineTrigger(ctx context.Context, cmd *cli.Command) error {
	trigger := cmd.String("event")
	paramsList := cmd.StringSlice("param")

	params := make(map[string]string)
	for _, p := range paramsList {
		parts := strings.SplitN(p, "=", 2)
		if len(parts) == 2 {
			params[parts[0]] = parts[1]
		}
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.Automation.TriggerPipeline(ctx, trigger, params); err != nil {
		return err
	}

	success("Triggered automation for event: %s", trigger)
	return nil
}
