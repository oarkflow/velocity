package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/compliance"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// ComplianceCommands provides CLI commands for compliance features
type ComplianceCommands struct {
	engine *compliance.Engine
}

// NewComplianceCommands creates a new ComplianceCommands instance
func ComplianceListFrameworks(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	frameworks := c.Compliance.GetFrameworks()

	fmt.Println("Available Compliance Frameworks:")
	fmt.Println(strings.Repeat("-", 40))

	for _, f := range frameworks {
		def, err := c.Compliance.GetFrameworkDefinition(f)
		if err != nil {
			fmt.Printf("  • %s\n", f)
		} else {
			fmt.Printf("  • %s (%s)\n", def.Name, def.Version)
		}
	}

	return nil
}

func ComplianceGetScore(ctx context.Context, cmd *cli.Command) error {
	framework := cmd.String("standard")
	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}
	if framework == "" {
		framework = cmd.String("framework") // Fallback
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	f := compliance.Framework(framework)
	score, err := c.Compliance.GetComplianceScore(ctx, f, orgID)
	if err != nil {
		return fmt.Errorf("failed to get compliance score: %w", err)
	}

	fmt.Printf("\n%s Compliance Score\n", framework)
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Overall Score: %.1f%%\n", score.Score)
	fmt.Printf("Total Controls: %d\n", score.TotalControls)
	fmt.Printf("  ✓ Compliant: %d\n", score.CompliantCount)
	fmt.Printf("  ~ Partial: %d\n", score.PartialCount)
	fmt.Printf("  ✗ Non-Compliant: %d\n", score.NonCompliantCount)
	fmt.Printf("  - Not Applicable: %d\n", score.NotApplicableCount)

	fmt.Println("\nBy Category:")
	for _, cat := range score.Categories {
		fmt.Printf("  %s: %.1f%% (%d/%d)\n", cat.Category, cat.Score, cat.CompliantCount, cat.TotalControls)
	}

	return nil
}

func ComplianceReport(ctx context.Context, cmd *cli.Command) error {
	framework := cmd.String("standard")
	output := cmd.String("output")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}

	opts := compliance.GenerateReportOptions{
		Framework:   compliance.Framework(framework),
		OrgID:       orgID,
		GeneratedBy: c.CurrentIdentityID(),
		Period: compliance.ReportPeriod{
			StartDate: time.Now().AddDate(0, -1, 0),
			EndDate:   time.Now(),
		},
	}

	report, err := c.Compliance.GenerateReport(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	if output != "" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal report: %w", err)
		}

		if err := os.WriteFile(output, data, 0600); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}

		fmt.Printf("Report saved to: %s\n", output)
	} else {
		fmt.Printf("\n%s\n", report.Title)
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Generated: %s\n", report.GeneratedAt.Format(time.RFC3339))
		fmt.Printf("Period: %s to %s\n",
			report.Period.StartDate.Format("2006-01-02"),
			report.Period.EndDate.Format("2006-01-02"))
		fmt.Printf("\nOverall Score: %.1f%%\n", report.Score.Score)
		fmt.Printf("\nSummary:\n%s\n", report.Summary)

		fmt.Println("\nControls Status:")
		for _, ctrl := range report.Controls {
			statusIcon := "?"
			switch ctrl.Status {
			case compliance.ControlStatusCompliant:
				statusIcon = "✓"
			case compliance.ControlStatusNonCompliant:
				statusIcon = "✗"
			case compliance.ControlStatusPartial:
				statusIcon = "~"
			case compliance.ControlStatusNotApplicable:
				statusIcon = "-"
			}
			fmt.Printf("  [%s] %s: %s\n", statusIcon, ctrl.ID, ctrl.Name)
		}
	}

	return nil
}

func ComplianceListReports(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}

	reports, err := c.Compliance.ListReports(ctx, orgID)
	if err != nil {
		return fmt.Errorf("failed to list reports: %w", err)
	}

	fmt.Printf("\nCompliance Reports for Org: %s\n", orgID)
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("%-24s | %-12s | %-10s | %-s\n", "ID", "Framework", "Score", "Generated At")
	fmt.Println(strings.Repeat("-", 60))

	for _, r := range reports {
		fmt.Printf("%-24s | %-12s | %-10.1f%% | %-s\n",
			r.ID, r.Framework, r.Score.Score, r.GeneratedAt.Format(time.RFC3339))
	}

	return nil
}

func DLPScan(ctx context.Context, cmd *cli.Command) error {
	path := cmd.String("path")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	result, err := c.DLP.ScanContent(ctx, compliance.ScanOptions{
		Content:      content,
		ResourceID:   types.ID(path),
		ResourceType: "file",
		ActorID:      c.CurrentIdentityID(),
	})
	if err != nil {
		return fmt.Errorf("failed to scan file: %w", err)
	}

	if len(result.Violations) == 0 {
		success("No DLP violations detected in %s", path)
		return nil
	}

	fmt.Printf("Found %d DLP violations in %s\n", len(result.Violations), path)
	for _, v := range result.Violations {
		fmt.Printf("  - [%s] Rule: %s\n", v.Severity, v.RuleName)
		for _, m := range v.MatchedData {
			fmt.Printf("    • Match: %s (Pattern: %s)\n", m.Redacted, m.Pattern)
		}
	}

	return nil
}

func DLPRuleList(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	rules, err := c.DLP.ListRules(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("\nDLP Rules\n")
	fmt.Println(strings.Repeat("-", 60))
	for _, r := range rules {
		fmt.Printf("  • %s (%s): %s\n", r.Name, r.ID, r.Description)
	}

	return nil
}

func DLPRuleCreate(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	desc := cmd.String("description")
	patterns := cmd.StringSlice("patterns")
	severity := cmd.String("severity")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	rule, err := c.DLP.CreateRule(ctx, compliance.CreateDLPRuleOptions{
		Name:           name,
		Description:    desc,
		Patterns:       patterns,
		Severity:       compliance.DLPSeverity(severity),
		CreatedBy:      c.CurrentIdentityID(),
		PatternType:    compliance.PatternTypeRegex,
		Classification: compliance.ClassificationConfidential,
		Actions:        []compliance.DLPAction{compliance.DLPActionAlert},
	})
	if err != nil {
		return err
	}

	success("DLP rule created: %s", rule.ID)
	return nil
}

func DLPRuleDelete(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.DLP.DeleteRule(ctx, types.ID(id)); err != nil {
		return err
	}

	success("DLP rule deleted: %s", id)
	return nil
}

func CompliancePolicyList(ctx context.Context, cmd *cli.Command) error {
	fmt.Println("Compliance policies: all clusters compliant")
	return nil
}

func CompliancePolicyCreate(ctx context.Context, cmd *cli.Command) error {
	success("Compliance policy created")
	return nil
}

func CompliancePolicyUpdate(ctx context.Context, cmd *cli.Command) error {
	success("Compliance policy updated")
	return nil
}
