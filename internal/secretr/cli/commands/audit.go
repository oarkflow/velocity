package commands

import (
	"context"
	"os"
	"time"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// Audit commands

func AuditQuery(ctx context.Context, cmd *cli.Command) error {
	action := cmd.String("action")
	actor := cmd.String("actor")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	events, err := c.Audit.Query(ctx, audit.QueryOptions{
		Action:  action,
		ActorID: types.ID(actor),
		Limit:   100,
	})
	if err != nil {
		return err
	}
	return output(cmd, events)
}

func AuditExport(ctx context.Context, cmd *cli.Command) error {
	outputPath := cmd.String("output")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	data, err := c.Audit.Export(ctx, audit.ExportOptions{
		Limit:      1000,
		ExporterID: c.CurrentIdentityID(),
		EndTime:    time.Now(),
	})
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return err
	}

	success("Audit log exported to %s", outputPath)
	return nil
}

func AuditVerify(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}

	ok, err := c.Audit.VerifyIntegrity(ctx)
	if err != nil {
		return err
	}

	if ok {
		success("Audit log integrity verified")
	} else {
		warning("Audit log integrity verification FAILED")
	}
	return nil
}
