package commands

import (
	"context"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// Session commands

func SessionList(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}

	sessions, err := c.Identity.GetActiveSessions(ctx, c.CurrentIdentityID())
	if err != nil {
		return err
	}
	info("Active sessions: %d", len(sessions))
	return nil
}

func SessionRevoke(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.Identity.RevokeSession(ctx, types.ID(id)); err != nil {
		return err
	}
	success("Session revoked: %s", id)
	return nil
}

func SessionRevokeAll(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.Identity.RevokeAllSessions(ctx, c.CurrentIdentityID()); err != nil {
		return err
	}
	success("All other sessions revoked")
	return nil
}
