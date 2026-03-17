package commands

import (
	"context"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/ssh"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// SSH Commands

func SSHCreateProfile(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	host := cmd.String("host")
	user := cmd.String("user")
	keyID := cmd.String("key-id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeSSHProfile); err != nil {
		return err
	}

	profile, err := c.SSH.CreateProfile(ctx, ssh.ProfileOptions{
		Name:          name,
		Host:          host,
		User:          user,
		IdentityKeyID: types.ID(keyID),
		OwnerID:       c.CurrentIdentityID(),
	})
	if err != nil {
		return err
	}

	success("SSH Profile created: %s (ID: %s)", profile.Name, profile.ID)
	return nil
}

func SSHListProfiles(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}

	profiles, err := c.SSH.ListProfiles(ctx, c.CurrentIdentityID())
	if err != nil {
		return err
	}
	return output(cmd, profiles)
}

func SSHStartSession(ctx context.Context, cmd *cli.Command) error {
	profileID := cmd.String("profile-id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeSSHConnect); err != nil {
		return err
	}

	session, err := c.SSH.StartSession(ctx, types.ID(profileID), c.CurrentIdentityID())
	if err != nil {
		return err
	}

	success("SSH Session started: %s", session.ID)
	info("To connect, run secure-ssh-proxy with session ID") // Placeholder for real connection logic
	return nil
}
