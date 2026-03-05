package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/identity"
	"github.com/oarkflow/velocity/internal/secretr/core/org"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// Auth commands

func AuthLogin(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	// Check if already logged in
	if session := c.CurrentSession(); session != nil && session.IsActive() {
		return fmt.Errorf("already logged in as %s", session.IdentityID)
	}

	email, err := resolveLoginEmail(ctx, c, cmd.String("email"), cmd.String("username"))
	if err != nil {
		return err
	}
	deviceID := cmd.String("device-id")

	password := cmd.String("password")
	if password == "" {
		password, err = promptSecurePassword("Password: ")
		if err != nil {
			return err
		}
	}

	session, err := c.Identity.Authenticate(ctx, email, password, types.ID(deviceID))
	if err != nil {
		if errors.Is(err, identity.ErrIdentityNotFound) {
			return fmt.Errorf("login failed: identity not found for email %q", email)
		}
		return fmt.Errorf("login failed: %w", err)
	}

	if err := c.SaveSession(ctx, session); err != nil {
		return err
	}

	success("Logged in as %s", email)
	info("Session expires at %s", session.ExpiresAt.Time().Format(time.RFC3339))
	return nil
}

func AuthLogout(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	session := c.CurrentSession()
	if session != nil {
		c.Identity.RevokeSession(ctx, session.ID)
	}

	if err := c.ClearSession(ctx); err != nil && !os.IsNotExist(err) {
		return err
	}

	success("Logged out successfully")
	return nil
}

func AuthStatus(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	session := c.CurrentSession()
	if session == nil || !session.IsActive() {
		info("Not logged in")
		return nil
	}

	ident, _ := c.Identity.GetIdentity(ctx, session.IdentityID)
	name := string(session.IdentityID)
	if ident != nil {
		name = ident.Name
	}

	info("Logged in as: %s", name)
	info("Session ID: %s", session.ID)
	info("Expires: %s", session.ExpiresAt.Time().Format(time.RFC3339))
	return nil
}

func AuthRotateToken(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireSession(); err != nil {
		return err
	}

	session := c.CurrentSession()
	if err := c.Identity.RefreshSession(ctx, session.ID); err != nil {
		return err
	}

	success("Token rotated successfully")
	return nil
}

func AuthMFA(ctx context.Context, cmd *cli.Command) error {
	token := cmd.String("token")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireSession(); err != nil {
		return err
	}

	session := c.CurrentSession()
	if err := c.Identity.VerifyMFA(ctx, session.IdentityID, token); err != nil {
		return fmt.Errorf("MFA verification failed: %w", err)
	}

	success("MFA verified successfully")
	return nil
}

func AuthInit(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	// Check if system is already initialized
	idents, err := c.Identity.ListIdentities(ctx, identity.ListOptions{})
	if err == nil && len(idents) > 0 {
		return fmt.Errorf("system already initialized")
	}

	username := strings.TrimSpace(cmd.String("username"))
	name := strings.TrimSpace(cmd.String("full-name"))
	if name == "" {
		name = strings.TrimSpace(cmd.String("name"))
	}
	if name == "" {
		name = username
	}
	email := strings.TrimSpace(cmd.String("email"))
	if email == "" {
		email = username
	}
	if email == "" {
		return fmt.Errorf("either --email or --username is required")
	}
	if name == "" {
		return fmt.Errorf("either --name, --full-name, or --username is required")
	}
	idleTimeout := cmd.String("idle-timeout")

	// Parse idle timeout with flexible formats
	timeout, err := parseDuration(idleTimeout)
	if err != nil {
		return fmt.Errorf("invalid idle timeout format: %w", err)
	}

	password := cmd.String("password")
	if password == "" {
		password, err = promptPasswordWithConfirm("Set admin password: ")
		if err != nil {
			return err
		}
	}

	// Create Admin
	ident, err := c.Identity.CreateHumanIdentity(ctx, identity.CreateHumanOptions{
		Name:     name,
		Email:    email,
		Password: password,
		Scopes:   []types.Scope{types.ScopeAdminAll},
	})
	if err != nil {
		return err
	}

	success("System initialized. Admin created: %s (%s)", ident.Name, ident.ID)
	info("Admin login email: %s", ident.Email)
	info("Idle timeout configured: %v", timeout)

	// Enroll initial device
	device, err := c.Identity.EnrollDevice(ctx, identity.EnrollDeviceOptions{
		OwnerID: ident.ID,
		Name:    "Admin CLI",
		Type:    "cli",
	})
	if err != nil {
		return fmt.Errorf("failed to enroll initial device: %w", err)
	}
	success("Initial device enrolled: %s", device.ID)

	// Create Default Organization
	organization, err := c.Org.CreateOrganization(ctx, org.CreateOrgOptions{
		Name:    "Default",
		Slug:    "default",
		OwnerID: ident.ID,
	})
	if err != nil {
		warning("Failed to create default organization: %v", err)
	} else {
		success("Default organization created: %s (%s)", organization.Name, organization.ID)
	}

	return nil
}

func resolveLoginEmail(ctx context.Context, c *client.Client, email, username string) (string, error) {
	email = strings.TrimSpace(email)
	if email != "" {
		return email, nil
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("either --email or --username is required")
	}
	if strings.Contains(username, "@") {
		return username, nil
	}

	idents, err := c.Identity.ListIdentities(ctx, identity.ListOptions{
		Type:   types.IdentityTypeHuman,
		Status: types.StatusActive,
	})
	if err != nil {
		return "", fmt.Errorf("failed to resolve username %q: %w", username, err)
	}

	var matches []string
	for _, ident := range idents {
		if strings.EqualFold(strings.TrimSpace(ident.Name), username) {
			if ident.Email != "" {
				matches = append(matches, ident.Email)
			}
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return username, nil
	default:
		return "", fmt.Errorf("username %q is ambiguous; use --email", username)
	}
}
