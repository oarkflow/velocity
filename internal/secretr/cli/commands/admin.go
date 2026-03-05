package commands

import (
	"context"

	"github.com/oarkflow/velocity/internal/secretr/api"
	"github.com/oarkflow/velocity/internal/secretr/authz"
	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/identity"
	"github.com/urfave/cli/v3"
)

// Admin commands

func AdminServer(ctx context.Context, cmd *cli.Command) error {
	addr := cmd.String("addr")
	if addr == "" {
		addr = ":9090"
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	// Note: We don't defer c.Close() here because Start() is blocking

	// Initialize API Server
	srv := api.NewServer(api.Config{
		Address:          addr,
		IdentityMgr:      c.Identity,
		SecretVault:      c.Secrets,
		FileVault:        c.Files,
		AccessManager:    c.Access,
		PolicyEngine:     c.Policy,
		ShareManager:     c.Share,
		AuditEngine:      c.Audit,
		CICDManager:      c.CICD,
		MonitoringEngine: c.Monitoring,
		AlertEngine:      c.Alerts,
		UsageCounter:     authz.NewStoreUsageCounter(c.Store),
		PolicyChecker:    &authz.PolicyAdapter{Engine: c.Policy},
	})

	info("Starting Secretr API Server on %s...", addr)
	return srv.Start()
}

func AdminUsers(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	// List all identities for admin
	idents, err := c.Identity.ListIdentities(ctx, identity.ListOptions{})
	if err != nil {
		return err
	}
	return output(cmd, idents)
}

func AdminSystem(ctx context.Context, cmd *cli.Command) error {
	info("System status: ONLINE")
	info("Version: 1.0.0")
	info("Data Directory: %s", "confidential") // Should get from config
	return nil
}

func AdminSecurity(ctx context.Context, cmd *cli.Command) error {
	// Placeholder for global security settings display
	info("Security settings:")
	info("  MFA Required: true")
	info("  Min Password Length: 12")
	return nil
}
