// Package app provides the CLI application setup.
package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/oarkflow/velocity"
	velocitycli "github.com/oarkflow/velocity/cli"
	"github.com/oarkflow/velocity/internal/secretr/authz"
	secretrcli "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/cli/commands"
	"github.com/oarkflow/velocity/internal/secretr/cli/middleware"
	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/securitymode"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

// Version information
var (
	Version   = "0.1.0"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// App holds the CLI application
type App struct {
	cli              *cli.Command
	gate             *middleware.PermissionGate
	sessionStore     SessionStore
	velocityDB       *velocity.DB
	velocityRegistry *velocitycli.Registry
	adapter          *secretrcli.VelocityAdapter
}

// SessionStore manages session state
type SessionStore interface {
	middleware.SessionProvider
	SaveSession(ctx context.Context, session *types.Session) error
	ClearSession(ctx context.Context) error
}

// NewApp creates a new CLI application with velocity integration
func NewApp(sessionStore SessionStore) (*App, error) {
	app := &App{
		sessionStore: sessionStore,
	}

	// Initialize velocity DB
	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".secretr")
	os.MkdirAll(dataDir, 0700)

	velocityDB, err := secretrcli.InitializeVelocityDB(dataDir, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize velocity DB: %w", err)
	}
	app.velocityDB = velocityDB

	// Create velocity registry
	app.velocityRegistry = velocitycli.NewRegistry()

	// Initialize adapter (client will be nil initially, set later)
	app.adapter = secretrcli.NewVelocityAdapter(nil, velocityDB)

	// Set global adapter reference for client initialization
	secretrcli.SetGlobalAdapter(app.adapter)

	// Default to the shared Secretr client as session provider to keep auth active.
	if sessionStore == nil {
		c, err := secretrcli.GetClient()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize secretr client: %w", err)
		}
		sessionStore = c
		app.sessionStore = c
		app.adapter.SetClient(c)
	}

	// Create permission gate - it will handle nil sessionStore
	app.gate = middleware.NewPermissionGate(sessionStore, nil)
	var aclChecker authz.ACLChecker
	var usageCounter authz.UsageCounter
	var policyChecker authz.PolicyChecker
	var auditLogger authz.AuditLogger
	if c := app.adapter.GetClient(); c != nil {
		aclChecker = c.Access
		usageCounter = authz.NewStoreUsageCounter(c.Store)
		policyChecker = &authz.PolicyAdapter{Engine: c.Policy}
		auditLogger = &authz.AuditAdapter{Engine: c.Audit}
	}
	authorizer := authz.NewAuthorizerWithCounter(authz.NewEnvEntitlementProvider(), aclChecker, auditLogger, usageCounter)
	authorizer.SetPolicyChecker(policyChecker)
	app.gate.SetAuthorizer(authorizer)

	// Build CLI
	app.cli = app.buildCLI()
	app.gate.SetCommandSpecs(authz.BuildCLIAuthSpecs(app.cli, nil))
	app.applyAuthzBefore(app.cli)
	app.applyCLIAudit(app.cli)

	return app, nil
}

func (a *App) applyAuthzBefore(cmd *cli.Command) {
	if cmd == nil {
		return
	}
	if cmd.Before == nil {
		cmd.Before = a.gate.RequireAuthz()
	} else {
		cmd.Before = middleware.Chain(a.gate.RequireAuthz(), cmd.Before)
	}
	for _, sub := range cmd.Commands {
		a.applyAuthzBefore(sub)
	}
}

func (a *App) applyCLIAudit(cmd *cli.Command) {
	if cmd == nil {
		return
	}
	if cmd.Action != nil {
		orig := cmd.Action
		cmd.Action = func(ctx context.Context, current *cli.Command) error {
			err := orig(ctx, current)
			a.logCLICommandAudit(ctx, current, err)
			return err
		}
	}
	for _, sub := range cmd.Commands {
		a.applyCLIAudit(sub)
	}
}

func (a *App) logCLICommandAudit(ctx context.Context, cmd *cli.Command, actionErr error) {
	if a == nil || a.adapter == nil {
		return
	}
	c := a.adapter.GetClient()
	if c == nil || c.Audit == nil || cmd == nil {
		return
	}

	actorID := types.ID("")
	if sess := c.CurrentSession(); sess != nil {
		actorID = sess.IdentityID
	}
	commandPath := strings.TrimSpace(cmd.FullName())
	if commandPath == "" {
		commandPath = strings.TrimSpace(cmd.Name)
	}
	details := types.Metadata{
		"command": commandPath,
	}
	if actionErr != nil {
		details["error"] = actionErr.Error()
	}
	_ = c.Audit.Log(ctx, audit.AuditEventInput{
		Type:      "cli",
		Action:    "command_execute",
		ActorID:   actorID,
		ActorType: "identity",
		Success:   actionErr == nil,
		Details:   details,
	})
}

func (a *App) buildCLI() *cli.Command {
	// Create velocity commands wrapper
	velocityWrapper := commands.NewVelocityCommandsWrapper(a.adapter, a.velocityDB)
	backupCmd := commands.ConvertVelocityCommandToSecretsCommand(
		velocityWrapper.GetBackupCommands(),
		commands.GetBackupScopeMappings(),
	)
	backupCmd.Commands = append(backupCmd.Commands, &cli.Command{
		Name:   "schedule",
		Usage:  "Schedule automated backups",
		Before: a.gate.RequireScopes(types.ScopeBackupSchedule),
		Action: commands.BackupSchedule,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "cron", Usage: "Cron expression", Required: true},
			&cli.StringFlag{Name: "destination", Usage: "Backup destination"},
		},
	})

	return &cli.Command{
		Name:    "secretr",
		Usage:   "Military-grade secrets management platform",
		Version: Version,
		Description: `Secretr is a comprehensive platform for secure secret management,
file encryption, identity management, and secure sharing with
feature-gated CLI commands.

Every feature enforces authority, preserves evidence, survives disasters,
and reduces trust ambiguity.`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Path to configuration file",
				Value:   "~/.secretr/config.yaml",
			},
			&cli.StringFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Usage:   "Output format: json, yaml, table, plain",
				Value:   "table",
			},
			&cli.StringFlag{
				Name:   "user",
				Usage:  "Internal: user identity for object access",
				Value:  "",
				Hidden: true,
			},
			&cli.BoolFlag{
				Name:  "quiet",
				Usage: "Suppress non-essential output",
			},
			&cli.BoolFlag{
				Name:   "debug",
				Usage:  "Enable debug output",
				Hidden: !securitymode.IsDevBuild(),
			},
			&cli.BoolFlag{
				Name:    "yes",
				Aliases: []string{"y"},
				Usage:   "Automatic yes to prompts; assume \"yes\" as answer to all prompts and run non-interactively",
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			if cmd.Bool("yes") {
				commands.GlobalYes = true
			}
			if a.isAuthenticationExempt(cmd) {
				return ctx, nil
			}
			return a.gate.RequireAuthenticated()(ctx, cmd)
		},
		Commands: []*cli.Command{
			a.authCommands(),
			a.identityCommands(),
			a.deviceCommands(),
			a.sessionCommands(),
			a.keyCommands(),

			// Use velocity commands for these
			commands.ConvertVelocityCommandToSecretsCommand(
				velocityWrapper.GetSecretCommands(),
				commands.GetSecretScopeMappings(),
			),
			commands.ConvertVelocityCommandToSecretsCommand(
				velocityWrapper.GetFileCommands(),
				commands.GetFileScopeMappings(),
			),
			commands.ConvertVelocityCommandToSecretsCommand(
				velocityWrapper.GetFolderCommands(),
				commands.GetFolderScopeMappings(),
			),
			backupCmd,
			commands.ConvertVelocityCommandToSecretsCommand(
				velocityWrapper.GetDataCommands(),
				map[string]types.Scope{
					"import": types.ScopeSecretCreate,
					"export": types.ScopeSecretRead,
				},
			),
			commands.ConvertVelocityCommandToSecretsCommand(
				velocityWrapper.GetExportCommands(),
				commands.GetExportScopeMappings(),
			),
			commands.ConvertVelocityCommandToSecretsCommand(
				velocityWrapper.GetImportCommands(),
				commands.GetImportScopeMappings(),
			),

			// Keep secretr-specific commands
			a.accessCommands(),
			a.roleCommands(),
			a.policyCommands(),
			a.auditCommands(),
			a.shareCommands(),
			a.orgCommands(),
			a.incidentCommands(),
			a.envelopeCommands(),
			a.adminCommands(),
			a.sshCommands(),
			a.cicdCommands(),
			a.execCommands(),
			a.envCommand(),
			a.loadEnvCommand(),
			a.enrichCommand(),
			a.monitoringCommands(),
			a.alertCommands(),
			a.complianceCommands(),
			a.dlpCommands(),
			a.automationPipelineCommands(),
		},
		ExitErrHandler: func(ctx context.Context, cmd *cli.Command, err error) {
			if err != nil {
				if terr, ok := err.(*types.Error); ok {
					fmt.Fprintf(os.Stderr, "Error [%s]: %s\n", terr.Code, terr.Message)
					os.Exit(getExitCode(terr.Code))
				}
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
}

// BuildCLIRootForAuthz builds the CLI command tree without runtime client dependencies.
// Used by authz metadata generation/tests.
func BuildCLIRootForAuthz() *cli.Command {
	a := &App{gate: middleware.NewPermissionGate(nil, nil)}
	return a.buildCLI()
}

func (a *App) isAuthenticationExempt(cmd *cli.Command) bool {
	if cmd == nil {
		return true
	}
	full := strings.TrimSpace(cmd.FullName())
	name := strings.TrimSpace(cmd.Name)

	// Discovery and metadata commands remain public.
	if name == "help" || name == "h" || cmd.Bool("help") || cmd.Bool("version") {
		return true
	}

	// Root-level metadata commands.
	if name == "secretr" {
		first := strings.TrimSpace(cmd.Args().First())
		if first == "" || first == "help" || first == "h" {
			return true
		}
		if first == "--help" || first == "-h" || first == "--version" || first == "-v" {
			return true
		}
		if first == "auth" {
			return true
		}
	}

	// Auth commands must be accessible before login.
	if name == "auth" || strings.HasPrefix(full, "auth ") || strings.HasPrefix(full, "secretr auth") {
		return true
	}

	// Hidden/internal commands are intentionally private.
	if cmd.Hidden {
		return true
	}

	return false
}

func getExitCode(code string) int {
	switch code {
	case types.ErrCodeUnauthorized:
		return 10
	case types.ErrCodeForbidden:
		return 11
	case types.ErrCodeNotFound:
		return 12
	case types.ErrCodeConflict:
		return 13
	case types.ErrCodeValidation:
		return 14
	case types.ErrCodeCrypto:
		return 20
	case types.ErrCodeStorage:
		return 21
	case types.ErrCodePolicy:
		return 30
	case types.ErrCodeExpired:
		return 40
	case types.ErrCodeRevoked:
		return 41
	case types.ErrCodeRateLimited:
		return 50
	case types.ErrCodeIncidentFrozen:
		return 60
	case types.ErrCodeScopeRequired:
		return 70
	default:
		return 1
	}
}

func (a *App) authCommands() *cli.Command {
	return &cli.Command{
		Name:  "auth",
		Usage: "Authentication and session management",
		Commands: []*cli.Command{
			{
				Name:   "init",
				Usage:  "Initialize system (create first admin)",
				Action: commands.AuthInit,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "Admin name"},
					&cli.StringFlag{Name: "full-name", Usage: "Admin full name"},
					&cli.StringFlag{Name: "username", Aliases: []string{"u"}, Usage: "Admin username (compat)"},
					&cli.StringFlag{Name: "email", Usage: "Admin email"},
					&cli.StringFlag{Name: "password", Usage: "Admin Password"},
					&cli.StringFlag{Name: "device-id", Usage: "Initial Device ID"},
					&cli.StringFlag{Name: "idle-timeout", Usage: "Session idle timeout (e.g., 24h, 30m)", Value: "24h"},
				},
			},
			{
				Name:   "login",
				Usage:  "Authenticate and create a session",
				Action: commands.AuthLogin,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "email", Aliases: []string{"e"}, Usage: "Email address"},
					&cli.StringFlag{Name: "username", Aliases: []string{"u"}, Usage: "Username (compat)"},
					&cli.StringFlag{Name: "password", Aliases: []string{"p"}, Usage: "Password (will prompt if not provided)"},
					&cli.StringFlag{Name: "mfa-token", Usage: "MFA token"},
					&cli.StringFlag{Name: "device-id", Usage: "Device ID"},
					&cli.BoolFlag{Name: "offline", Usage: "Create offline-capable session"},
				},
			},
			{
				Name:   "logout",
				Usage:  "End current session",
				Before: a.gate.RequireScopes(types.ScopeAuthLogout),
				Action: commands.AuthLogout,
			},
			{
				Name:   "status",
				Usage:  "Show current session status",
				Before: a.gate.RequireAuthenticated(),
				Action: commands.AuthStatus,
			},
			{
				Name:   "rotate-token",
				Usage:  "Rotate the current session token",
				Before: a.gate.RequireScopes(types.ScopeAuthRotate),
				Action: commands.AuthRotateToken,
			},
			{
				Name:   "mfa",
				Usage:  "Verify MFA for current session",
				Before: a.gate.RequireAuthenticated(),
				Action: commands.AuthMFA,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "token", Aliases: []string{"t"}, Usage: "MFA token", Required: true},
				},
			},
		},
	}
}

func (a *App) identityCommands() *cli.Command {
	return &cli.Command{
		Name:  "identity",
		Usage: "Identity management",
		Commands: []*cli.Command{
			{
				Name:   "create",
				Usage:  "Create a new identity",
				Before: a.gate.RequireScopes(types.ScopeIdentityCreate),
				Action: commands.IdentityCreate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Identity name", Required: true},
					&cli.StringFlag{Name: "email", Aliases: []string{"e"}, Usage: "Email address", Required: true},
					&cli.StringFlag{Name: "type", Aliases: []string{"t"}, Usage: "Identity type: human, service", Value: "human"},
					&cli.StringFlag{Name: "password", Aliases: []string{"p"}, Usage: "Password (will prompt if not provided)"},
					&cli.StringSliceFlag{Name: "scopes", Aliases: []string{"s"}, Usage: "Permission scopes"},
				},
			},
			{
				Name:   "list",
				Usage:  "List identities",
				Before: a.gate.RequireScopes(types.ScopeIdentityRead),
				Action: commands.IdentityList,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "type", Usage: "Filter by type"},
					&cli.StringFlag{Name: "status", Usage: "Filter by status"},
				},
			},
			{
				Name:   "get",
				Usage:  "Get identity details",
				Before: a.gate.RequireScopes(types.ScopeIdentityRead),
				Action: commands.IdentityGet,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Identity ID", Required: true},
				},
			},
			{
				Name:   "revoke",
				Usage:  "Revoke an identity",
				Before: a.gate.RequireScopes(types.ScopeIdentityDelete),
				Action: commands.IdentityRevoke,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Identity ID", Required: true},
					&cli.BoolFlag{Name: "force", Usage: "Force revocation without confirmation"},
				},
			},
			{
				Name:   "recover",
				Usage:  "Start identity recovery workflow",
				Before: a.gate.RequireScopes(types.ScopeIdentityRecover),
				Action: commands.IdentityRecover,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "email", Usage: "Email address", Required: true},
				},
			},
		},
	}
}

func (a *App) deviceCommands() *cli.Command {
	return &cli.Command{
		Name:  "device",
		Usage: "Device management",
		Commands: []*cli.Command{
			{
				Name:   "enroll",
				Usage:  "Enroll this device",
				Before: a.gate.RequireScopes(types.ScopeDeviceEnroll),
				Action: commands.DeviceEnroll,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Device name", Required: true},
					&cli.StringFlag{Name: "type", Usage: "Device type: desktop, mobile, server", Value: "desktop"},
				},
			},
			{
				Name:   "list",
				Usage:  "List enrolled devices",
				Before: a.gate.RequireScopes(types.ScopeDeviceRead),
				Action: commands.DeviceList,
			},
			{
				Name:   "revoke",
				Usage:  "Revoke a device",
				Before: a.gate.RequireScopes(types.ScopeDeviceRevoke),
				Action: commands.DeviceRevoke,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Device ID", Required: true},
				},
			},
			{
				Name:   "trust",
				Usage:  "View device trust score",
				Before: a.gate.RequireScopes(types.ScopeDeviceTrust),
				Action: commands.DeviceTrust,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Device ID"},
				},
			},
		},
	}
}

func (a *App) sessionCommands() *cli.Command {
	return &cli.Command{
		Name:  "session",
		Usage: "Session management",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "List active sessions",
				Before: a.gate.RequireScopes(types.ScopeSessionRead),
				Action: commands.SessionList,
			},
			{
				Name:   "revoke",
				Usage:  "Revoke a session",
				Before: a.gate.RequireScopes(types.ScopeSessionRevoke),
				Action: commands.SessionRevoke,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Session ID", Required: true},
				},
			},
			{
				Name:   "revoke-all",
				Usage:  "Revoke all sessions except current",
				Before: a.gate.RequireScopes(types.ScopeSessionRevoke),
				Action: commands.SessionRevokeAll,
			},
		},
	}
}

func (a *App) keyCommands() *cli.Command {
	return &cli.Command{
		Name:  "key",
		Usage: "Cryptographic key management",
		Commands: []*cli.Command{
			{
				Name:   "generate",
				Usage:  "Generate a new key",
				Before: a.gate.RequireScopes(types.ScopeKeyGenerate),
				Action: commands.KeyGenerate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "type", Usage: "Key type: encryption, signing", Value: "encryption"},
					&cli.StringFlag{Name: "purpose", Usage: "Key purpose", Value: "encrypt"},
					&cli.DurationFlag{Name: "expires-in", Usage: "Key expiration duration"},
				},
			},
			{
				Name:   "list",
				Usage:  "List keys",
				Before: a.gate.RequireScopes(types.ScopeKeyRead),
				Action: commands.KeyList,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "type", Usage: "Filter by type"},
					&cli.StringFlag{Name: "status", Usage: "Filter by status"},
				},
			},
			{
				Name:   "rotate",
				Usage:  "Rotate a key",
				Before: a.gate.RequireScopes(types.ScopeKeyRotate),
				Action: commands.KeyRotate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Key ID", Required: true},
				},
			},
			{
				Name:   "destroy",
				Usage:  "Destroy a key with proof",
				Before: a.gate.RequireScopes(types.ScopeKeyDestroy),
				Action: commands.KeyDestroy,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Key ID", Required: true},
					&cli.BoolFlag{Name: "force", Usage: "Force destruction without confirmation"},
				},
			},
			{
				Name:   "export",
				Usage:  "Export a key for backup",
				Before: a.gate.RequireScopes(types.ScopeKeyExport),
				Action: commands.KeyExport,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Key ID", Required: true},
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "Output file", Required: true},
				},
			},
			{
				Name:   "import",
				Usage:  "Import a key from backup",
				Before: a.gate.RequireScopes(types.ScopeKeyImport),
				Action: commands.KeyImport,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "input", Aliases: []string{"i"}, Usage: "Input file", Required: true},
				},
			},
			{
				Name:   "split",
				Usage:  "Split key for M-of-N recovery",
				Before: a.gate.RequireScopes(types.ScopeKeyRecovery),
				Action: commands.KeySplit,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Key ID", Required: true},
					&cli.IntFlag{Name: "shares", Aliases: []string{"n"}, Usage: "Total shares", Value: 5},
					&cli.IntFlag{Name: "threshold", Aliases: []string{"t"}, Usage: "Required threshold", Value: 3},
				},
			},
		},
	}
}

/*
// DEPRECATED: Now using velocity secret commands
func (a *App) secretCommands() *cli.Command {
	return &cli.Command{
		Name:  "secret",
		Usage: "Secret management",
		Commands: []*cli.Command{
			{
				Name:   "create",
				Usage:  "Create a new secret",
				Before: a.gate.RequireScopes(types.ScopeSecretCreate),
				Action: commands.SecretCreate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Secret name", Required: true},
					&cli.StringFlag{Name: "value", Aliases: []string{"v"}, Usage: "Secret value (use - for stdin)"},
					&cli.StringFlag{Name: "type", Aliases: []string{"t"}, Usage: "Secret type", Value: "generic"},
					&cli.StringFlag{Name: "env", Aliases: []string{"e"}, Usage: "Environment"},
					&cli.DurationFlag{Name: "expires-in", Usage: "Expiration duration"},
					&cli.BoolFlag{Name: "read-once", Usage: "Secret can only be read once"},
					&cli.BoolFlag{Name: "immutable", Usage: "Secret cannot be updated"},
				},
			},
			{
				Name:   "get",
				Usage:  "Retrieve a secret",
				Before: a.gate.RequireScopes(types.ScopeSecretRead),
				Action: commands.SecretGet,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Secret name", Required: true},
					&cli.IntFlag{Name: "version", Usage: "Specific version"},
					&cli.BoolFlag{Name: "metadata-only", Usage: "Only show metadata"},
				},
			},
			{
				Name:   "list",
				Usage:  "List secrets",
				Before: a.gate.RequireScopes(types.ScopeSecretList),
				Action: commands.SecretList,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "prefix", Usage: "Filter by prefix"},
					&cli.StringFlag{Name: "env", Usage: "Filter by environment"},
					&cli.StringFlag{Name: "type", Usage: "Filter by type"},
				},
			},
			{
				Name:   "update",
				Usage:  "Update a secret",
				Before: a.gate.RequireScopes(types.ScopeSecretUpdate),
				Action: commands.SecretUpdate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Secret name", Required: true},
					&cli.StringFlag{Name: "value", Aliases: []string{"v"}, Usage: "New value"},
				},
			},
			{
				Name:   "delete",
				Usage:  "Delete a secret",
				Before: a.gate.RequireScopes(types.ScopeSecretDelete),
				Action: commands.SecretDelete,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Secret name", Required: true},
					&cli.BoolFlag{Name: "force", Usage: "Force deletion"},
				},
			},
			{
				Name:   "history",
				Usage:  "View secret version history",
				Before: a.gate.RequireScopes(types.ScopeSecretHistory),
				Action: commands.SecretHistory,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Secret name", Required: true},
				},
			},
			{
				Name:   "rotate",
				Usage:  "Rotate a secret",
				Before: a.gate.RequireScopes(types.ScopeSecretRotate),
				Action: commands.SecretRotate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Secret name", Required: true},
				},
			},
			{
				Name:   "export",
				Usage:  "Export secrets for offline use",
				Before: a.gate.RequireScopes(types.ScopeSecretExport),
				Action: commands.SecretExport,
				Flags: []cli.Flag{
					&cli.StringSliceFlag{Name: "names", Usage: "Secret names to export"},
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "Output file", Required: true},
				},
			},
		},
	}
}
*/

/*
// DEPRECATED: Now using velocity file commands
func (a *App) fileCommands() *cli.Command {
	return &cli.Command{
		Name:  "file",
		Usage: "Encrypted file management",
		Commands: []*cli.Command{
			{
				Name:   "upload",
				Usage:  "Upload and encrypt a file",
				Before: a.gate.RequireScopes(types.ScopeFileUpload),
				Action: commands.FileUpload,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "File name in vault", Required: true},
					&cli.StringFlag{Name: "path", Aliases: []string{"p"}, Usage: "Local file path", Required: true},
					&cli.DurationFlag{Name: "expires-in", Usage: "Expiration duration"},
					&cli.BoolFlag{Name: "overwrite", Usage: "Overwrite if exists"},
				},
			},
			{
				Name:   "download",
				Usage:  "Download and decrypt a file",
				Before: a.gate.RequireScopes(types.ScopeFileDownload),
				Action: commands.FileDownload,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "File name in vault", Required: true},
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "Output path", Required: true},
				},
			},
			{
				Name:   "view",
				Usage:  "View/preview a file in the terminal",
				Before: a.gate.RequireScopes(types.ScopeFileDownload),
				Action: commands.FileView,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "File name in vault", Required: true},
				},
			},
			{
				Name:   "list",
				Usage:  "List files",
				Before: a.gate.RequireScopes(types.ScopeFileList),
				Action: commands.FileList,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "prefix", Usage: "Filter by prefix"},
				},
			},
			{
				Name:   "delete",
				Usage:  "Delete a file",
				Before: a.gate.RequireScopes(types.ScopeFileDelete),
				Action: commands.FileDelete,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "File name", Required: true},
				},
			},
			{
				Name:   "seal",
				Usage:  "Seal a file for long-term storage",
				Before: a.gate.RequireScopes(types.ScopeFileSeal),
				Action: commands.FileSeal,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "File name", Required: true},
				},
			},
			{
				Name:   "unseal",
				Usage:  "Unseal a file",
				Before: a.gate.RequireScopes(types.ScopeFileUnseal),
				Action: commands.FileUnseal,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "File name", Required: true},
				},
			},
			{
				Name:   "shred",
				Usage:  "Cryptographically destroy a file",
				Before: a.gate.RequireScopes(types.ScopeFileShred),
				Action: commands.FileShred,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "File name", Required: true},
					&cli.BoolFlag{Name: "force", Usage: "Skip confirmation"},
				},
			},
			{
				Name:   "protect",
				Usage:  "Set file protection policy",
				Before: a.gate.RequireScopes(types.ScopeFileSeal),
				Action: commands.FileProtect,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "File name", Required: true},
					&cli.IntFlag{Name: "max-downloads", Usage: "Maximum allowed downloads"},
					&cli.StringFlag{Name: "geofence", Usage: "Allowed countries (comma-separated)"},
					&cli.BoolFlag{Name: "remote-kill", Usage: "Enable remote kill for this file"},
					&cli.BoolFlag{Name: "require-mfa", Usage: "Require MFA to access this file"},
				},
			},
			{
				Name:   "kill",
				Usage:  "Remotely kill a file (emergency)",
				Before: a.gate.RequireScopes(types.ScopeFileDelete),
				Action: commands.FileKill,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "File name", Required: true},
					&cli.StringFlag{Name: "reason", Usage: "Reason for killing the file"},
				},
			},
			{
				Name:   "revive",
				Usage:  "Revive a remotely killed file",
				Before: a.gate.RequireScopes(types.ScopeFileSeal),
				Action: commands.FileRevive,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "File name", Required: true},
				},
			},
			{
				Name:    "view",
				Aliases: []string{"preview", "show"},
				Usage:   "Preview/view a file in terminal",
				Before:  a.gate.RequireScopes(types.ScopeFileDownload),
				Action:  commands.FileView,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "File name to view", Required: true},
				},
			},
		},
	}
}
*/

func (a *App) accessCommands() *cli.Command {
	return &cli.Command{
		Name:  "access",
		Usage: "Access control and delegation",
		Commands: []*cli.Command{
			{
				Name:   "grant",
				Usage:  "Grant access to a resource",
				Before: a.gate.RequireScopes(types.ScopeAccessGrant),
				Action: commands.AccessGrant,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "grantee", Aliases: []string{"g"}, Usage: "Grantee identity ID", Required: true},
					&cli.StringFlag{Name: "resource", Aliases: []string{"r"}, Usage: "Resource ID", Required: true},
					&cli.StringFlag{Name: "type", Usage: "Resource type: secret, file, key"},
					&cli.StringSliceFlag{Name: "scopes", Aliases: []string{"s"}, Usage: "Scopes to grant"},
					&cli.DurationFlag{Name: "expires-in", Usage: "Grant expiration"},
					&cli.BoolFlag{Name: "resharing", Usage: "Allow grantee to reshare"},
				},
			},
			{
				Name:   "revoke",
				Usage:  "Revoke access",
				Before: a.gate.RequireScopes(types.ScopeAccessRevoke),
				Action: commands.AccessRevoke,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Grant ID", Required: true},
				},
			},
			{
				Name:   "list",
				Usage:  "List access grants",
				Before: a.gate.RequireScopes(types.ScopeAccessRead),
				Action: commands.AccessList,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "resource", Usage: "Filter by resource"},
					&cli.StringFlag{Name: "grantee", Usage: "Filter by grantee"},
				},
			},
			{
				Name:   "request",
				Usage:  "Request temporary JIT access",
				Action: commands.AccessRequest,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "resource", Usage: "Resource ID", Required: true},
					&cli.StringFlag{Name: "type", Usage: "Resource type", Required: true},
					&cli.StringFlag{Name: "justification", Usage: "Justification for access", Required: true},
					&cli.StringFlag{Name: "duration", Usage: "Duration (e.g. 1h, 30m)", Required: true},
				},
			},
			{
				Name:   "approve",
				Usage:  "Approve a JIT access request",
				Action: commands.AccessApprove,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Request ID", Required: true},
				},
			},
		},
	}
}

func (a *App) roleCommands() *cli.Command {
	return &cli.Command{
		Name:  "role",
		Usage: "Role-based access control",
		Commands: []*cli.Command{
			{
				Name:   "create",
				Usage:  "Create a role",
				Before: a.gate.RequireScopes(types.ScopeRoleCreate),
				Action: commands.RoleCreate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Role name", Required: true},
					&cli.StringFlag{Name: "description", Aliases: []string{"d"}, Usage: "Description"},
					&cli.StringSliceFlag{Name: "scopes", Aliases: []string{"s"}, Usage: "Scopes"},
				},
			},
			{
				Name:   "list",
				Usage:  "List roles",
				Before: a.gate.RequireScopes(types.ScopeRoleRead),
				Action: commands.RoleList,
			},
			{
				Name:   "assign",
				Usage:  "Assign role to identity",
				Before: a.gate.RequireScopes(types.ScopeRoleAssign),
				Action: commands.RoleAssign,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "role", Usage: "Role ID", Required: true},
					&cli.StringFlag{Name: "identity", Usage: "Identity ID", Required: true},
				},
			},
		},
	}
}

func (a *App) policyCommands() *cli.Command {
	return &cli.Command{
		Name:  "policy",
		Usage: "Policy management",
		Commands: []*cli.Command{
			{
				Name:   "create",
				Usage:  "Create a policy",
				Before: a.gate.RequireScopes(types.ScopePolicyCreate),
				Action: commands.PolicyCreate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Policy name", Required: true},
					&cli.StringFlag{Name: "file", Aliases: []string{"f"}, Usage: "Policy definition file"},
				},
			},
			{
				Name:   "list",
				Usage:  "List policies",
				Before: a.gate.RequireScopes(types.ScopePolicyRead),
				Action: commands.PolicyList,
			},
			{
				Name:   "bind",
				Usage:  "Bind policy to resource",
				Before: a.gate.RequireScopes(types.ScopePolicyBind),
				Action: commands.PolicyBind,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "policy", Usage: "Policy ID", Required: true},
					&cli.StringFlag{Name: "resource", Usage: "Resource ID", Required: true},
					&cli.StringFlag{Name: "type", Usage: "Resource type", Required: true},
				},
			},
			{
				Name:   "simulate",
				Usage:  "Simulate policy evaluation",
				Before: a.gate.RequireScopes(types.ScopePolicySimulate),
				Action: commands.PolicySimulate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "policy", Usage: "Policy ID", Required: true},
					&cli.StringFlag{Name: "action", Usage: "Action to simulate", Required: true},
					&cli.StringFlag{Name: "resource", Usage: "Resource ID"},
				},
			},
			{
				Name:   "freeze",
				Usage:  "Enable policy lockdown mode",
				Before: middleware.Chain(a.gate.RequireScopes(types.ScopePolicyFreeze), a.gate.RequireAdmin()),
				Action: commands.PolicyFreeze,
			},
		},
	}
}

func (a *App) auditCommands() *cli.Command {
	return &cli.Command{
		Name:  "audit",
		Usage: "Audit log management",
		Commands: []*cli.Command{
			{
				Name:   "query",
				Usage:  "Query audit log",
				Before: a.gate.RequireScopes(types.ScopeAuditQuery),
				Action: commands.AuditQuery,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "actor", Usage: "Filter by actor ID"},
					&cli.StringFlag{Name: "resource", Usage: "Filter by resource ID"},
					&cli.StringFlag{Name: "action", Usage: "Filter by action"},
					&cli.TimestampFlag{Name: "start", Config: cli.TimestampConfig{Timezone: nil}, Usage: "Start time"},
					&cli.TimestampFlag{Name: "end", Config: cli.TimestampConfig{Timezone: nil}, Usage: "End time"},
					&cli.IntFlag{Name: "limit", Value: 100, Usage: "Result limit"},
				},
			},
			{
				Name:   "export",
				Usage:  "Export signed audit log",
				Before: a.gate.RequireScopes(types.ScopeAuditExport),
				Action: commands.AuditExport,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "Output file", Required: true},
					&cli.TimestampFlag{Name: "start", Config: cli.TimestampConfig{Timezone: nil}, Usage: "Start time"},
					&cli.TimestampFlag{Name: "end", Config: cli.TimestampConfig{Timezone: nil}, Usage: "End time"},
				},
			},
			{
				Name:   "verify",
				Usage:  "Verify audit log integrity",
				Before: a.gate.RequireScopes(types.ScopeAuditVerify),
				Action: commands.AuditVerify,
			},
		},
	}
}

func (a *App) shareCommands() *cli.Command {
	return &cli.Command{
		Name:  "share",
		Usage: "Secure sharing",
		Commands: []*cli.Command{
			{
				Name:   "create",
				Usage:  "Create a secure share",
				Before: a.gate.RequireScopes(types.ScopeShareCreate),
				Action: commands.ShareCreate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "type", Usage: "Share type: secret, file, folder, object, envelope", Required: true},
					&cli.StringFlag{Name: "resource", Aliases: []string{"r"}, Usage: "Resource name or ID", Required: true},
					&cli.StringFlag{Name: "recipient", Usage: "Recipient identity ID"},
					&cli.DurationFlag{Name: "expires-in", Usage: "Share expiration"},
					&cli.IntFlag{Name: "max-access", Usage: "Maximum access count"},
					&cli.BoolFlag{Name: "one-time", Usage: "One-time access only"},
				},
			},
			{
				Name:   "list",
				Usage:  "List shares",
				Before: a.gate.RequireScopes(types.ScopeShareRead),
				Action: commands.ShareList,
			},
			{
				Name:   "revoke",
				Usage:  "Revoke a share",
				Before: a.gate.RequireScopes(types.ScopeShareRevoke),
				Action: commands.ShareRevoke,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Share ID", Required: true},
				},
			},
			{
				Name:   "accept",
				Usage:  "Accept an incoming share",
				Before: a.gate.RequireScopes(types.ScopeShareAccept),
				Action: commands.ShareAccept,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Share ID", Required: true},
				},
			},
			{
				Name:   "export",
				Usage:  "Export share for offline transfer",
				Before: a.gate.RequireScopes(types.ScopeShareExport),
				Action: commands.ShareExport,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Share ID", Required: true},
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "Output file", Required: true},
				},
			},
			{
				Name:   "import",
				Usage:  "Import offline share package",
				Before: a.gate.RequireScopes(types.ScopeShareAccept),
				Action: commands.ShareImport,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "input", Aliases: []string{"i"}, Usage: "Input share package file", Required: true},
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "Optional output file for imported payload"},
					&cli.StringFlag{Name: "password", Usage: "Recipient password (if omitted, prompt securely)"},
				},
			},
			{
				Name:   "qr-generate",
				Usage:  "Generate QR code for share accept URL/payload",
				Before: a.gate.RequireScopes(types.ScopeShareExport),
				Action: commands.ShareQRGenerate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Share ID", Required: true},
					&cli.StringFlag{Name: "api-url", Usage: "Base API URL for online accept (e.g. https://host:9090)"},
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "Output PNG path (requires qrencode)"},
				},
			},
			{
				Name:   "qr-decode",
				Usage:  "Decode QR image payload",
				Before: a.gate.RequireScopes(types.ScopeShareRead),
				Action: commands.ShareQRDecode,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "input", Aliases: []string{"i"}, Usage: "Input QR image file (requires zbarimg)", Required: true},
				},
			},
			{
				Name:   "lan-send",
				Usage:  "Serve an encrypted share package over local LAN HTTP",
				Before: a.gate.RequireScopes(types.ScopeShareExport),
				Action: commands.ShareLANSend,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Share ID", Required: true},
					&cli.StringFlag{Name: "bind", Usage: "Listen address (e.g. 0.0.0.0:8787)", Value: "0.0.0.0:8787"},
					&cli.StringFlag{Name: "api-url", Usage: "Advertised base URL override (e.g. http://192.168.1.10:8787)"},
					&cli.DurationFlag{Name: "ttl", Usage: "How long server stays up waiting for receiver", Value: 10 * time.Minute},
					&cli.BoolFlag{Name: "qr", Usage: "Render URL as terminal QR if qrencode is installed"},
				},
			},
			{
				Name:   "lan-receive",
				Usage:  "Fetch an encrypted share package from LAN URL and import it",
				Before: a.gate.RequireScopes(types.ScopeShareAccept),
				Action: commands.ShareLANReceive,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "url", Usage: "Package URL from sender", Required: true},
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "Optional output file for imported payload"},
					&cli.StringFlag{Name: "password", Usage: "Recipient password (if omitted, prompt securely)"},
				},
			},
			{
				Name:   "webrtc-offer",
				Usage:  "Automatic WebRTC sender (optional share create + offer/answer handshake + transfer)",
				Before: a.gate.RequireScopes(types.ScopeShareExport),
				Action: commands.ShareWebRTCOffer,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Existing share ID (if omitted, create one using --type/--resource/--recipient)"},
					&cli.StringFlag{Name: "type", Usage: "Share type when creating: secret, file, folder, object, envelope"},
					&cli.StringFlag{Name: "resource", Usage: "Resource name/path/ID when creating share"},
					&cli.StringFlag{Name: "recipient", Usage: "Recipient identity ID when creating share"},
					&cli.StringFlag{Name: "bind", Usage: "Listen address (e.g. 0.0.0.0:8789)", Value: "0.0.0.0:8789"},
					&cli.StringFlag{Name: "api-url", Usage: "Advertised base URL override (e.g. http://192.168.1.10:8789)"},
					&cli.DurationFlag{Name: "ttl", Usage: "How long signaling endpoint is kept alive", Value: 10 * time.Minute},
					&cli.BoolFlag{Name: "qr", Usage: "Render receiver URL as terminal QR if qrencode is installed"},
					&cli.StringFlag{Name: "stun", Usage: "STUN URL", Value: "stun:stun.l.google.com:19302"},
					&cli.DurationFlag{Name: "timeout", Usage: "Overall timeout", Value: 5 * time.Minute},
				},
			},
			{
				Name:   "webrtc-answer",
				Usage:  "Automatic WebRTC receiver (fetch offer URL, send answer, receive/import package)",
				Before: a.gate.RequireScopes(types.ScopeShareAccept),
				Action: commands.ShareWebRTCAnswer,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "url", Usage: "Sender URL (from webrtc-offer output)", Required: true},
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "Optional output file for imported payload"},
					&cli.StringFlag{Name: "password", Usage: "Recipient password (if omitted, prompt securely)"},
					&cli.StringFlag{Name: "stun", Usage: "STUN URL", Value: "stun:stun.l.google.com:19302"},
					&cli.DurationFlag{Name: "timeout", Usage: "Overall timeout", Value: 5 * time.Minute},
				},
			},
		},
	}
}

/*
// DEPRECATED: Now using velocity backup commands
func (a *App) backupCommands() *cli.Command {
	return &cli.Command{
		Name:  "backup",
		Usage: "Backup and recovery",
		Commands: []*cli.Command{
			{
				Name:   "create",
				Usage:  "Create an encrypted backup",
				Before: a.gate.RequireScopes(types.ScopeBackupCreate),
				Action: commands.BackupCreate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "Output file", Required: true},
					&cli.StringSliceFlag{Name: "collections", Usage: "Collections to backup"},
				},
			},
			{
				Name:   "verify",
				Usage:  "Verify backup integrity",
				Before: a.gate.RequireScopes(types.ScopeBackupVerify),
				Action: commands.BackupVerify,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "input", Aliases: []string{"i"}, Usage: "Backup file", Required: true},
				},
			},
			{
				Name:   "restore",
				Usage:  "Restore from backup",
				Before: a.gate.RequireScopes(types.ScopeBackupRestore),
				Action: commands.BackupRestore,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "input", Aliases: []string{"i"}, Usage: "Backup file", Required: true},
					&cli.BoolFlag{Name: "dry-run", Usage: "Simulate restore without changes"},
				},
			},
			{
				Name:   "schedule",
				Usage:  "Schedule automated backups",
				Before: a.gate.RequireScopes(types.ScopeBackupSchedule),
				Action: commands.BackupSchedule,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "cron", Usage: "Cron expression", Required: true},
					&cli.StringFlag{Name: "destination", Usage: "Backup destination"},
				},
			},
		},
	}
}
*/

func (a *App) orgCommands() *cli.Command {
	return &cli.Command{
		Name:  "org",
		Usage: "Organization management",
		Commands: []*cli.Command{
			{
				Name:   "create",
				Usage:  "Create an organization",
				Before: a.gate.RequireScopes(types.ScopeOrgCreate),
				Action: commands.OrgCreate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Organization name", Required: true},
					&cli.StringFlag{Name: "slug", Usage: "URL-friendly slug"},
				},
			},
			{
				Name:   "list",
				Usage:  "List organizations",
				Before: a.gate.RequireScopes(types.ScopeOrgRead),
				Action: commands.OrgList,
			},
			{
				Name:   "invite",
				Usage:  "Invite member to organization",
				Before: a.gate.RequireScopes(types.ScopeOrgInvite),
				Action: commands.OrgInvite,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "email", Usage: "Email address", Required: true},
					&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
					&cli.StringFlag{Name: "role", Usage: "Role to assign"},
				},
			},
			{
				Name:   "teams",
				Usage:  "Team management",
				Before: a.gate.RequireScopes(types.ScopeOrgTeams),
				Commands: []*cli.Command{
					{
						Name:   "create",
						Usage:  "Create team",
						Action: commands.TeamCreate,
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
							&cli.StringFlag{Name: "name", Usage: "Team name", Required: true},
						},
					},
					{
						Name:   "list",
						Usage:  "List teams",
						Action: commands.TeamList,
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
						},
					},
				},
			},
			{
				Name:   "environments",
				Usage:  "Environment management",
				Before: a.gate.RequireScopes(types.ScopeOrgEnv),
				Commands: []*cli.Command{
					{
						Name:   "create",
						Usage:  "Create environment",
						Action: commands.EnvCreate,
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
							&cli.StringFlag{Name: "name", Usage: "Environment name", Required: true},
							&cli.StringFlag{Name: "type", Usage: "Environment type (e.g., production, staging)"},
							&cli.StringFlag{Name: "description", Usage: "Environment description"},
						},
					},
					{
						Name:   "list",
						Usage:  "List environments",
						Action: commands.EnvList,
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
						},
					},
				},
			},
			{
				Name:   "legal-hold",
				Usage:  "Enable legal hold mode",
				Before: middleware.Chain(a.gate.RequireScopes(types.ScopeOrgLegalHold), a.gate.RequireAdmin()),
				Action: commands.OrgLegalHold,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
				},
			},
			{
				Name:   "grant-auditor",
				Usage:  "Grant access to external auditor",
				Before: a.gate.RequireScopes(types.ScopeOrgAuditor),
				Action: commands.OrgGrantAuditor,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "auditor-id", Usage: "Auditor Identity ID", Required: true},
					&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
				},
			},
			{
				Name:   "create-vendor",
				Usage:  "Create vendor access",
				Before: a.gate.RequireScopes(types.ScopeVendorManage),
				Action: commands.OrgCreateVendor,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "Vendor Name", Required: true},
					&cli.StringFlag{Name: "vendor-id", Usage: "Vendor Identity ID", Required: true},
					&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
				},
			},
			{
				Name:  "transfer",
				Usage: "M&A resource transfer",
				Commands: []*cli.Command{
					{
						Name:   "init",
						Usage:  "Initiate transfer between organizations",
						Before: a.gate.RequireScopes(types.ScopeTransferInit),
						Action: commands.OrgTransferInit,
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "source-org", Usage: "Source organization ID", Required: true},
							&cli.StringFlag{Name: "target-org", Usage: "Target organization ID", Required: true},
						},
					},
					{
						Name:   "approve",
						Usage:  "Approve resource transfer",
						Before: a.gate.RequireScopes(types.ScopeTransferApprove),
						Action: commands.OrgTransferApprove,
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "id", Usage: "Transfer ID", Required: true},
						},
					},
					{
						Name:   "execute",
						Usage:  "Execute approved transfer",
						Before: a.gate.RequireScopes(types.ScopeTransferExecute),
						Action: commands.OrgTransferExecute,
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "id", Usage: "Transfer ID", Required: true},
						},
					},
				},
			},
		},
	}
}

func (a *App) incidentCommands() *cli.Command {
	return &cli.Command{
		Name:  "incident",
		Usage: "Incident response",
		Commands: []*cli.Command{
			{
				Name:   "declare",
				Usage:  "Declare a security incident",
				Before: a.gate.RequireScopes(types.ScopeIncidentDeclare),
				Action: commands.IncidentDeclare,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
					&cli.StringFlag{Name: "type", Usage: "Incident type", Required: true},
					&cli.StringFlag{Name: "severity", Usage: "Severity: critical, high, medium, low", Value: "high"},
					&cli.StringFlag{Name: "description", Aliases: []string{"d"}, Usage: "Description", Required: true},
				},
			},
			{
				Name:   "freeze",
				Usage:  "Freeze organization access",
				Before: a.gate.RequireScopes(types.ScopeIncidentFreeze),
				Action: commands.IncidentFreeze,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
					&cli.BoolFlag{Name: "disable", Usage: "Disable freeze (unfreeze)"},
				},
			},
			{
				Name:   "rotate",
				Usage:  "Emergency secret rotation",
				Before: a.gate.RequireScopes(types.ScopeIncidentRotate),
				Action: commands.IncidentRotate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
					&cli.BoolFlag{Name: "all", Usage: "Rotate all secrets"},
					&cli.StringSliceFlag{Name: "names", Usage: "Specific secrets to rotate"},
				},
			},
			{
				Name:   "export",
				Usage:  "Export incident evidence",
				Before: a.gate.RequireScopes(types.ScopeIncidentExport),
				Action: commands.IncidentExport,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Incident ID", Required: true},
					&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "Output file", Required: true},
				},
			},
			{
				Name:   "list",
				Usage:  "List security incidents",
				Before: a.gate.RequireScopes(types.ScopeIncidentTimeline),
				Action: commands.IncidentList,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
				},
			},
			{
				Name:   "timeline",
				Usage:  "View incident timeline",
				Before: a.gate.RequireScopes(types.ScopeIncidentTimeline),
				Action: commands.IncidentTimeline,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Incident ID", Required: true},
					&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
				},
			},
		},
	}
}

func (a *App) envelopeCommands() *cli.Command {
	return &cli.Command{
		Name:  "envelope",
		Usage: "Secure envelope management",
		Commands: []*cli.Command{
			{
				Name:   "create",
				Usage:  "Create a secure envelope",
				Before: a.gate.RequireScopes(types.ScopeEnvelopeCreate),
				Action: commands.EnvelopeCreate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "recipient", Aliases: []string{"r"}, Usage: "Recipient ID or Email", Required: true},
					&cli.StringSliceFlag{Name: "secret", Aliases: []string{"s"}, Usage: "Secrets to include (name:value or name)"},
					&cli.StringSliceFlag{Name: "file", Aliases: []string{"f"}, Usage: "Files to include (path)"},
					&cli.StringFlag{Name: "message", Aliases: []string{"m"}, Usage: "Message to include"},
					&cli.StringFlag{Name: "policy", Aliases: []string{"p"}, Usage: "Policy ID"},
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "Output file path", Required: true},
					&cli.DurationFlag{Name: "expires-in", Usage: "Expiration duration"},
					&cli.BoolFlag{Name: "require-mfa", Usage: "Require MFA to open"},
				},
			},
			{
				Name:   "open",
				Usage:  "Open a secure envelope",
				Before: a.gate.RequireScopes(types.ScopeEnvelopeOpen),
				Action: commands.EnvelopeOpen,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "file", Aliases: []string{"f"}, Usage: "Envelope file path", Required: true},
					&cli.BoolFlag{Name: "inspect", Usage: "Inspect metadata only"},
				},
			},
			{
				Name:   "verify",
				Usage:  "Verify envelope integrity",
				Before: a.gate.RequireScopes(types.ScopeEnvelopeVerify),
				Action: commands.EnvelopeVerify,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "file", Aliases: []string{"f"}, Usage: "Envelope file path", Required: true},
				},
			},
		},
	}
}

func (a *App) adminCommands() *cli.Command {
	return &cli.Command{
		Name:   "admin",
		Usage:  "Administrative operations",
		Before: a.gate.RequireAdmin(),
		Commands: []*cli.Command{
			{
				Name:   "users",
				Usage:  "User administration",
				Action: commands.AdminUsers,
			},
			{
				Name:   "system",
				Usage:  "System status and health",
				Action: commands.AdminSystem,
			},
			{
				Name:   "security",
				Usage:  "Global security settings",
				Action: commands.AdminSecurity,
			},
			{
				Name:   "server",
				Usage:  "Start the API server",
				Action: commands.AdminServer,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "addr", Usage: "Listen address", Value: ":9090"},
				},
			},
		},
	}
}

// Run runs the CLI application
func (a *App) Run(ctx context.Context, args []string) error {
	return a.cli.Run(ctx, args)
}

// Close closes the app and releases resources
func (a *App) Close() error {
	if a.velocityDB != nil {
		return a.velocityDB.Close()
	}
	return nil
}

func (a *App) sshCommands() *cli.Command {
	return &cli.Command{
		Name:  "ssh",
		Usage: "SSH profile and session management",
		Commands: []*cli.Command{
			{
				Name:   "create-profile",
				Usage:  "Create an SSH profile",
				Before: a.gate.RequireScopes(types.ScopeSSHProfile),
				Action: commands.SSHCreateProfile,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "Profile name", Required: true},
					&cli.StringFlag{Name: "host", Usage: "Host address", Required: true},
					&cli.StringFlag{Name: "user", Usage: "Username", Required: true},
					&cli.StringFlag{Name: "key-id", Usage: "Identity Key ID", Required: true},
				},
			},
			{
				Name:   "list-profiles",
				Usage:  "List SSH profiles",
				Before: a.gate.RequireScopes(types.ScopeSSHProfile),
				Action: commands.SSHListProfiles,
			},
			{
				Name:   "start",
				Usage:  "Start SSH session",
				Before: a.gate.RequireScopes(types.ScopeSSHConnect),
				Action: commands.SSHStartSession,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "profile-id", Usage: "Profile ID", Required: true},
				},
			},
		},
	}
}

func (a *App) cicdCommands() *cli.Command {
	return &cli.Command{
		Name:  "cicd",
		Usage: "CI/CD pipeline integration",
		Commands: []*cli.Command{
			{
				Name:   "create-pipeline",
				Usage:  "Register a pipeline identity",
				Before: a.gate.RequireScopes(types.ScopePipelineCreate),
				Action: commands.CICDCreatePipeline,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "Pipeline name", Required: true},
					&cli.StringFlag{Name: "provider", Usage: "Provider (github, gitlab, etc)", Required: true},
					&cli.StringFlag{Name: "repo", Usage: "Repository identifier", Required: true},
					&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
					&cli.StringSliceFlag{Name: "secret-patterns", Usage: "Secret patterns (e.g., prod/*)"},
				},
			},
			{
				Name:   "inject",
				Usage:  "Inject secrets into environment",
				Before: a.gate.RequireScopes(types.ScopePipelineInject),
				Action: commands.CICDInject,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "pipeline-id", Usage: "Pipeline ID", Required: true},
					&cli.StringFlag{Name: "env", Usage: "Environment name", Required: true},
					&cli.StringFlag{Name: "branch", Usage: "Git branch"},
				},
			},
		},
	}
}

func (a *App) execCommands() *cli.Command {
	return &cli.Command{
		Name:   "exec",
		Usage:  "Execute command with secrets",
		Before: a.gate.RequireScopes(types.ScopeExecRun),
		Action: commands.ExecRun,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "command", Usage: "Command to run", Required: true},
			&cli.StringSliceFlag{Name: "secret", Aliases: []string{"s"}, Usage: "Secret mapping ID:ENV_VAR or ID:ENV_VAR:file"},
			&cli.BoolFlag{Name: "all-secrets", Usage: "Load all secrets as environment variables"},
			&cli.StringFlag{Name: "prefix", Usage: "Load only secrets under prefix/folder as environment variables"},
			&cli.StringFlag{Name: "env", Usage: "Filter bulk-loaded secrets by environment"},
			&cli.StringFlag{Name: "env-prefix", Usage: "Prefix applied to generated environment variable names"},
			&cli.StringFlag{Name: "isolation", Usage: "Isolation level: auto (default), host, ns (Linux namespaces)", Value: "auto"},
			&cli.StringFlag{Name: "seccomp-profile", Usage: "Linux seccomp profile (e.g. strict); strict mode fails closed if unavailable"},
			&cli.BoolFlag{Name: "strict-sandbox", Usage: "Fail command if requested sandbox controls are unavailable"},
		},
	}
}

func (a *App) envCommand() *cli.Command {
	return &cli.Command{
		Name:   "env",
		Usage:  "Output a secret as an environment variable export",
		Before: a.gate.RequireScopes(types.ScopeSecretRead),
		Action: commands.Env,
	}
}

func (a *App) loadEnvCommand() *cli.Command {
	return &cli.Command{
		Name:   "load-env",
		Usage:  "Output all secrets as environment variable exports",
		Before: a.gate.RequireScopes(types.ScopeSecretList),
		Action: commands.LoadEnv,
	}
}

func (a *App) enrichCommand() *cli.Command {
	return &cli.Command{
		Name:   "enrich",
		Usage:  "Run a command with all secrets injected into environment",
		Before: a.gate.RequireScopes(types.ScopeSecretList),
		Action: commands.Enrich,
	}
}
func (a *App) monitoringCommands() *cli.Command {
	return &cli.Command{
		Name:  "monitoring",
		Usage: "System monitoring and behavior analysis",
		Commands: []*cli.Command{
			{
				Name:   "dashboard",
				Usage:  "Show monitoring dashboard",
				Before: a.gate.RequireScopes(types.ScopeAuditRead),
				Action: commands.MonitoringDashboard,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "period", Usage: "Time period (1h, 24h, 7d, 30d)", Value: "24h"},
				},
			},
			{
				Name:   "events",
				Usage:  "Query monitoring events",
				Before: a.gate.RequireScopes(types.ScopeAuditRead),
				Action: commands.MonitoringEvents,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "type", Usage: "Filter by event type"},
					&cli.StringFlag{Name: "actor", Usage: "Filter by actor ID"},
					&cli.IntFlag{Name: "limit", Usage: "Max events to show", Value: 20},
				},
			},
		},
	}
}

func (a *App) alertCommands() *cli.Command {
	return &cli.Command{
		Name:  "alert",
		Usage: "Alert management",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "List alerts",
				Before: a.gate.RequireScopes(types.ScopeAuditRead),
				Action: commands.AlertList,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "status", Usage: "Filter by status (open, acknowledged, resolved)"},
					&cli.StringFlag{Name: "severity", Usage: "Filter by severity"},
				},
			},
			{
				Name:   "rules",
				Usage:  "List alert rules",
				Before: a.gate.RequireScopes(types.ScopeAuditRead),
				Action: commands.AlertRules,
			},
			{
				Name:   "ack",
				Usage:  "Acknowledge an alert",
				Before: a.gate.RequireScopes(types.ScopeAuditRead),
				Action: commands.AlertAcknowledge,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Alert ID", Required: true},
				},
			},
			{
				Name:   "resolve",
				Usage:  "Resolve an alert",
				Before: a.gate.RequireScopes(types.ScopeAuditRead),
				Action: commands.AlertResolve,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Alert ID", Required: true},
				},
			},
		},
	}
}

func (a *App) complianceCommands() *cli.Command {
	return &cli.Command{
		Name:  "compliance",
		Usage: "Compliance reporting and policy enforcement",
		Commands: []*cli.Command{
			{
				Name:   "report",
				Usage:  "Generate compliance report",
				Before: a.gate.RequireScopes(types.ScopeComplianceReport),
				Action: commands.ComplianceReport,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "standard", Usage: "Compliance standard (e.g., SOC2, GDPR)", Required: true},
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "Output file", Required: true},
				},
			},
			{
				Name:   "frameworks",
				Usage:  "List available compliance frameworks",
				Action: commands.ComplianceListFrameworks,
			},
			{
				Name:   "score",
				Usage:  "Get compliance score",
				Action: commands.ComplianceGetScore,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "standard", Usage: "Compliance standard", Required: true},
					&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
				},
			},
			{
				Name:   "list-reports",
				Usage:  "List generated compliance reports",
				Action: commands.ComplianceListReports,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
				},
			},
			{
				Name:   "policy",
				Usage:  "Manage compliance policies",
				Before: a.gate.RequireScopes(types.ScopeCompliancePolicy),
				Commands: []*cli.Command{
					{Name: "list", Usage: "List policies", Action: commands.CompliancePolicyList},
					{Name: "create", Usage: "Create policy", Action: commands.CompliancePolicyCreate},
					{Name: "update", Usage: "Update policy", Action: commands.CompliancePolicyUpdate},
				},
			},
		},
	}
}

func (a *App) dlpCommands() *cli.Command {
	return &cli.Command{
		Name:  "dlp",
		Usage: "Data Loss Prevention",
		Commands: []*cli.Command{
			{
				Name:   "scan",
				Usage:  "Scan for sensitive data",
				Before: a.gate.RequireScopes(types.ScopeDLPScan),
				Action: commands.DLPScan,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "path", Usage: "Path to scan", Required: true},
					&cli.StringSliceFlag{Name: "rules", Usage: "DLP rules to apply"},
				},
			},
			{
				Name:   "rules",
				Usage:  "Manage DLP rules",
				Before: a.gate.RequireScopes(types.ScopeDLPRules),
				Commands: []*cli.Command{
					{Name: "list", Usage: "List rules", Action: commands.DLPRuleList},
					{
						Name:   "create",
						Usage:  "Create rule",
						Action: commands.DLPRuleCreate,
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "name", Usage: "Rule name", Required: true},
							&cli.StringFlag{Name: "description", Usage: "Rule description"},
							&cli.StringSliceFlag{Name: "patterns", Usage: "Regex patterns to match", Required: true},
							&cli.StringFlag{Name: "severity", Usage: "Severity: critical, high, medium, low", Value: "high"},
						},
					},
					{
						Name:   "delete",
						Usage:  "Delete rule",
						Action: commands.DLPRuleDelete,
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "id", Usage: "Rule ID", Required: true},
						},
					},
				},
			},
		},
	}
}
func (a *App) automationPipelineCommands() *cli.Command {
	return &cli.Command{
		Name:   "pipeline",
		Usage:  "Manage automation pipelines",
		Before: a.gate.RequireScopes(types.ScopeAutomationManage),
		Commands: []*cli.Command{
			{
				Name:   "apply",
				Usage:  "Apply a pipeline configuration",
				Action: commands.PipelineApply,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "file", Aliases: []string{"f"}, Usage: "JSON configuration file", Required: true},
				},
			},
			{
				Name:   "list",
				Usage:  "List automation pipelines",
				Action: commands.PipelineList,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Usage: "Organization ID"},
				},
			},
			{
				Name:   "trigger",
				Usage:  "Trigger an automation event",
				Action: commands.PipelineTrigger,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "event", Aliases: []string{"e"}, Usage: "Event name", Required: true},
					&cli.StringSliceFlag{Name: "param", Aliases: []string{"p"}, Usage: "Parameter (key=value)"},
				},
			},
		},
	}
}

/*
// DEPRECATED: Now using velocity folder commands
func (a *App) folderCommands() *cli.Command {
	return &cli.Command{
		Name:  "folder",
		Usage: "Folder encryption and management",
		Commands: []*cli.Command{
			{
				Name:   "lock",
				Usage:  "Lock and encrypt a folder",
				Before: a.gate.RequireScopes(types.ScopeFileUpload),
				Action: commands.FolderLock,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "path", Aliases: []string{"p"}, Usage: "Folder path to lock", Required: true},
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Name for locked folder in vault"},
				},
			},
			{
				Name:   "unlock",
				Usage:  "Unlock and decrypt a folder",
				Before: a.gate.RequireScopes(types.ScopeFileDownload),
				Action: commands.FolderUnlock,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Name of locked folder in vault", Required: true},
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "Output path for unlocked folder", Required: true},
				},
			},
			{
				Name:   "hide",
				Usage:  "Hide a folder (encrypt and remove original)",
				Before: a.gate.RequireScopes(types.ScopeFileUpload),
				Action: commands.FolderHide,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "path", Aliases: []string{"p"}, Usage: "Folder path to hide", Required: true},
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Name for hidden folder in vault"},
				},
			},
			{
				Name:   "show",
				Usage:  "Show a hidden folder (decrypt and restore)",
				Before: a.gate.RequireScopes(types.ScopeFileDownload),
				Action: commands.FolderShow,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Name of hidden folder in vault", Required: true},
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "Output path for restored folder", Required: true},
				},
			},
		},
	}
}
*/
