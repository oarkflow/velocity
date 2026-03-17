// Package commands provides velocity-integrated commands for secretr
package commands

import (
	"context"
	"fmt"

	"github.com/oarkflow/velocity"
	velocitycli "github.com/oarkflow/velocity/cli"
	velocitycommands "github.com/oarkflow/velocity/cli/commands"
	"github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/types"
	cliflag "github.com/urfave/cli/v3"
)

// VelocityCommandsWrapper wraps velocity commands with secretr integration
type VelocityCommandsWrapper struct {
	adapter *cli.VelocityAdapter
	db      *velocity.DB
}

// NewVelocityCommandsWrapper creates a new wrapper
func NewVelocityCommandsWrapper(adapter *cli.VelocityAdapter, db *velocity.DB) *VelocityCommandsWrapper {
	return &VelocityCommandsWrapper{
		adapter: adapter,
		db:      db,
	}
}

// GetFileCommands returns velocity file commands integrated with secretr
func (w *VelocityCommandsWrapper) GetFileCommands() velocitycli.CommandBuilder {
	// Use velocity's object commands for file management
	return velocitycommands.ObjectCommands(w.db)
}

// GetFolderCommands returns velocity folder commands integrated with secretr
func (w *VelocityCommandsWrapper) GetFolderCommands() velocitycli.CommandBuilder {
	return velocitycommands.FolderCommands(w.db)
}

// GetSecretCommands returns velocity secret commands integrated with secretr
func (w *VelocityCommandsWrapper) GetSecretCommands() velocitycli.CommandBuilder {
	return velocitycommands.SecretCommands(w.db)
}

// GetBackupCommands returns velocity backup commands integrated with secretr
func (w *VelocityCommandsWrapper) GetBackupCommands() velocitycli.CommandBuilder {
	return velocitycommands.BackupCommand(w.db)
}

// GetDataCommands returns velocity data import/export commands
func (w *VelocityCommandsWrapper) GetDataCommands() velocitycli.CommandBuilder {
	return velocitycommands.DataCommands(w.db)
}

// GetExportCommands returns velocity export commands
func (w *VelocityCommandsWrapper) GetExportCommands() velocitycli.CommandBuilder {
	return velocitycommands.ExportCommand(w.db)
}

// GetImportCommands returns velocity import commands
func (w *VelocityCommandsWrapper) GetImportCommands() velocitycli.CommandBuilder {
	return velocitycommands.ImportCommand(w.db)
}

// WrapVelocityCommand wraps a velocity command to work with secretr's permission system
func WrapVelocityCommand(cmd *cliflag.Command, requiredScope string) *cliflag.Command {
	originalAction := cmd.Action

	cmd.Action = func(ctx context.Context, c *cliflag.Command) error {
		// Set user from current session for velocity commands
		client, err := cli.GetClient()
		if err == nil && client != nil {
			if userID := client.CurrentIdentityID(); userID != "" {
				// Set the user flag value for velocity commands to use
				c.Root().Set("user", string(userID))
			}
		}

		// Check secretr permissions if required scope is set
		if requiredScope != "" {
			if err != nil {
				return err
			}

			if err := client.RequireScope(types.Scope(requiredScope)); err != nil {
				return err
			}
		}

		// Execute the original velocity command
		if originalAction != nil {
			return originalAction(ctx, c)
		}
		return nil
	}

	return cmd
}

// ConvertVelocityCommandToSecretsCommand converts a velocity CommandBuilder to a CLI command
func ConvertVelocityCommandToSecretsCommand(builder velocitycli.CommandBuilder, scopeMapping map[string]types.Scope) *cliflag.Command {
	cmd := builder.Build()

	// Add scope-based permission checking if needed
	if len(scopeMapping) > 0 {
		originalAction := cmd.Action

		cmd.Action = func(ctx context.Context, c *cliflag.Command) error {
			// Set user from current session for velocity commands
			client, err := cli.GetClient()
			if err == nil && client != nil {
				if userID := client.CurrentIdentityID(); userID != "" {
					// Set the user flag value for velocity commands to use
					c.Root().Set("user", string(userID))
				}
			}

			// Find the required scope for this command
			var requiredScope types.Scope
			if scope, exists := scopeMapping[cmd.Name]; exists {
				requiredScope = scope
			}

			// Check permissions
			if requiredScope != "" {
				if err != nil {
					return fmt.Errorf("failed to get client: %w", err)
				}

				if err := client.RequireScope(types.Scope(requiredScope)); err != nil {
					return err
				}
			}

			// Execute original action
			if originalAction != nil {
				return originalAction(ctx, c)
			}
			return nil
		}
	}

	// Process subcommands recursively
	if len(cmd.Commands) > 0 {
		for i, subCmd := range cmd.Commands {
			cmd.Commands[i] = addScopeCheckToCommand(subCmd, scopeMapping)
		}
	}

	return cmd
}

// addScopeCheckToCommand adds scope checking to a command
func addScopeCheckToCommand(cmd *cliflag.Command, scopeMapping map[string]types.Scope) *cliflag.Command {
	originalAction := cmd.Action

	if originalAction != nil {
		cmd.Action = func(ctx context.Context, c *cliflag.Command) error {
			// Get client and current user
			client, err := cli.GetClient()
			if err == nil && client != nil {
				currentUserID := client.CurrentIdentityID()
				if currentUserID != "" {
					// For commands that access resources, check if shared
					c.Root().Set("user", string(currentUserID))
				}
			}

			// Find the required scope for this command
			var requiredScope types.Scope
			if scope, exists := scopeMapping[cmd.Name]; exists {
				requiredScope = scope
			}

			// Check permissions
			if requiredScope != "" {
				if err != nil {
					return fmt.Errorf("failed to get client: %w", err)
				}

				if err := client.RequireScope(types.Scope(requiredScope)); err != nil {
					return err
				}
			}

			// Execute original action
			return originalAction(ctx, c)
		}
	}

	// Process subcommands recursively
	if len(cmd.Commands) > 0 {
		for i, subCmd := range cmd.Commands {
			cmd.Commands[i] = addScopeCheckToCommand(subCmd, scopeMapping)
		}
	}

	return cmd
}

// GetFileScopeMappings returns scope mappings for file commands
func GetFileScopeMappings() map[string]types.Scope {
	return map[string]types.Scope{
		"upload":   types.ScopeFileUpload,
		"put":      types.ScopeFileUpload,
		"download": types.ScopeFileDownload,
		"get":      types.ScopeFileDownload,
		"list":     types.ScopeFileList,
		"ls":       types.ScopeFileList,
		"delete":   types.ScopeFileDelete,
		"rm":       types.ScopeFileDelete,
		"view":     types.ScopeFileDownload,
		"preview":  types.ScopeFileDownload,
	}
}

// GetFolderScopeMappings returns scope mappings for folder commands
func GetFolderScopeMappings() map[string]types.Scope {
	return map[string]types.Scope{
		"lock":   types.ScopeFileUpload,
		"unlock": types.ScopeFileDownload,
		"hide":   types.ScopeFileUpload,
		"show":   types.ScopeFileDownload,
		"list":   types.ScopeFileList,
		"view":   types.ScopeFileDownload,
	}
}

// GetSecretScopeMappings returns scope mappings for secret commands
func GetSecretScopeMappings() map[string]types.Scope {
	return map[string]types.Scope{
		"set":    types.ScopeSecretCreate,
		"get":    types.ScopeSecretRead,
		"list":   types.ScopeSecretList,
		"delete": types.ScopeSecretDelete,
		"rotate": types.ScopeSecretRotate,
	}
}

// GetBackupScopeMappings returns scope mappings for backup commands
func GetBackupScopeMappings() map[string]types.Scope {
	return map[string]types.Scope{
		"create":   types.ScopeBackupCreate,
		"backup":   types.ScopeBackupCreate,
		"restore":  types.ScopeBackupRestore,
		"verify":   types.ScopeBackupVerify,
		"list":     types.ScopeBackupCreate,
		"schedule": types.ScopeBackupSchedule,
	}
}

// GetExportScopeMappings returns scope mappings for export commands
func GetExportScopeMappings() map[string]types.Scope {
	return map[string]types.Scope{
		"export": types.ScopeSecretRead,
	}
}

// GetImportScopeMappings returns scope mappings for import commands
func GetImportScopeMappings() map[string]types.Scope {
	return map[string]types.Scope{
		"import": types.ScopeSecretCreate,
	}
}
