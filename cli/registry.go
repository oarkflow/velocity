package cli

import (
	"context"
	"fmt"
	"sync"

	"github.com/urfave/cli/v3"
)

type DefaultFlagValidator struct {
	mu             sync.RWMutex
	validators     map[string]func(interface{}) error
	flagPermissions map[string]Permission
}

func NewDefaultFlagValidator() *DefaultFlagValidator {
	return &DefaultFlagValidator{
		validators:      make(map[string]func(interface{}) error),
		flagPermissions: make(map[string]Permission),
	}
}

func (v *DefaultFlagValidator) AddValidator(flagName string, validator func(interface{}) error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.validators[flagName] = validator
}

func (v *DefaultFlagValidator) SetFlagPermission(flagName string, permission Permission) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.flagPermissions[flagName] = permission
}

func (v *DefaultFlagValidator) Validate(flagName string, value interface{}) error {
	v.mu.RLock()
	validator, exists := v.validators[flagName]
	v.mu.RUnlock()

	if !exists {
		return nil
	}
	return validator(value)
}

func (v *DefaultFlagValidator) RequiredPermission(flagName string) Permission {
	v.mu.RLock()
	perm, exists := v.flagPermissions[flagName]
	v.mu.RUnlock()

	if !exists {
		return PermissionPublic
	}
	return perm
}

type DefaultPermissionChecker struct {
	mu        sync.RWMutex
	userRoles map[string]Permission
}

func NewDefaultPermissionChecker() *DefaultPermissionChecker {
	return &DefaultPermissionChecker{
		userRoles: make(map[string]Permission),
	}
}

func (c *DefaultPermissionChecker) SetUserRole(user string, role Permission) {
	c.mu.Lock()
	c.userRoles[user] = role
	c.mu.Unlock()
}

func (c *DefaultPermissionChecker) HasPermission(user string, required Permission) bool {
	if required == PermissionPublic {
		return true
	}

	// Empty user defaults to "default" which has User permissions
	if user == "" {
		user = "default"
	}

	permissions := map[Permission]int{
		PermissionPublic: 0,
		PermissionUser:   1,
		PermissionAdmin:  2,
		PermissionOwner:  3,
	}

	c.mu.RLock()
	userRole, exists := c.userRoles[user]
	c.mu.RUnlock()

	// If user is not explicitly registered, deny access
	// This is more secure than granting default access
	if !exists {
		return false
	}

	return permissions[userRole] >= permissions[required]
}

type Registry struct {
	mu                sync.RWMutex
	commands          []CommandBuilder
	middlewares       []MiddlewareFunc
	permissionChecker PermissionChecker
	flagValidator     FlagValidator
}

func NewRegistry() *Registry {
	return &Registry{
		commands:    make([]CommandBuilder, 0),
		middlewares: make([]MiddlewareFunc, 0),
	}
}

func (r *Registry) Register(builder CommandBuilder) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, existing := range r.commands {
		if existing.Name() == builder.Name() {
			return fmt.Errorf("command '%s' already registered", builder.Name())
		}
	}
	r.commands = append(r.commands, builder)
	return nil
}

func (r *Registry) RegisterMiddleware(middleware MiddlewareFunc) {
	r.mu.Lock()
	r.middlewares = append(r.middlewares, middleware)
	r.mu.Unlock()
}

func (r *Registry) SetPermissionChecker(checker PermissionChecker) {
	r.mu.Lock()
	r.permissionChecker = checker
	r.mu.Unlock()
}

func (r *Registry) SetFlagValidator(validator FlagValidator) {
	r.mu.Lock()
	r.flagValidator = validator
	r.mu.Unlock()
}

func (r *Registry) GetCommands() []*cli.Command {
	r.mu.RLock()
	defer r.mu.RUnlock()

	commands := make([]*cli.Command, 0, len(r.commands))
	for _, builder := range r.commands {
		cmd := r.buildCommandWithMiddleware(builder)
		commands = append(commands, cmd)
	}
	return commands
}

//
// ──────────────────────────────────────────────────────────────────────────────
//   COMMAND WRAPPING
// ──────────────────────────────────────────────────────────────────────────────
//

func (r *Registry) buildCommandWithMiddleware(builder CommandBuilder) *cli.Command {
	cmd := builder.Build()
	originalAction := cmd.Action

	cmd.Action = func(ctx context.Context, c *cli.Command) error {
		// Try to get user from command context, then from root
		currentUser := c.String("user")
		if currentUser == "" {
			// Try to get from root command
			if root := c.Root(); root != nil {
				currentUser = root.String("user")
			}
		}
		// If still empty, use "default" as fallback (not anonymous)
		if currentUser == "" {
			currentUser = "default"
		}

		// Permission check on command
		if r.permissionChecker != nil {
			required := builder.RequiredPermission()
			if !r.permissionChecker.HasPermission(currentUser, required) {
				return fmt.Errorf("permission denied: %s permission required", required)
			}
		}

		// Validate flags
		if r.flagValidator != nil {
			for _, flag := range builder.Flags() {
				flagName := flag.Names()[0]
				value := c.Value(flagName)

				// Check flag permission
				flagPerm := r.flagValidator.RequiredPermission(flagName)
				if flagPerm != "" && flagPerm != PermissionPublic {
					if !r.permissionChecker.HasPermission(currentUser, flagPerm) {
						return fmt.Errorf("permission denied for flag '%s': %s permission required", flagName, flagPerm)
					}
				}

				// Validate flag values
				if err := r.flagValidator.Validate(flagName, value); err != nil {
					return fmt.Errorf("invalid flag '%s': %w", flagName, err)
				}
			}
		}

		// Call original action
		if originalAction != nil {
			return originalAction(ctx, c)
		}

		return nil
	}

	// build subcommands
	if len(builder.Subcommands()) > 0 {
		subCmds := make([]*cli.Command, 0, len(builder.Subcommands()))
		for _, subBuilder := range builder.Subcommands() {
			subCmd := r.buildCommandWithMiddleware(subBuilder)
			subCmds = append(subCmds, subCmd)
		}
		cmd.Commands = subCmds
	}

	return cmd
}
