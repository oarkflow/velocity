package cli

import (
	"context"

	"github.com/urfave/cli/v3"
)

// Permission represents a permission level
type Permission string

const (
	PermissionPublic Permission = "public"
	PermissionUser   Permission = "user"
	PermissionAdmin  Permission = "admin"
	PermissionOwner  Permission = "owner"
)

// CommandContext provides access to CLI context and database
type CommandContext struct {
	*cli.Command
	DB          interface{} // Database instance
	CurrentUser string
	UserRole    Permission
}

// CommandExecutor defines the interface for command execution
type CommandExecutor interface {
	Execute(ctx context.Context, cmd *CommandContext) error
}

// CommandBuilder defines the interface for building commands
type CommandBuilder interface {
	Name() string
	Description() string
	Usage() string
	Category() string
	Flags() []cli.Flag
	Subcommands() []CommandBuilder
	RequiredPermission() Permission
	Build() *cli.Command
}

// MiddlewareFunc is a function that wraps command execution
type MiddlewareFunc func(next CommandExecutor) CommandExecutor

// PermissionChecker checks if a user has required permissions
type PermissionChecker interface {
	HasPermission(user string, required Permission) bool
}

// FlagValidator validates flag values
type FlagValidator interface {
	Validate(flagName string, value interface{}) error
	RequiredPermission(flagName string) Permission
}

// CommandRegistry manages command registration
type CommandRegistry interface {
	Register(builder CommandBuilder) error
	RegisterMiddleware(middleware MiddlewareFunc)
	GetCommands() []*cli.Command
	SetPermissionChecker(checker PermissionChecker)
	SetFlagValidator(validator FlagValidator)
}
