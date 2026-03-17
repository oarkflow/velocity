package cli

import (
	"context"

	"github.com/urfave/cli/v3"
)

// BaseCommand provides common command functionality
type BaseCommand struct {
	name               string
	description        string
	usage              string
	category           string
	flags              []cli.Flag
	subcommands        []CommandBuilder
	requiredPermission Permission
	action             func(ctx context.Context, cmd *cli.Command) error
}

// NewBaseCommand creates a new base command
func NewBaseCommand(name, description string) *BaseCommand {
	return &BaseCommand{
		name:               name,
		description:        description,
		flags:              make([]cli.Flag, 0),
		subcommands:        make([]CommandBuilder, 0),
		requiredPermission: PermissionUser,
	}
}

func (b *BaseCommand) Name() string {
	return b.name
}

func (b *BaseCommand) Description() string {
	return b.description
}

func (b *BaseCommand) Usage() string {
	return b.usage
}

func (b *BaseCommand) Category() string {
	return b.category
}

func (b *BaseCommand) Flags() []cli.Flag {
	return b.flags
}

func (b *BaseCommand) Subcommands() []CommandBuilder {
	return b.subcommands
}

func (b *BaseCommand) RequiredPermission() Permission {
	return b.requiredPermission
}

func (b *BaseCommand) SetUsage(usage string) *BaseCommand {
	b.usage = usage
	return b
}

func (b *BaseCommand) SetCategory(category string) *BaseCommand {
	b.category = category
	return b
}

func (b *BaseCommand) SetPermission(perm Permission) *BaseCommand {
	b.requiredPermission = perm
	return b
}

func (b *BaseCommand) AddFlag(flag cli.Flag) *BaseCommand {
	b.flags = append(b.flags, flag)
	return b
}

func (b *BaseCommand) AddFlags(flags ...cli.Flag) *BaseCommand {
	b.flags = append(b.flags, flags...)
	return b
}

func (b *BaseCommand) AddSubcommand(subcommand CommandBuilder) *BaseCommand {
	b.subcommands = append(b.subcommands, subcommand)
	return b
}

func (b *BaseCommand) SetAction(action func(ctx context.Context, cmd *cli.Command) error) *BaseCommand {
	b.action = action
	return b
}

func (b *BaseCommand) Build() *cli.Command {
	cmd := &cli.Command{
		Name:        b.name,
		Usage:       b.usage,
		Description: b.description,
		Category:    b.category,
		Flags:       b.flags,
		Action:      b.action,
	}

	// Build subcommands
	if len(b.subcommands) > 0 {
		subCmds := make([]*cli.Command, 0, len(b.subcommands))
		for _, subBuilder := range b.subcommands {
			subCmds = append(subCmds, subBuilder.Build())
		}
		cmd.Commands = subCmds
	}

	return cmd
}
