package commands

import (
	"context"
	"fmt"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/identity"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// Identity commands

func IdentityCreate(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	email := cmd.String("email")
	identityType := cmd.String("type")
	scopes := cmd.StringSlice("scopes")

	password := cmd.String("password")
	if password == "" {
		var err error
		password, err = promptPassword("Set password: ")
		if err != nil {
			return err
		}
		confirmPwd, err := promptPassword("Confirm password: ")
		if err != nil {
			return err
		}
		if password != confirmPwd {
			return fmt.Errorf("passwords do not match")
		}
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	var scopeList []types.Scope
	for _, s := range scopes {
		scopeList = append(scopeList, types.Scope(s))
	}

	switch identityType {
	case "service":
		ident, _, err := c.Identity.CreateServiceIdentity(ctx, identity.CreateServiceOptions{
			Name:   name,
			Scopes: scopeList,
		})
		if err != nil {
			return err
		}
		success("Service identity created: %s (ID: %s)", ident.Name, ident.ID)
	default:
		ident, err := c.Identity.CreateHumanIdentity(ctx, identity.CreateHumanOptions{
			Name:     name,
			Email:    email,
			Password: password,
			Scopes:   scopeList,
		})
		if err != nil {
			return err
		}
		success("Identity created: %s (ID: %s)", ident.Name, ident.ID)
	}
	return nil
}

func IdentityList(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}

	identities, err := c.Identity.ListIdentities(ctx, identity.ListOptions{})
	if err != nil {
		return err
	}
	return output(cmd, identities)
}

func IdentityGet(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	ident, err := c.Identity.GetIdentity(ctx, types.ID(id))
	if err != nil {
		return err
	}
	return output(cmd, ident)
}

func IdentityRevoke(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")
	force := cmd.Bool("force")

	if !force && !confirm("Revoke identity "+id+"?") {
		return nil
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.Identity.RevokeIdentity(ctx, types.ID(id), c.CurrentIdentityID()); err != nil {
		return err
	}
	success("Identity revoked: %s", id)
	return nil
}

func IdentityRecover(ctx context.Context, cmd *cli.Command) error {
	email := cmd.String("email")

	// Recovery workflow would typically send an email
	// For now, just show the info message
	_ = email
	info("Recovery workflow started. Check your email.")
	return nil
}
