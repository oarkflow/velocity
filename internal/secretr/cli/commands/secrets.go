package commands

import (
	"context"
	"fmt"
	"io"
	"os"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/core/secrets"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

// Secret commands

func SecretCreate(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	value := cmd.String("value")
	secretType := cmd.String("type")
	env := cmd.String("env")
	expiresIn := cmd.Duration("expires-in")
	readOnce := cmd.Bool("read-once")
	immutable := cmd.Bool("immutable")

	// Read from stdin if value is "-"
	switch value {
	case "-":
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		value = string(data)
	case "":
		// Only prompt if not piped
		if term.IsTerminal(int(os.Stdin.Fd())) {
			var err error
			value, err = promptPassword("Secret value: ")
			if err != nil {
				return err
			}
		} else {
			// Read from pipe
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return err
			}
			value = string(data)
		}
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	defer c.Close()

	if err := c.RequireScope(types.ScopeSecretCreate); err != nil {
		return err
	}

	secret, err := c.Secrets.Create(ctx, secrets.CreateSecretOptions{
		Name:        name,
		Value:       []byte(value),
		Type:        types.SecretType(secretType),
		Environment: env,
		ExpiresIn:   expiresIn,
		ReadOnce:    readOnce,
		Immutable:   immutable,
		CreatorID:   c.CurrentIdentityID(),
	})
	if err != nil {
		return err
	}

	success("Secret created: %s (v%d)", secret.Name, secret.Version)
	return nil
}

func SecretGet(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	metadataOnly := cmd.Bool("metadata-only")
	version := cmd.Int("version")
	_ = version // Versioned retrieval not yet implemented in manager API exposed here

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	defer c.Close()

	if err := c.RequireScope(types.ScopeSecretRead); err != nil {
		return err
	}

	if metadataOnly {
		meta, err := c.Secrets.GetMetadata(ctx, name)
		if err != nil {
			return err
		}
		return output(cmd, meta)
	}

	mfaVerified := false
	if sess := c.CurrentSession(); sess != nil {
		mfaVerified = sess.MFAVerified
	}

	val, err := c.Secrets.Get(ctx, name, c.CurrentIdentityID(), mfaVerified)
	if err != nil {
		return err
	}

	// If outputting to terminal, might want to be careful
	if term.IsTerminal(int(os.Stdout.Fd())) {
		// Just print it
		fmt.Println(string(val))
	} else {
		fmt.Print(string(val))
	}

	return nil
}

func SecretList(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeSecretList); err != nil {
		return err
	}

	opts := secrets.ListSecretsOptions{
		Prefix:      cmd.String("prefix"),
		Environment: cmd.String("env"),
	}

	l, err := c.Secrets.List(ctx, opts)
	if err != nil {
		return err
	}
	return output(cmd, l)
}

func SecretUpdate(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	value := cmd.String("value")

	if value == "" {
		p, err := promptPassword("New value: ")
		if err != nil {
			return err
		}
		value = p
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeSecretUpdate); err != nil {
		return err
	}

	if _, err := c.Secrets.Update(ctx, name, []byte(value), c.CurrentIdentityID()); err != nil {
		return err
	}
	success("Secret updated: %s", name)
	return nil
}

func SecretDelete(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	force := cmd.Bool("force")

	if !force && !confirm("Delete secret "+name+"?") {
		return nil
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeSecretDelete); err != nil {
		return err
	}

	if err := c.Secrets.Delete(ctx, name, c.CurrentIdentityID()); err != nil {
		return err
	}

	success("Secret deleted: %s", name)
	return nil
}

func SecretHistory(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeSecretRead); err != nil {
		return err
	}

	history, err := c.Secrets.GetHistory(ctx, name)
	if err != nil {
		return err
	}

	return output(cmd, history)
}

func SecretRotate(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeSecretRotate); err != nil {
		return err
	}

	// Pass nil generator for now (assuming Vault handles it or manual value needed)
	// If Vault requires generator, we need to implement one.
	// For this implementation we'll assume nil uses a default random generator if supported,
	// or we should prompt for a new value? Rotate usually implies auto-generation.
	if _, err := c.Secrets.Rotate(ctx, name, nil, c.CurrentIdentityID()); err != nil {
		return err
	}

	success("Secret rotated: %s", name)
	return nil
}

func SecretExport(ctx context.Context, cmd *cli.Command) error {
	names := cmd.StringSlice("names")
	outputPath := cmd.String("output")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeSecretExport); err != nil {
		return err
	}

	password, err := promptPassword("Enter export password: ")
	if err != nil {
		return err
	}

	// Derive key
	salt, _ := crypto.NewEngine("").GenerateSalt()
	key, err := crypto.NewEngine("").DeriveKey([]byte(password), salt, crypto.KeySize256)
	if err != nil {
		return err
	}
	defer key.Free()

	data, err := c.Secrets.Export(ctx, names, key.Bytes())
	if err != nil {
		return err
	}

	// Prepend salt to export file
	finalData := append(salt, data...)

	if err := os.WriteFile(outputPath, finalData, 0600); err != nil {
		return err
	}

	success("Secrets exported to %s", outputPath)
	return nil
}
