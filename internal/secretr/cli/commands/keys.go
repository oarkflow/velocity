package commands

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/core/keys"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// Key commands

func KeyGenerate(ctx context.Context, cmd *cli.Command) error {
	keyType := cmd.String("type")
	purpose := cmd.String("purpose")
	expiresIn := cmd.Duration("expires-in")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	defer c.Close()

	if err := c.RequireScope(types.ScopeKeyGenerate); err != nil {
		return err
	}

	key, err := c.Keys.GenerateKey(ctx, keys.GenerateKeyOptions{
		Type:      types.KeyType(keyType),
		Purpose:   types.KeyPurpose(purpose),
		ExpiresIn: expiresIn,
	})
	if err != nil {
		return err
	}

	success("Key generated: %s (ID: %s)", key.Algorithm, key.ID)
	return nil
}

func KeyList(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeKeyRead); err != nil {
		return err
	}

	keyList, err := c.Keys.ListKeys(ctx, keys.ListKeysOptions{})
	if err != nil {
		return err
	}

	return output(cmd, keyList)
}

func KeyRotate(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeKeyRotate); err != nil {
		return err
	}

	newKey, err := c.Keys.RotateKey(ctx, types.ID(id))
	if err != nil {
		return err
	}

	success("Key rotated: %s -> %s", id, newKey.ID)
	return nil
}

func KeyDestroy(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")
	force := cmd.Bool("force")

	if !force && !confirm("Destroy key "+id+"? This is irreversible.") {
		return nil
	}

	password, err := promptPassword("Enter password to confirm destruction: ")
	if err != nil {
		return err
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeKeyDestroy); err != nil {
		return err
	}

	// key destruction requires a signed proof using the private key
	privKey, err := c.Identity.GetPrivateKey(ctx, c.CurrentIdentityID(), password)
	if err != nil {
		return fmt.Errorf("failed to get private key for signature: %w", err)
	}

	proof, err := c.Keys.DestroyKey(ctx, types.ID(id), c.CurrentIdentityID(), privKey)
	if err != nil {
		return err
	}

	success("Key destroyed with proof: %s", proof.Signature)
	return nil
}

func KeyExport(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")
	outputPath := cmd.String("output")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeKeyExport); err != nil {
		return err
	}

	// Prompt for password to encrypt the exported key
	password, err := promptPassword("Enter password to encrypt export: ")
	if err != nil {
		return err
	}
	confirmSdk, err := promptPassword("Confirm password: ")
	if err != nil {
		return err
	}
	if password != confirmSdk {
		return fmt.Errorf("passwords do not match")
	}

	// Derive encryption key
	salt, _ := crypto.NewEngine("").GenerateSalt()
	key, err := crypto.NewEngine("").DeriveKey([]byte(password), salt, crypto.KeySize256)
	if err != nil {
		return err
	}
	defer key.Free()

	data, err := c.Keys.ExportKey(ctx, types.ID(id), key.Bytes())
	if err != nil {
		return err
	}

	// Prepend salt to data for import
	fullData := append(salt, data...)

	if err := os.WriteFile(outputPath, fullData, 0600); err != nil {
		return err
	}

	success("Key exported to %s", outputPath)
	return nil
}

func KeyImport(ctx context.Context, cmd *cli.Command) error {
	inputPath := cmd.String("input")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeKeyImport); err != nil {
		return err
	}

	password, err := promptPassword("Enter password to decrypt export: ")
	if err != nil {
		return err
	}

	fullData, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	if len(fullData) < 32 { // salt size
		return fmt.Errorf("invalid export file format")
	}

	salt := fullData[:32]
	data := fullData[32:]

	// Derive encryption key
	key, err := crypto.NewEngine("").DeriveKey([]byte(password), salt, crypto.KeySize256)
	if err != nil {
		return err
	}
	defer key.Free()

	importedKey, err := c.Keys.ImportKey(ctx, data, key.Bytes())
	if err != nil {
		return err
	}

	success("Key imported: %s", importedKey.ID)
	return nil
}

func KeySplit(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")
	shares := cmd.Int("shares")
	threshold := cmd.Int("threshold")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeKeyRecovery); err != nil {
		return err
	}

	keyShares, err := c.Keys.SplitKey(ctx, types.ID(id), int(shares), int(threshold))
	if err != nil {
		return err
	}

	// Output shares (in a real scenario, these would be distributed securely)
	// For CLI, we might print them or save to files
	fmt.Printf("Key split into %d shares (threshold: %d):\n", shares, threshold)
	for i, share := range keyShares {
		fmt.Printf("Share %d: %s\n", i+1, base64.StdEncoding.EncodeToString(share.Data))
	}
	return nil
}
