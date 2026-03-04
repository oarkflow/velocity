package commands

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/envelope"
	"github.com/oarkflow/velocity/internal/secretr/core/policy"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

// Envelope commands

func EnvelopeCreate(ctx context.Context, cmd *cli.Command) error {
	recipient := cmd.String("recipient")
	secrets := cmd.StringSlice("secret")
	files := cmd.StringSlice("file")
	message := cmd.String("message")
	policyID := cmd.String("policy")
	outputFile := cmd.String("output")
	expiresIn := cmd.Duration("expires-in")
	requireMFA := cmd.Bool("require-mfa")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	// 1. Prepare items
	secretPayloads := make([]types.SecretPayload, 0)
	for _, s := range secrets {
		parts := strings.SplitN(s, ":", 2)
		name := parts[0]
		var val []byte
		if len(parts) > 1 {
			val = []byte(parts[1])
		} else {
			val = []byte("placeholder-value")
		}
		secretPayloads = append(secretPayloads, types.SecretPayload{
			Name:  name,
			Value: val,
			Type:  "generic",
		})
	}

	filePayloads := make([]types.FilePayload, 0)
	for _, f := range files {
		// Check if it's a folder
		info, err := os.Stat(f)
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", f, err)
		}

		if info.IsDir() {
			// Archive folder
			data, err := createFolderArchive(f)
			if err != nil {
				return fmt.Errorf("failed to archive folder %s: %w", f, err)
			}
			filePayloads = append(filePayloads, types.FilePayload{
				Name: f,
				Data: data,
				Type: "application/x-tar-gzip",
				Metadata: types.Metadata{"is_folder": true},
			})
		} else {
			// Regular file
			data, err := os.ReadFile(f)
			if err != nil {
				return fmt.Errorf("failed to read file %s: %w", f, err)
			}
			filePayloads = append(filePayloads, types.FilePayload{
				Name: f,
				Data: data,
				Type: "application/octet-stream",
			})
		}
	}

	// 2. Initialize Engine
	policyEngine := policy.NewEngine(policy.EngineConfig{})
	engine := envelope.NewEngine(policyEngine)
	defer engine.Close()

	// 3. Sender Identity & Keys
	senderID := c.CurrentIdentityID()
	password, err := promptPassword("Enter your password to sign envelope: ")
	if err != nil {
		return err
	}
	senderPriv, err := c.Identity.GetPrivateKey(ctx, senderID, password)
	if err != nil {
		return fmt.Errorf("failed to get private key: %w", err)
	}

	// 4. Recipient Public Key (Encryption Key)
	recipIdentity, err := c.Identity.GetIdentity(ctx, types.ID(recipient))
	if err != nil {
		return fmt.Errorf("failed to find recipient %s: %w", recipient, err)
	}

	encPubStr, ok := recipIdentity.Metadata["encryption_public_key"].(string)
	if !ok {
		return fmt.Errorf("recipient %s does not have an encryption key (created before feature enabled?)", recipient)
	}
	recipPub, err := base64.StdEncoding.DecodeString(encPubStr)
	if err != nil {
		return fmt.Errorf("invalid encryption key for recipient: %w", err)
	}

	// 5. Create Envelope
	rules := types.BusinessRules{
		RequireMFA: requireMFA,
	}

	env, err := engine.Create(ctx, envelope.CreateOptions{
		SenderID:      senderID,
		SenderPrivKey: senderPriv,
		RecipientID:   types.ID(recipient),
		RecipientPubKey: recipPub,
		Secrets:       secretPayloads,
		Files:         filePayloads,
		Message:       message,
		PolicyID:      types.ID(policyID),
		Rules:         rules,
		ExpiresIn:     expiresIn,
	})

	if err != nil {
		return err
	}

	// 6. Save to file
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputFile, data, 0600); err != nil {
		return err
	}

	success("Envelope created: %s", outputFile)
	info("ID: %s", env.ID)
	return nil
}

func EnvelopeOpen(ctx context.Context, cmd *cli.Command) error {
	filePath := cmd.String("file")
	inspect := cmd.Bool("inspect")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	// 1. Load File
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	var env types.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("invalid envelope format: %w", err)
	}

	if inspect {
		outputTable(env.Header)
		fmt.Println("\nCustody Chain:")
		outputTable(env.Custody)
		return nil
	}

	// 2. Initialize Engine
	policyEngine := policy.NewEngine(policy.EngineConfig{})
	engine := envelope.NewEngine(policyEngine)
	defer engine.Close()

	// 3. Current Context
	session, _ := c.Identity.GetCurrentSession(ctx)
	currCtx := envelope.Context{
		Time: time.Now(),
		MFAVerified: session != nil && session.MFAVerified,
		TrustScore: 1.0,
	}

	// 4. Open
	fmt.Printf("Attempting to open envelope %s...\n", env.ID)

	password, err := promptPassword("Enter your password to open envelope: ")
	if err != nil {
		return err
	}

	// Get Decryption Key (X25519 Private Key)
	recipPriv, err := c.Identity.GetEncryptionPrivateKey(ctx, c.CurrentIdentityID(), password)
	if err != nil {
		return fmt.Errorf("failed to get decryption key: %w", err)
	}

	payload, err := engine.Open(ctx, envelope.OpenOptions{
		Envelope: &env,
		RecipientID: env.Header.RecipientID,
		RecipientPrivKey: recipPriv,
		Context: currCtx,
	})

	if err != nil {
		return err
	}

	success("Envelope Opened!")
	if payload.Message != "" {
		fmt.Printf("Message: %s\n", payload.Message)
	}
	for _, s := range payload.Secrets {
		fmt.Printf("Secret: %s = %s\n", s.Name, string(s.Value)) // Show value
	}
	for _, f := range payload.Files {
		if isFolder, ok := f.Metadata["is_folder"].(bool); ok && isFolder {
			fmt.Printf("Folder: %s (archived, %d bytes)\n", f.Name, len(f.Data))
			// Optionally extract folder here
		} else {
			fmt.Printf("File: %s (%d bytes)\n", f.Name, len(f.Data))
		}
	}

	return nil
}

func EnvelopeVerify(ctx context.Context, cmd *cli.Command) error {
	filePath := cmd.String("file")

	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	var env types.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("invalid envelope format: %w", err)
	}

	policyEngine := policy.NewEngine(policy.EngineConfig{})
	engine := envelope.NewEngine(policyEngine)
	defer engine.Close()

	if err := engine.VerifyChain(&env); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	success("Envelope Integrity Verified")
	fmt.Printf("Chain length: %d\n", len(env.Custody))
	return nil
}
