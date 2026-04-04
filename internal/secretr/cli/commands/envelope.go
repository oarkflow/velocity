package commands

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/audit"
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
				Name:     f,
				Data:     data,
				Type:     "application/x-tar-gzip",
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
		SenderID:        senderID,
		SenderPrivKey:   senderPriv,
		RecipientID:     types.ID(recipient),
		RecipientPubKey: recipPub,
		Secrets:         secretPayloads,
		Files:           filePayloads,
		Message:         message,
		PolicyID:        types.ID(policyID),
		Rules:           rules,
		ExpiresIn:       expiresIn,
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
		logEnvelopeAudit(ctx, c, "envelope_create_write_failed", optsEnvelopeID(env), false, map[string]any{
			"path":  outputFile,
			"error": err.Error(),
		})
		return err
	}

	sum := sha256.Sum256(data)
	logEnvelopeAudit(ctx, c, "envelope_create", env.ID, true, map[string]any{
		"path":   outputFile,
		"sha256": hex.EncodeToString(sum[:]),
	})

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
		logEnvelopeAudit(ctx, c, "envelope_open_read_failed", "", false, map[string]any{
			"path":  filePath,
			"error": err.Error(),
		})
		return err
	}

	var env types.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		logEnvelopeAudit(ctx, c, "envelope_open_invalid_format", "", false, map[string]any{
			"path":  filePath,
			"error": err.Error(),
		})
		return fmt.Errorf("invalid envelope format: %w", err)
	}

	if inspect {
		logEnvelopeAudit(ctx, c, "envelope_inspect", env.ID, true, map[string]any{
			"path": filePath,
		})
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
		Time:        time.Now(),
		MFAVerified: session != nil && session.MFAVerified,
		TrustScore:  1.0,
	}

	// 4. Open
	fmt.Printf("Attempting to open envelope %s...\n", env.ID)

	password, err := promptPassword("Enter your password to open envelope: ")
	if err != nil {
		logEnvelopeAudit(ctx, c, "envelope_open_password_failed", env.ID, false, map[string]any{
			"path":  filePath,
			"error": err.Error(),
		})
		return err
	}

	// Get Decryption Key (X25519 Private Key)
	recipPriv, err := c.Identity.GetEncryptionPrivateKey(ctx, c.CurrentIdentityID(), password)
	if err != nil {
		logEnvelopeAudit(ctx, c, "envelope_open_key_failed", env.ID, false, map[string]any{
			"path":  filePath,
			"error": err.Error(),
		})
		return fmt.Errorf("failed to get decryption key: %w", err)
	}

	payload, err := engine.Open(ctx, envelope.OpenOptions{
		Envelope:         &env,
		RecipientID:      env.Header.RecipientID,
		RecipientPrivKey: recipPriv,
		SenderPublicKey:  senderPublicKeyForEnvelope(ctx, c, &env),
		ResolveActorPublicKey: func(actorID types.ID) ([]byte, error) {
			idn, e := c.Identity.GetIdentity(ctx, actorID)
			if e != nil {
				return nil, e
			}
			return idn.PublicKey, nil
		},
		Context: currCtx,
	})

	if err != nil {
		logEnvelopeAudit(ctx, c, "envelope_open_denied", env.ID, false, map[string]any{
			"path":  filePath,
			"error": err.Error(),
		})
		return err
	}

	// Record recipient open in custody chain and persist updated envelope.
	signerPriv, sigErr := c.Identity.GetPrivateKey(ctx, c.CurrentIdentityID(), password)
	if sigErr == nil {
		if recErr := engine.RecordAction(&env, types.ActionEnvelopeOpen, c.CurrentIdentityID(), signerPriv, "local"); recErr == nil {
			updated, mErr := json.MarshalIndent(&env, "", "  ")
			if mErr == nil {
				_ = os.WriteFile(filePath, updated, 0600)
			}
		}
	}
	payloadHash := sha256.Sum256(payloadDataForAudit(payload))
	dependencyRefs := envelope.BuildDependencyRefs(&env, payload)
	logEnvelopeAudit(ctx, c, "envelope_open", env.ID, true, map[string]any{
		"path":            filePath,
		"payload_hash":    hex.EncodeToString(payloadHash[:]),
		"dependency_refs": dependencyRefs,
		"recipient_only":  c.CurrentIdentityID() == env.Header.RecipientID,
	})
	logEnvelopeAudit(ctx, c, "envelope_access_chain", env.ID, true, map[string]any{
		"path":           filePath,
		"actor_id":       c.CurrentIdentityID(),
		"recipient_id":   env.Header.RecipientID,
		"recipient_only": c.CurrentIdentityID() == env.Header.RecipientID,
		"custody_length": len(env.Custody),
	})
	logEnvelopeAudit(ctx, c, "envelope_dependency_chain", env.ID, true, map[string]any{
		"path":            filePath,
		"dependency_refs": dependencyRefs,
	})
	logEnvelopeAudit(ctx, c, "envelope_custody_chain", env.ID, true, map[string]any{
		"path":           filePath,
		"custody_length": len(env.Custody),
	})
	logEnvelopeAudit(ctx, c, "envelope_event_log", env.ID, true, map[string]any{
		"path":  filePath,
		"event": "open_success",
	})

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
		logEnvelopeAudit(ctx, nil, "envelope_verify_read_failed", "", false, map[string]any{
			"path":  filePath,
			"error": err.Error(),
		})
		return err
	}

	var env types.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		logEnvelopeAudit(ctx, nil, "envelope_verify_invalid_format", "", false, map[string]any{
			"path":  filePath,
			"error": err.Error(),
		})
		return fmt.Errorf("invalid envelope format: %w", err)
	}

	policyEngine := policy.NewEngine(policy.EngineConfig{})
	engine := envelope.NewEngine(policyEngine)
	defer engine.Close()

	if err := engine.VerifyChain(&env); err != nil {
		logEnvelopeAudit(ctx, nil, "envelope_verify_failed", env.ID, false, map[string]any{
			"path":  filePath,
			"error": err.Error(),
		})
		return fmt.Errorf("verification failed: %w", err)
	}
	sum := sha256.Sum256(data)
	logEnvelopeAudit(ctx, nil, "envelope_verify", env.ID, true, map[string]any{
		"path":   filePath,
		"sha256": hex.EncodeToString(sum[:]),
	})

	success("Envelope Integrity Verified")
	fmt.Printf("Chain length: %d\n", len(env.Custody))
	return nil
}

func payloadDataForAudit(payload *types.EnvelopePayload) []byte {
	if payload == nil {
		return nil
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return b
}

func optsEnvelopeID(env *types.Envelope) types.ID {
	if env == nil {
		return ""
	}
	return env.ID
}

func logEnvelopeAudit(ctx context.Context, c *client.Client, action string, envelopeID types.ID, success bool, details map[string]any) {
	var cliClient *client.Client
	if c != nil {
		cliClient = c
	} else {
		var err error
		cliClient, err = client.GetClient()
		if err != nil || cliClient == nil {
			return
		}
		defer cliClient.Close()
	}
	if cliClient.Audit == nil {
		return
	}
	actorID := cliClient.CurrentIdentityID()
	var resourceID *types.ID
	if envelopeID != "" {
		r := envelopeID
		resourceID = &r
	}
	if details == nil {
		details = map[string]any{}
	}
	if envelopeID != "" {
		details["envelope_id"] = envelopeID
	}
	details["audit_family"] = "envelope"
	_ = cliClient.Audit.Log(ctx, audit.AuditEventInput{
		Type:         "envelope",
		Action:       action,
		ActorID:      actorID,
		ActorType:    "identity",
		ResourceID:   resourceID,
		ResourceType: "envelope",
		Success:      success,
		Details:      details,
	})
}

func EnvelopeLock(ctx context.Context, cmd *cli.Command) error {
	filePath := cmd.String("file")
	if strings.TrimSpace(filePath) == "" {
		return fmt.Errorf("file is required")
	}
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	env, data, err := loadEnvelopeFile(filePath)
	if err != nil {
		return err
	}
	env.Header.BusinessRules.RequireMFA = true
	if env.Header.BusinessRules.RequiredTrustLevel < 0.8 {
		env.Header.BusinessRules.RequiredTrustLevel = 0.8
	}
	appendEnvelopeCustody(env, types.ActionEnvelopeReject, c.CurrentIdentityID(), "lockdown")
	if err := saveEnvelopeFile(filePath, env); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	logEnvelopeAudit(ctx, c, "envelope_lock", env.ID, true, map[string]any{
		"path":   filePath,
		"sha256": hex.EncodeToString(sum[:]),
	})
	success("Envelope locked: %s", env.ID)
	return nil
}

func EnvelopeUnlock(ctx context.Context, cmd *cli.Command) error {
	filePath := cmd.String("file")
	if strings.TrimSpace(filePath) == "" {
		return fmt.Errorf("file is required")
	}
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	env, _, err := loadEnvelopeFile(filePath)
	if err != nil {
		return err
	}
	env.Header.BusinessRules.RequireMFA = false
	appendEnvelopeCustody(env, types.ActionEnvelopeSend, c.CurrentIdentityID(), "unlock")
	if err := saveEnvelopeFile(filePath, env); err != nil {
		return err
	}
	logEnvelopeAudit(ctx, c, "envelope_unlock", env.ID, true, map[string]any{"path": filePath})
	success("Envelope unlocked: %s", env.ID)
	return nil
}

func EnvelopeACL(ctx context.Context, cmd *cli.Command) error {
	filePath := cmd.String("file")
	if strings.TrimSpace(filePath) == "" {
		return fmt.Errorf("file is required")
	}
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	env, _, err := loadEnvelopeFile(filePath)
	if err != nil {
		return err
	}
	ipRanges := cmd.StringSlice("allow-ip")
	requireMFA := cmd.Bool("require-mfa")
	trust := cmd.Float64("trust-level")
	if len(ipRanges) > 0 {
		env.Header.BusinessRules.AllowedIPRanges = ipRanges
	}
	env.Header.BusinessRules.RequireMFA = requireMFA
	if trust > 0 {
		env.Header.BusinessRules.RequiredTrustLevel = trust
	}
	appendEnvelopeCustody(env, "acl_update", c.CurrentIdentityID(), "acl")
	if err := saveEnvelopeFile(filePath, env); err != nil {
		return err
	}
	logEnvelopeAudit(ctx, c, "envelope_acl", env.ID, true, map[string]any{
		"path":      filePath,
		"allow_ips": ipRanges,
		"mfa":       env.Header.BusinessRules.RequireMFA,
		"trust":     env.Header.BusinessRules.RequiredTrustLevel,
	})
	success("Envelope ACL updated: %s", env.ID)
	return nil
}

func loadEnvelopeFile(path string) (*types.Envelope, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var env types.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, nil, err
	}
	return &env, data, nil
}

func saveEnvelopeFile(path string, env *types.Envelope) error {
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func appendEnvelopeCustody(env *types.Envelope, action string, actor types.ID, location string) {
	if env == nil {
		return
	}
	now := types.Now()
	var prev []byte
	if n := len(env.Custody); n > 0 {
		prev = env.Custody[n-1].Hash
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("%x|%s|%s|%d|%s", prev, action, actor, now, location)))
	env.Custody = append(env.Custody, types.CustodyEntry{
		Hash:      h[:],
		PrevHash:  append([]byte(nil), prev...),
		Action:    action,
		Category:  "custody",
		Outcome:   "success",
		ActorID:   actor,
		Timestamp: now,
		Location:  location,
	})
}

func senderPublicKeyForEnvelope(ctx context.Context, c *client.Client, env *types.Envelope) []byte {
	if c == nil || env == nil {
		return nil
	}
	idn, err := c.Identity.GetIdentity(ctx, env.Header.SenderID)
	if err != nil || idn == nil {
		return nil
	}
	return idn.PublicKey
}
