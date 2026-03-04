package commands

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/files"
	"github.com/oarkflow/velocity/internal/secretr/core/share"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// Share commands

func ShareCreate(ctx context.Context, cmd *cli.Command) error {
	resource := cmd.String("resource")
	recipient := cmd.String("recipient")
	expiresIn := cmd.Duration("expires-in")
	maxAccess := cmd.Int("max-access")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.RequireScope(types.ScopeShareCreate); err != nil {
		return err
	}

	recipientID := types.ID(recipient)

	shr, err := c.Share.CreateShare(ctx, share.CreateShareOptions{
		ResourceID:  types.ID(resource),
		RecipientID: &recipientID,
		ExpiresIn:   expiresIn,
		MaxAccess:   maxAccess,
		CreatorID:   c.CurrentIdentityID(),
		Type:        "standard", // Default type
	})
	if err != nil {
		return err
	}

	success("Share created: %s", shr.ID)
	return nil
}

func ShareList(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}

	shares, err := c.Share.ListShares(ctx, share.ListSharesOptions{
		CreatorID: c.CurrentIdentityID(),
	})
	if err != nil {
		return err
	}
	return output(cmd, shares)
}

func ShareRevoke(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.Share.RevokeShare(ctx, types.ID(id), c.CurrentIdentityID()); err != nil {
		return err
	}
	success("Share revoked")
	return nil
}

func ShareAccept(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")
	// Accepting likely involves using the share token
	_ = id
	info("Accept share logic placeholder")
	return nil
}

func ShareExport(ctx context.Context, cmd *cli.Command) error {
	id := types.ID(strings.TrimSpace(cmd.String("id")))
	outputPath := strings.TrimSpace(cmd.String("output"))

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	if err := c.RequireScope(types.ScopeShareExport); err != nil {
		return err
	}

	shr, err := c.Share.GetShare(ctx, id)
	if err != nil {
		return err
	}

	recipientPubKey := shr.RecipientKey
	if len(recipientPubKey) == 0 && shr.RecipientID != nil {
		identity, identityErr := c.Identity.GetIdentity(ctx, *shr.RecipientID)
		if identityErr != nil {
			return fmt.Errorf("could not resolve recipient public key: %w", identityErr)
		}
		recipientPubKey = identity.PublicKey
	}
	if len(recipientPubKey) == 0 {
		return fmt.Errorf("recipient public key is required for offline export")
	}

	resourceData, err := resolveShareResourceData(ctx, c, shr)
	if err != nil {
		return err
	}

	pkg, err := c.Share.CreateOfflinePackage(ctx, share.OfflinePackageOptions{
		ShareID:         shr.ID,
		ResourceData:    resourceData,
		RecipientPubKey: recipientPubKey,
	})
	if err != nil {
		return err
	}

	exported, err := c.Share.ExportOfflinePackage(ctx, pkg.ID)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, exported, 0600); err != nil {
		return err
	}

	success("Share exported: %s (package_id=%s)", outputPath, pkg.ID)
	return nil
}

func resolveShareResourceData(ctx context.Context, c *client.Client, shr *types.Share) ([]byte, error) {
	switch shr.Type {
	case "secret":
		mfaVerified := false
		if sess := c.CurrentSession(); sess != nil {
			mfaVerified = sess.MFAVerified
		}
		val, err := c.Secrets.Get(ctx, string(shr.ResourceID), c.CurrentIdentityID(), mfaVerified)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve shared secret payload: %w", err)
		}
		return val, nil
	case "file":
		var buf bytes.Buffer
		err := c.Files.Download(ctx, string(shr.ResourceID), files.DownloadOptions{
			AccessorID:  c.CurrentIdentityID(),
			MFAVerified: c.CurrentSession() != nil && c.CurrentSession().MFAVerified,
		}, &buf)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve shared file payload: %w", err)
		}
		return buf.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported share type for export: %s", shr.Type)
	}
}
