package commands

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oarkflow/velocity"
	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/files"
	"github.com/oarkflow/velocity/internal/secretr/core/share"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// Share commands

func ShareCreate(ctx context.Context, cmd *cli.Command) error {
	shareType := strings.ToLower(strings.TrimSpace(cmd.String("type")))
	resource := cmd.String("resource")
	recipient := cmd.String("recipient")
	expiresIn := cmd.Duration("expires-in")
	maxAccess := cmd.Int("max-access")
	oneTime := cmd.Bool("one-time")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireScope(types.ScopeShareCreate); err != nil {
		return err
	}

	resourceType, resourceID, err := resolveShareResourceForCreate(ctx, c, shareType, resource)
	if err != nil {
		return err
	}

	recipientID := types.ID(recipient)
	var recipientPtr *types.ID
	if strings.TrimSpace(recipient) != "" {
		recipientPtr = &recipientID
	}

	shr, err := c.Share.CreateShare(ctx, share.CreateShareOptions{
		Type:        resourceType,
		ResourceID:  resourceID,
		RecipientID: recipientPtr,
		ExpiresIn:   expiresIn,
		MaxAccess:   maxAccess,
		CreatorID:   c.CurrentIdentityID(),
		OneTime:     oneTime,
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
	defer c.Close()

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
	defer c.Close()

	if err := c.Share.RevokeShare(ctx, types.ID(id), c.CurrentIdentityID()); err != nil {
		return err
	}
	success("Share revoked")
	return nil
}

func ShareAccept(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RequireScope(types.ScopeShareAccept); err != nil {
		return err
	}
	access, err := c.Share.AccessShare(ctx, types.ID(id), c.CurrentIdentityID())
	if err != nil {
		return err
	}
	success("Share accepted: %s", access.ShareID)
	info("Resource: %s (%s)", access.ResourceID, access.Type)
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
	typ := strings.ToLower(strings.TrimSpace(shr.Type))
	switch typ {
	case "secret":
		if v, found, err := getVelocitySecretValue(string(shr.ResourceID)); err != nil {
			return nil, fmt.Errorf("failed to resolve shared secret payload: %w", err)
		} else if found {
			return []byte(v), nil
		}
		mfaVerified := false
		if sess := c.CurrentSession(); sess != nil {
			mfaVerified = sess.MFAVerified
		}
		val, err := c.Secrets.Get(ctx, string(shr.ResourceID), c.CurrentIdentityID(), mfaVerified)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve shared secret payload: %w", err)
		}
		return val, nil
	case "file", "object":
		if data, ok := getVelocityObjectData(c, string(shr.ResourceID)); ok {
			return data, nil
		}
		var buf bytes.Buffer
		err := c.Files.Download(ctx, string(shr.ResourceID), files.DownloadOptions{
			AccessorID:  c.CurrentIdentityID(),
			MFAVerified: c.CurrentSession() != nil && c.CurrentSession().MFAVerified,
		}, &buf)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve shared file payload: %w", err)
		}
		return buf.Bytes(), nil
	case "folder":
		db := velocityDB()
		if db == nil {
			return nil, fmt.Errorf("folder sharing requires velocity database")
		}
		data, err := buildFolderArchive(db, string(shr.ResourceID), string(c.CurrentIdentityID()))
		if err != nil {
			return nil, fmt.Errorf("failed to resolve shared folder payload: %w", err)
		}
		return data, nil
	default:
		return nil, fmt.Errorf("unsupported share type for export: %s", shr.Type)
	}
}

func resolveShareResourceForCreate(ctx context.Context, c *client.Client, shareType, resource string) (string, types.ID, error) {
	shareType = strings.ToLower(strings.TrimSpace(shareType))
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return "", "", fmt.Errorf("resource is required")
	}
	switch shareType {
	case "secret":
		if _, found, err := getVelocitySecretValue(resource); err != nil {
			return "", "", fmt.Errorf("failed to validate secret resource %q: %w", resource, err)
		} else if found {
			return "secret", types.ID(resource), nil
		}
		mfaVerified := false
		if sess := c.CurrentSession(); sess != nil {
			mfaVerified = sess.MFAVerified
		}
		if _, err := c.Secrets.Get(ctx, resource, c.CurrentIdentityID(), mfaVerified); err != nil {
			return "", "", fmt.Errorf("secret resource not found or not accessible: %s", resource)
		}
		return "secret", types.ID(resource), nil
	case "file", "object":
		if ok := hasVelocityObject(resource); ok {
			return "object", types.ID(resource), nil
		}
		if _, err := c.Files.GetMetadata(ctx, resource); err != nil {
			return "", "", fmt.Errorf("file/object resource not found: %s", resource)
		}
		return "file", types.ID(resource), nil
	case "folder":
		db := velocityDB()
		if db == nil {
			return "", "", fmt.Errorf("folder sharing requires velocity database")
		}
		if _, err := db.GetFolder(resource); err != nil {
			return "", "", fmt.Errorf("folder resource not found: %s", resource)
		}
		return "folder", types.ID(resource), nil
	default:
		return "", "", fmt.Errorf("unsupported share type %q (expected: secret, file, folder, object)", shareType)
	}
}

func velocityDB() *velocity.DB {
	adapter := client.GetGlobalAdapter()
	if adapter == nil {
		return nil
	}
	return adapter.GetVelocityDB()
}

func hasVelocityObject(path string) bool {
	db := velocityDB()
	if db == nil {
		return false
	}
	_, err := db.GetObjectMetadata(path)
	return err == nil
}

func getVelocityObjectData(c *client.Client, path string) ([]byte, bool) {
	db := velocityDB()
	if db == nil {
		return nil, false
	}
	data, _, err := db.GetObject(path, string(c.CurrentIdentityID()))
	if err != nil {
		return nil, false
	}
	return data, true
}

func buildFolderArchive(db *velocity.DB, folderPath, user string) ([]byte, error) {
	objects, err := db.ListObjects(velocity.ObjectListOptions{
		Folder:    folderPath,
		Recursive: true,
		MaxKeys:   100000,
	})
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	base := strings.TrimPrefix(filepath.ToSlash(folderPath), "/")
	for _, obj := range objects {
		data, _, err := db.GetObject(obj.Path, user)
		if err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
		objPath := filepath.ToSlash(obj.Path)
		name := strings.TrimPrefix(objPath, "/")
		if base != "" {
			name = strings.TrimPrefix(name, base)
			name = strings.TrimPrefix(name, "/")
		}
		if name == "" {
			name = filepath.Base(objPath)
		}
		hdr := &tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
