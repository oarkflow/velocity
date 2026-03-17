package commands

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/backup"
	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// Backup commands

func BackupCreate(ctx context.Context, cmd *cli.Command) error {
	outputPath := cmd.String("output")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.RequireScope(types.ScopeBackupCreate); err != nil {
		return err
	}

	password, err := promptPassword("Enter password to encrypt backup: ")
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

	// Derive encryption key
	salt, _ := crypto.NewEngine("").GenerateSalt()
	key, err := crypto.NewEngine("").DeriveKey([]byte(password), salt, crypto.KeySize256)
	if err != nil {
		return err
	}
	defer key.Free()

	// Open output file
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Helper: write salt to file first (prefix)
	if _, err := f.Write(salt); err != nil {
		return err
	}

	// Create backup of everything
	bck, err := c.Backup.CreateBackup(ctx, backup.CreateBackupOptions{
		Type:          "full",
		EncryptionKey: key.Bytes(),
		CreatorID:     c.CurrentIdentityID(),
		Output:        f,
	})
	if err != nil {
		return err
	}
	success("Backup created: %s (ID: %s)", outputPath, bck.ID)
	return nil
}

func BackupVerify(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")
	inputPath := cmd.String("input")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	// Read file
	fileData, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	if len(fileData) < 32 {
		return fmt.Errorf("invalid backup file")
	}
	// salt is prefix, encryptedData follows. Verify checks integrity hash.
	encryptedData := fileData[32:]

	res, err := c.Backup.VerifyBackup(ctx, types.ID(id), encryptedData)
	if err != nil {
		return err
	}

	if res.Verified {
		success("Backup verified: %s", inputPath)
	} else {
		warning("Backup verification failed: %s", res.Error)
		return fmt.Errorf("verification failed")
	}
	return nil
}

func BackupRestore(ctx context.Context, cmd *cli.Command) error {
	id := cmd.String("id")
	inputPath := cmd.String("input")

	if !confirm("Restore from backup? This will overwrite data.") {
		return nil
	}

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	password, err := promptPassword("Enter backup password: ")
	if err != nil {
		return err
	}

	// Read file
	fileData, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	if len(fileData) < 32 {
		return fmt.Errorf("invalid backup file")
	}
	salt := fileData[:32]
	encryptedData := fileData[32:]

	// Derive key
	key, err := crypto.NewEngine("").DeriveKey([]byte(password), salt, crypto.KeySize256)
	if err != nil {
		return err
	}
	defer key.Free()

	res, err := c.Backup.RestoreBackup(ctx, backup.RestoreOptions{
		BackupID:      types.ID(id),
		DecryptionKey: key.Bytes(),
		EncryptedData: encryptedData,
	})
	if err != nil {
		return err
	}

	if res.Success {
		success("Restored %d items from %s", res.RestoredCount, inputPath)
	} else {
		warning("Restore completed with errors: %v", res.Errors)
	}
	return nil
}

func BackupSchedule(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}

	if err := c.RequireScope(types.ScopeBackupSchedule); err != nil {
		return err
	}

	cronExpr := strings.TrimSpace(cmd.String("cron"))
	if cronExpr == "" {
		return fmt.Errorf("cron expression is required")
	}
	// Minimal validation: 5 or 6 cron fields.
	fields := strings.Fields(cronExpr)
	if len(fields) != 5 && len(fields) != 6 {
		return fmt.Errorf("invalid cron expression: expected 5 or 6 fields, got %d", len(fields))
	}

	destination := strings.TrimSpace(cmd.String("destination"))
	retentionDays := 30
	if destination != "" {
		// Convention: "path[:retentionDays]" for CLI compatibility without adding new flags.
		parts := strings.Split(destination, ":")
		if len(parts) > 1 {
			if n, parseErr := strconv.Atoi(parts[len(parts)-1]); parseErr == nil && n > 0 {
				retentionDays = n
			}
		}
	}

	orgID := c.CurrentIdentityID()
	if orgID == "" {
		orgID = "default"
	}

	schedule, err := c.Backup.CreateSchedule(ctx, backup.CreateScheduleOptions{
		OrgID:         orgID,
		Type:          "full",
		CronExpr:      cronExpr,
		RetentionDays: retentionDays,
		CreatorID:     c.CurrentIdentityID(),
		Destination:   destination,
	})
	if err != nil {
		return err
	}

	success("Backup schedule created: id=%s cron=%s destination=%s retention_days=%d", schedule.ID, schedule.CronExpr, schedule.Destination, schedule.RetentionDays)
	return nil
}
