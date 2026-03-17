package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// Audit commands

func AuditQuery(ctx context.Context, cmd *cli.Command) error {
	action := cmd.String("action")
	actor := cmd.String("actor")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	events, err := c.Audit.Query(ctx, audit.QueryOptions{
		Action:  action,
		ActorID: types.ID(actor),
		Limit:   100,
	})
	if err != nil {
		return err
	}
	return output(cmd, events)
}

func AuditExport(ctx context.Context, cmd *cli.Command) error {
	outputPath := cmd.String("output")

	c, err := client.GetClient()
	if err != nil {
		return err
	}

	data, err := c.Audit.Export(ctx, audit.ExportOptions{
		Limit:      1000,
		ExporterID: c.CurrentIdentityID(),
		EndTime:    time.Now(),
	})
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return err
	}

	success("Audit log exported to %s", outputPath)
	return nil
}

func AuditVerify(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}

	storeOK, err := c.Audit.VerifyIntegrity(ctx)
	if err != nil {
		return err
	}
	ledgerOK, err := c.Audit.VerifyLedgerIntegrity(ctx)
	if err != nil {
		return err
	}
	proof, err := c.Audit.GetChainProof(ctx)
	if err != nil {
		return err
	}

	if storeOK && ledgerOK {
		success("Audit log integrity verified")
	} else {
		warning("Audit log integrity verification FAILED")
	}
	info("Hash chain (event store): %t", storeOK)
	info("Merkle ledger chain: %t", ledgerOK)
	if proof != nil {
		info("Ledger blocks: %d", proof.TotalBlocks)
		info("Latest block index: %d", proof.LatestBlockIndex)
		if proof.LatestBlockID != "" {
			info("Latest block id: %s", proof.LatestBlockID)
		}
		if proof.LatestBlockHash != "" {
			info("Latest block hash: %s", proof.LatestBlockHash)
		}
	}
	return nil
}

func AuditCustody(ctx context.Context, cmd *cli.Command) error {
	resource := cmd.String("resource")
	if resource == "" {
		return fmt.Errorf("resource is required (format: type:id)")
	}
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	parts := strings.SplitN(resource, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		return fmt.Errorf("resource must be in type:id format")
	}
	resourceID := types.ID(parts[1])
	events, err := c.Audit.Query(ctx, audit.QueryOptions{
		ResourceID: resourceID,
		Limit:      500,
	})
	if err != nil {
		return err
	}
	verify := cmd.Bool("verify")
	res := map[string]any{
		"resource": resource,
		"events":   events,
	}
	if verify {
		storeOK, _ := c.Audit.VerifyIntegrity(ctx)
		ledgerOK, _ := c.Audit.VerifyLedgerIntegrity(ctx)
		res["chain_verified"] = storeOK && ledgerOK
		res["store_verified"] = storeOK
		res["ledger_verified"] = ledgerOK
	}
	return output(cmd, res)
}

func AuditAnchor(ctx context.Context, cmd *cli.Command) error {
	outputPath := cmd.String("output")
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	proof, err := c.Audit.GetChainProof(ctx)
	if err != nil {
		return err
	}
	if proof == nil {
		return fmt.Errorf("no chain proof available")
	}
	if outputPath == "" {
		home, _ := os.UserHomeDir()
		outputPath = filepath.Join(home, ".secretr", "anchors", "latest.json")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return err
	}
	success("Audit anchor written: %s", outputPath)
	return nil
}

func AuditAnchorVerify(ctx context.Context, cmd *cli.Command) error {
	inputPath := cmd.String("input")
	if inputPath == "" {
		home, _ := os.UserHomeDir()
		inputPath = filepath.Join(home, ".secretr", "anchors", "latest.json")
	}
	b, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	var anchored audit.ChainProof
	if err := json.Unmarshal(b, &anchored); err != nil {
		return err
	}
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	current, err := c.Audit.GetChainProof(ctx)
	if err != nil {
		return err
	}
	if current == nil {
		return fmt.Errorf("no current chain proof available")
	}
	ok := anchored.LatestBlockHash == current.LatestBlockHash
	result := map[string]any{
		"verified":            ok,
		"anchored_block_hash": anchored.LatestBlockHash,
		"current_block_hash":  current.LatestBlockHash,
		"anchored_block_id":   anchored.LatestBlockID,
		"current_block_id":    current.LatestBlockID,
	}
	return output(cmd, result)
}
