package audit

import (
	"context"
	"testing"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

func TestLedgerIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := storage.NewStore(storage.Config{Path: tmpDir, EncryptionKey: make([]byte, 32)})
	defer store.Close()

	// 1. Create Ledger
	ledger := NewLedger(LedgerConfig{
		Store:         store,
		BlockSize:     2, // Small block size for testing
		BlockInterval: 1 * time.Second,
		SignerKey:     nil,
	})
	defer ledger.Close()

	// 2. Add Events
	ctx := context.Background()
	events := []types.ID{"event1", "event2", "event3", "event4"}

	for _, e := range events {
		if err := ledger.AddEvent(e); err != nil {
			t.Fatalf("AddEvent failed: %v", err)
		}
	}

	// 3. Verify Chain
	res, err := ledger.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}
	if !res.Valid {
		t.Errorf("Chain should be valid, invalid blocks: %v", res.InvalidBlocks)
	}

	// 4. Verify Block content
	blocks, _ := ledger.ListBlocks(ctx)
	if len(blocks) != 2 {
		t.Errorf("Expected 2 blocks, got %d", len(blocks))
	}

	// Check chaining manually
	if len(blocks) == 2 {
		genB0, err := ledger.GetBlockByIndex(ctx, 0)
		if err != nil {
			t.Errorf("Failed to get block 0: %v", err)
		}
		genB1, err := ledger.GetBlockByIndex(ctx, 1)
		if err != nil {
			t.Errorf("Failed to get block 1: %v", err)
		}

		if genB1 != nil && genB0 != nil {
			// Check if previous hash matches
			if string(genB1.PreviousHash) != string(genB0.Hash) {
				t.Errorf("Hash chain broken")
			}
		}
	}

	// 5. Tamper Check
	// Modify a block in storage
	ts := storage.NewTypedStore[LedgerBlock](store, "ledger_blocks")
	blocks, _ = ledger.ListBlocks(ctx)
	if len(blocks) > 0 {
		target := blocks[0]
		target.PreviousHash = []byte("tampered")

		ts.Set(ctx, string(target.ID), target)

		res, err = ledger.VerifyChain(ctx)
		if res.Valid {
			t.Errorf("Tampered chain should be invalid")
		}
	}
}
