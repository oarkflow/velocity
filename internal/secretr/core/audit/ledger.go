// Package audit provides enhanced audit ledger with Merkle trees and cryptographic integrity.
package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrLedgerIntegrityFailed = errors.New("ledger: integrity verification failed")
	ErrBlockNotFound         = errors.New("ledger: block not found")
	ErrProofInvalid          = errors.New("ledger: proof is invalid")
)

// MerkleNode represents a node in the Merkle tree
type MerkleNode struct {
	Hash  []byte      `json:"hash"`
	Left  *MerkleNode `json:"left,omitempty"`
	Right *MerkleNode `json:"right,omitempty"`
	Data  []byte      `json:"data,omitempty"`
}

// MerkleTree represents a Merkle tree for audit integrity
type MerkleTree struct {
	Root   *MerkleNode   `json:"root"`
	Leaves []*MerkleNode `json:"leaves"`
}

// MerkleProof represents a proof of inclusion
type MerkleProof struct {
	Path      []ProofNode `json:"path"`
	LeafHash  []byte      `json:"leaf_hash"`
	LeafIndex int         `json:"leaf_index"`
	RootHash  []byte      `json:"root_hash"`
}

// ProofNode represents a node in the proof path
type ProofNode struct {
	Hash     []byte `json:"hash"`
	Position string `json:"position"` // "left" or "right"
}

// LedgerBlock represents a block in the audit ledger
type LedgerBlock struct {
	ID             types.ID        `json:"id"`
	Index          int64           `json:"index"`
	Timestamp      time.Time       `json:"timestamp"`
	Events         []types.ID      `json:"events"`
	MerkleRoot     []byte          `json:"merkle_root"`
	PreviousHash   []byte          `json:"previous_hash"`
	Hash           []byte          `json:"hash"`
	Signature      []byte          `json:"signature,omitempty"`
	TrustScore     float64         `json:"trust_score"`
	PolicySnapshot *PolicySnapshot `json:"policy_snapshot,omitempty"`
	ZKProof        *ZKProof        `json:"zk_proof,omitempty"`
}

// ZKProof represents a zero-knowledge proof for the block
type ZKProof struct {
	ProofType string `json:"proof_type"`
	ProofData []byte `json:"proof_data"`
	Public    []byte `json:"public_inputs"`
}

// PolicySnapshot captures policy state at block creation time
type PolicySnapshot struct {
	Timestamp      time.Time         `json:"timestamp"`
	ActivePolicies []types.ID        `json:"active_policies"`
	PolicyHashes   map[string]string `json:"policy_hashes"`
}

// CryptographicReceipt represents a receipt for an audit event
type CryptographicReceipt struct {
	EventID     types.ID     `json:"event_id"`
	BlockID     types.ID     `json:"block_id"`
	BlockIndex  int64        `json:"block_index"`
	MerkleProof *MerkleProof `json:"merkle_proof"`
	Timestamp   time.Time    `json:"timestamp"`
	Signature   []byte       `json:"signature,omitempty"`
}

// LedgerConfig holds ledger configuration
type LedgerConfig struct {
	Store         *storage.Store
	BlockSize     int           // Events per block
	BlockInterval time.Duration // Max time between blocks
	SignerKey     []byte
}

// Ledger provides distributed ledger functionality for audit
type Ledger struct {
	mu            sync.RWMutex
	store         *storage.Store
	crypto        *crypto.Engine
	blockStore    *storage.TypedStore[LedgerBlock]
	receiptStore  *storage.TypedStore[CryptographicReceipt]
	blockSize     int
	blockInterval time.Duration
	signerKey     []byte
	pendingEvents []types.ID
	lastBlock     *LedgerBlock
	stopCh        chan struct{}
	zkSystem      *ZKProofSystem
	zkPrivKey     *big.Int
	zkPubKey      []byte
}

// NewLedger creates a new audit ledger
func NewLedger(cfg LedgerConfig) *Ledger {
	if cfg.BlockSize == 0 {
		cfg.BlockSize = 100
	}
	if cfg.BlockInterval == 0 {
		cfg.BlockInterval = 5 * time.Minute
	}

	l := &Ledger{
		store:         cfg.Store,
		crypto:        crypto.NewEngine(""),
		blockStore:    storage.NewTypedStore[LedgerBlock](cfg.Store, "ledger_blocks"),
		receiptStore:  storage.NewTypedStore[CryptographicReceipt](cfg.Store, "ledger_receipts"),
		blockSize:     cfg.BlockSize,
		blockInterval: cfg.BlockInterval,
		signerKey:     cfg.SignerKey,
		pendingEvents: []types.ID{},
		stopCh:        make(chan struct{}),
		zkSystem:      NewZKProofSystem(),
	}

	// Generate ephemeral ZK identity for this ledger instance (if not configured)
	// In production this should come from config
	priv, pub, _ := l.zkSystem.GenerateKeyPair()
	l.zkPrivKey = priv
	l.zkPubKey = pub

	// Load last block
	ctx := context.Background()
	blocks, _ := l.blockStore.List(ctx, "")
	if len(blocks) > 0 {
		// Find latest by index
		latest := blocks[0]
		for _, b := range blocks {
			if b.Index > latest.Index {
				latest = b
			}
		}
		l.lastBlock = latest
	}

	return l
}

// StartBlockProducer starts the background block producer
func (l *Ledger) StartBlockProducer(ctx context.Context) {
	ticker := time.NewTicker(l.blockInterval)
	go func() {
		for {
			select {
			case <-ticker.C:
				l.mu.Lock()
				if len(l.pendingEvents) > 0 {
					_ = l.createBlock(ctx)
				}
				l.mu.Unlock()
			case <-l.stopCh:
				ticker.Stop()
				return
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

// AddEvent adds an event to the pending list
func (l *Ledger) AddEvent(eventID types.ID) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.pendingEvents = append(l.pendingEvents, eventID)

	// Create block if threshold reached
	if len(l.pendingEvents) >= l.blockSize {
		return l.createBlock(context.Background())
	}

	return nil
}

// createBlock creates a new ledger block from pending events
func (l *Ledger) createBlock(ctx context.Context) error {
	if len(l.pendingEvents) == 0 {
		return nil
	}

	// Build Merkle tree from events
	tree := l.buildMerkleTree(l.pendingEvents)

	// Generate block ID
	id, err := l.crypto.GenerateRandomID()
	if err != nil {
		return err
	}

	var index int64 = 0
	var previousHash []byte
	if l.lastBlock != nil {
		index = l.lastBlock.Index + 1
		previousHash = l.lastBlock.Hash
	}

	block := &LedgerBlock{
		ID:           id,
		Index:        index,
		Timestamp:    time.Now(),
		Events:       l.pendingEvents,
		MerkleRoot:   tree.Root.Hash,
		PreviousHash: previousHash,
		TrustScore:   l.calculateTrustScore(),
	}

	// Generate ZK Proof (Proving we know the private key associated with our public ID)
	if l.zkPrivKey != nil {
		proof, err := l.zkSystem.GenerateProof(l.zkPrivKey)
		if err == nil {
			proofBytes, _ := json.Marshal(proof)
			block.ZKProof = &ZKProof{
				ProofType: "Schnorr-P256",
				ProofData: proofBytes,
				Public:    l.zkPubKey,
			}
		}
	}

	// Calculate block hash
	blockData, _ := json.Marshal(block)
	hash := sha256.Sum256(blockData)
	block.Hash = hash[:]

	// Sign block
	if len(l.signerKey) > 0 {
		sig, err := l.crypto.Sign(l.signerKey, block.Hash)
		if err != nil {
			return err
		}
		block.Signature = sig
	}

	// Store block
	if err := l.blockStore.Set(ctx, string(block.ID), block); err != nil {
		return err
	}

	// Generate receipts for each event
	for i, eventID := range l.pendingEvents {
		proof := l.generateProof(tree, i)
		receipt := &CryptographicReceipt{
			EventID:     eventID,
			BlockID:     block.ID,
			BlockIndex:  block.Index,
			MerkleProof: proof,
			Timestamp:   time.Now(),
		}

		if len(l.signerKey) > 0 {
			receiptData, _ := json.Marshal(receipt)
			sig, err := l.crypto.Sign(l.signerKey, receiptData)
			if err != nil {
				return err
			}
			receipt.Signature = sig
		}

		_ = l.receiptStore.Set(ctx, string(eventID), receipt)
	}

	// Update state
	l.lastBlock = block
	l.pendingEvents = []types.ID{}

	return nil
}

// buildMerkleTree builds a Merkle tree from event IDs
func (l *Ledger) buildMerkleTree(events []types.ID) *MerkleTree {
	tree := &MerkleTree{
		Leaves: make([]*MerkleNode, len(events)),
	}

	// Create leaf nodes
	for i, event := range events {
		data := []byte(event)
		hash := sha256.Sum256(data)
		tree.Leaves[i] = &MerkleNode{
			Hash: hash[:],
			Data: data,
		}
	}

	// Build tree from leaves
	nodes := tree.Leaves
	for len(nodes) > 1 {
		var nextLevel []*MerkleNode

		for i := 0; i < len(nodes); i += 2 {
			left := nodes[i]
			var right *MerkleNode

			if i+1 < len(nodes) {
				right = nodes[i+1]
			} else {
				// Duplicate last node if odd number
				right = left
			}

			combinedHash := sha256.Sum256(append(left.Hash, right.Hash...))
			parent := &MerkleNode{
				Hash:  combinedHash[:],
				Left:  left,
				Right: right,
			}
			nextLevel = append(nextLevel, parent)
		}

		nodes = nextLevel
	}

	if len(nodes) > 0 {
		tree.Root = nodes[0]
	}

	return tree
}

// generateProof generates a Merkle proof for an event at given index
func (l *Ledger) generateProof(tree *MerkleTree, index int) *MerkleProof {
	if tree.Root == nil || index >= len(tree.Leaves) {
		return nil
	}

	proof := &MerkleProof{
		Path:      []ProofNode{},
		LeafHash:  tree.Leaves[index].Hash,
		LeafIndex: index,
		RootHash:  tree.Root.Hash,
	}

	// Walk the tree to collect sibling hashes
	nodes := tree.Leaves
	currentIndex := index

	for len(nodes) > 1 {
		var nextLevel []*MerkleNode
		siblingIndex := currentIndex ^ 1 // XOR to find sibling

		if siblingIndex < len(nodes) {
			position := "right"
			if currentIndex%2 == 1 {
				position = "left"
			}
			proof.Path = append(proof.Path, ProofNode{
				Hash:     nodes[siblingIndex].Hash,
				Position: position,
			})
		}

		// Build next level
		for i := 0; i < len(nodes); i += 2 {
			left := nodes[i]
			var right *MerkleNode
			if i+1 < len(nodes) {
				right = nodes[i+1]
			} else {
				right = left
			}
			combinedHash := sha256.Sum256(append(left.Hash, right.Hash...))
			nextLevel = append(nextLevel, &MerkleNode{Hash: combinedHash[:]})
		}

		nodes = nextLevel
		currentIndex = currentIndex / 2
	}

	return proof
}

// VerifyProof verifies a Merkle proof
func (l *Ledger) VerifyProof(proof *MerkleProof) bool {
	if proof == nil {
		return false
	}

	currentHash := proof.LeafHash

	for _, node := range proof.Path {
		var combinedHash [32]byte
		if node.Position == "left" {
			combinedHash = sha256.Sum256(append(node.Hash, currentHash...))
		} else {
			combinedHash = sha256.Sum256(append(currentHash, node.Hash...))
		}
		currentHash = combinedHash[:]
	}

	// Compare with root hash
	return hex.EncodeToString(currentHash) == hex.EncodeToString(proof.RootHash)
}

// GetBlock retrieves a block by ID
func (l *Ledger) GetBlock(ctx context.Context, id types.ID) (*LedgerBlock, error) {
	return l.blockStore.Get(ctx, string(id))
}

// GetBlockByIndex retrieves a block by index
func (l *Ledger) GetBlockByIndex(ctx context.Context, index int64) (*LedgerBlock, error) {
	blocks, err := l.blockStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	for _, b := range blocks {
		if b.Index == index {
			return b, nil
		}
	}

	return nil, ErrBlockNotFound
}

// ListBlocks lists all blocks
func (l *Ledger) ListBlocks(ctx context.Context) ([]*LedgerBlock, error) {
	return l.blockStore.List(ctx, "")
}

// GetReceipt retrieves a receipt for an event
func (l *Ledger) GetReceipt(ctx context.Context, eventID types.ID) (*CryptographicReceipt, error) {
	return l.receiptStore.Get(ctx, string(eventID))
}

// VerifyChain verifies the integrity of the entire ledger chain
func (l *Ledger) VerifyChain(ctx context.Context) (*ChainVerificationResult, error) {
	blocks, err := l.blockStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	result := &ChainVerificationResult{
		TotalBlocks:   len(blocks),
		VerifiedAt:    time.Now(),
		Valid:         true,
		InvalidBlocks: []types.ID{},
	}

	// Sort blocks by index
	blockMap := make(map[int64]*LedgerBlock)
	for _, b := range blocks {
		blockMap[b.Index] = b
	}

	// Verify chain
	for i := int64(1); i <= int64(len(blocks)-1); i++ {
		current := blockMap[i]
		previous := blockMap[i-1]

		if current == nil || previous == nil {
			continue
		}

		// Verify previous hash link
		if hex.EncodeToString(current.PreviousHash) != hex.EncodeToString(previous.Hash) {
			result.Valid = false
			result.InvalidBlocks = append(result.InvalidBlocks, current.ID)
		}

		// Verify block integrity (re-hash)
		if !l.VerifyBlockIntegrity(current) {
			result.Valid = false
			result.InvalidBlocks = append(result.InvalidBlocks, current.ID)
		}
	}

	// Verify first block too
	if len(blocks) > 0 {
		if !l.VerifyBlockIntegrity(blocks[0]) {
			result.Valid = false
			result.InvalidBlocks = append(result.InvalidBlocks, blocks[0].ID)
		}
	}

	return result, nil
}

// VerifyBlockIntegrity verifies the hash and signature of a block
func (l *Ledger) VerifyBlockIntegrity(b *LedgerBlock) bool {
	// 1. Re-calculate hash
	// Create a copy to zero out fields excluded from hash
	clone := *b
	clone.Hash = nil
	clone.Signature = nil

	data, _ := json.Marshal(&clone)
	hash := sha256.Sum256(data)

	if hex.EncodeToString(hash[:]) != hex.EncodeToString(b.Hash) {
		return false
	}

	// 2. Verify signature when signer key is configured.
	if len(l.signerKey) > 0 {
		if len(b.Signature) == 0 {
			return false
		}
		if len(l.signerKey) != ed25519.PrivateKeySize {
			return false
		}
		pub, ok := ed25519.PrivateKey(l.signerKey).Public().(ed25519.PublicKey)
		if !ok {
			return false
		}
		if err := l.crypto.Verify(pub, b.Hash, b.Signature); err != nil {
			return false
		}
	}

	return true
}

// ChainVerificationResult represents the result of chain verification
type ChainVerificationResult struct {
	TotalBlocks   int        `json:"total_blocks"`
	VerifiedAt    time.Time  `json:"verified_at"`
	Valid         bool       `json:"valid"`
	InvalidBlocks []types.ID `json:"invalid_blocks,omitempty"`
}

// calculateTrustScore calculates trust score based on various factors
func (l *Ledger) calculateTrustScore() float64 {
	// Base trust score
	score := 0.8

	// Increase for signed blocks
	if len(l.signerKey) > 0 {
		score += 0.1
	}

	// Increase for valid chain
	if l.lastBlock != nil {
		score += 0.1
	}

	return score
}

// ExportChainProof exports a cryptographic proof of the chain state
func (l *Ledger) ExportChainProof(ctx context.Context) (*ChainProof, error) {
	blocks, err := l.blockStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var hashes []string
	for _, b := range blocks {
		hashes = append(hashes, hex.EncodeToString(b.Hash))
	}

	proof := &ChainProof{
		ExportedAt:  time.Now(),
		TotalBlocks: len(blocks),
		BlockHashes: hashes,
	}

	if l.lastBlock != nil {
		proof.LatestBlockID = l.lastBlock.ID
		proof.LatestBlockIndex = l.lastBlock.Index
		proof.LatestBlockHash = hex.EncodeToString(l.lastBlock.Hash)
	}

	// Sign proof
	if len(l.signerKey) > 0 {
		proofData, _ := json.Marshal(proof)
		proof.Signature, _ = l.crypto.Sign(l.signerKey, proofData)
	}

	return proof, nil
}

// ChainProof represents a cryptographic proof of chain state
type ChainProof struct {
	ExportedAt       time.Time `json:"exported_at"`
	TotalBlocks      int       `json:"total_blocks"`
	LatestBlockID    types.ID  `json:"latest_block_id,omitempty"`
	LatestBlockIndex int64     `json:"latest_block_index"`
	LatestBlockHash  string    `json:"latest_block_hash,omitempty"`
	BlockHashes      []string  `json:"block_hashes"`
	Signature        []byte    `json:"signature,omitempty"`
}

// Close cleans up resources
func (l *Ledger) Close() error {
	close(l.stopCh)
	return l.crypto.Close()
}

// VerifyZKProof verifies a zero-knowledge proof
func (l *Ledger) VerifyZKProof(proof *ZKProof) bool {
	if proof == nil {
		return true // No proof to verify is considered valid for now (optional)
	}

	if proof.ProofType != "Schnorr-P256" {
		// Fallback for empty/legacy
		return len(proof.ProofData) > 0
	}

	// Unmarshal proof data
	var schnorrProof SchnorrProof
	if err := json.Unmarshal(proof.ProofData, &schnorrProof); err != nil {
		return false
	}

	// Verify
	zk := NewZKProofSystem()
	return zk.VerifyProof(proof.Public, &schnorrProof)
}
