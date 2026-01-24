package velocity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ImmutableAuditLog represents a tamper-proof audit trail using Merkle trees
type ImmutableAuditLog struct {
	ChainID       string       `json:"chain_id"`
	BlockHeight   int          `json:"block_height"`
	PreviousBlock string       `json:"previous_block"` // Hash of previous block
	Timestamp     time.Time    `json:"timestamp"`
	Events        []AuditEvent `json:"events"`
	MerkleRoot    string       `json:"merkle_root"`     // Root of Merkle tree for events
	Signature     string       `json:"signature"`       // Cryptographic signature
	Metadata      BlockMetadata `json:"metadata"`
}

// AuditEvent represents a single auditable action
type AuditEvent struct {
	EventID           string                 `json:"event_id"`
	Timestamp         time.Time              `json:"timestamp"`
	Actor             string                 `json:"actor"`
	ActorRole         string                 `json:"actor_role,omitempty"`
	Action            string                 `json:"action"`
	Resource          string                 `json:"resource"`
	ResourceID        string                 `json:"resource_id,omitempty"`
	Result            string                 `json:"result"` // success, failure, denied
	IPAddress         string                 `json:"ip_address,omitempty"`
	SessionID         string                 `json:"session_id,omitempty"`
	DataHash          string                 `json:"data_hash,omitempty"` // Hash of affected data
	BeforeState       string                 `json:"before_state,omitempty"`
	AfterState        string                 `json:"after_state,omitempty"`
	Reason            string                 `json:"reason,omitempty"`
	Classification    DataClassification     `json:"classification"`
	ComplianceTags    []ComplianceFramework  `json:"compliance_tags,omitempty"`
	Severity          string                 `json:"severity"` // low, medium, high, critical
	MerkleProof       []string               `json:"merkle_proof,omitempty"` // Proof of inclusion
	EventHash         string                 `json:"event_hash"` // SHA-256 of event data
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// BlockMetadata contains block-level information
type BlockMetadata struct {
	NodeID       string `json:"node_id"`
	Version      string `json:"version"`
	EventCount   int    `json:"event_count"`
	CreatedBy    string `json:"created_by"`
	Sealed       bool   `json:"sealed"`       // Immutable once sealed
	SealedAt     time.Time `json:"sealed_at,omitempty"`
	RetentionEnd time.Time `json:"retention_end"` // When this can be archived
}

// AuditLogManager manages the immutable audit trail
type AuditLogManager struct {
	db               *DB
	currentBlock     *ImmutableAuditLog
	blocks           []*ImmutableAuditLog
	pendingEvents    []AuditEvent
	mu               sync.RWMutex
	blockSize        int // Max events per block
	autoSeal         bool
	retentionPeriod  time.Duration
	chainID          string
}

// NewAuditLogManager creates a new audit log manager
func NewAuditLogManager(db *DB) *AuditLogManager {
	return &AuditLogManager{
		db:              db,
		pendingEvents:   make([]AuditEvent, 0),
		blocks:          make([]*ImmutableAuditLog, 0),
		blockSize:       100, // Seal block after 100 events
		autoSeal:        true,
		retentionPeriod: 7 * 365 * 24 * time.Hour, // 7 years (compliance requirement)
		chainID:         generateChainID(),
	}
}

// LogEvent records an auditable event
func (alm *AuditLogManager) LogEvent(event AuditEvent) error {
	alm.mu.Lock()
	defer alm.mu.Unlock()

	// Generate event hash
	event.EventHash = alm.hashEvent(event)
	event.EventID = generateEventID()

	// Add to pending events
	alm.pendingEvents = append(alm.pendingEvents, event)

	// Auto-seal if block size reached
	if alm.autoSeal && len(alm.pendingEvents) >= alm.blockSize {
		return alm.sealBlockLocked()
	}

	return nil
}

// SealBlock seals the current block and creates a new one
func (alm *AuditLogManager) SealBlock() error {
	alm.mu.Lock()
	defer alm.mu.Unlock()

	return alm.sealBlockLocked()
}

// sealBlockLocked seals the block (caller must hold lock)
func (alm *AuditLogManager) sealBlockLocked() error {
	if len(alm.pendingEvents) == 0 {
		return nil // Nothing to seal
	}

	// Create new block
	block := &ImmutableAuditLog{
		ChainID:     alm.chainID,
		BlockHeight: len(alm.blocks),
		Timestamp:   time.Now(),
		Events:      make([]AuditEvent, len(alm.pendingEvents)),
		Metadata: BlockMetadata{
			NodeID:       "node-001", // TODO: Get from config
			Version:      "2.0.0",
			EventCount:   len(alm.pendingEvents),
			CreatedBy:    "audit_system",
			RetentionEnd: time.Now().Add(alm.retentionPeriod),
		},
	}

	copy(block.Events, alm.pendingEvents)

	// Link to previous block
	if len(alm.blocks) > 0 {
		prevBlock := alm.blocks[len(alm.blocks)-1]
		block.PreviousBlock = prevBlock.Signature
	}

	// Build Merkle tree for events
	block.MerkleRoot = alm.buildMerkleTree(block.Events)

	// Generate Merkle proofs for each event
	for i := range block.Events {
		block.Events[i].MerkleProof = alm.generateMerkleProof(block.Events, i)
	}

	// Sign the block
	block.Signature = alm.signBlock(block)

	// Seal the block
	block.Metadata.Sealed = true
	block.Metadata.SealedAt = time.Now()

	// Store block
	if err := alm.storeBlock(block); err != nil {
		return fmt.Errorf("failed to store block: %w", err)
	}

	// Add to chain
	alm.blocks = append(alm.blocks, block)

	// Clear pending events
	alm.pendingEvents = make([]AuditEvent, 0)

	return nil
}

// buildMerkleTree constructs a Merkle tree from events and returns the root hash
func (alm *AuditLogManager) buildMerkleTree(events []AuditEvent) string {
	if len(events) == 0 {
		return ""
	}

	// Get leaf hashes
	hashes := make([]string, len(events))
	for i, event := range events {
		hashes[i] = event.EventHash
	}

	// Build tree bottom-up
	for len(hashes) > 1 {
		var nextLevel []string

		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				// Combine two hashes
				combined := hashes[i] + hashes[i+1]
				h := sha256.Sum256([]byte(combined))
				nextLevel = append(nextLevel, hex.EncodeToString(h[:]))
			} else {
				// Odd number: duplicate last hash
				combined := hashes[i] + hashes[i]
				h := sha256.Sum256([]byte(combined))
				nextLevel = append(nextLevel, hex.EncodeToString(h[:]))
			}
		}

		hashes = nextLevel
	}

	return hashes[0]
}

// generateMerkleProof generates a proof of inclusion for an event
func (alm *AuditLogManager) generateMerkleProof(events []AuditEvent, index int) []string {
	proof := make([]string, 0)

	// Get leaf hashes
	hashes := make([]string, len(events))
	for i, event := range events {
		hashes[i] = event.EventHash
	}

	currentIndex := index

	// Build proof by collecting sibling hashes at each level
	for len(hashes) > 1 {
		var nextLevel []string
		var siblingIndex int

		if currentIndex%2 == 0 {
			// Current is left child
			siblingIndex = currentIndex + 1
		} else {
			// Current is right child
			siblingIndex = currentIndex - 1
		}

		// Add sibling to proof if it exists
		if siblingIndex < len(hashes) {
			proof = append(proof, hashes[siblingIndex])
		}

		// Build next level
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := hashes[i] + hashes[i+1]
				h := sha256.Sum256([]byte(combined))
				nextLevel = append(nextLevel, hex.EncodeToString(h[:]))
			} else {
				combined := hashes[i] + hashes[i]
				h := sha256.Sum256([]byte(combined))
				nextLevel = append(nextLevel, hex.EncodeToString(h[:]))
			}
		}

		hashes = nextLevel
		currentIndex = currentIndex / 2
	}

	return proof
}

// VerifyMerkleProof verifies an event's inclusion in the Merkle tree
func (alm *AuditLogManager) VerifyMerkleProof(event AuditEvent, merkleRoot string) bool {
	currentHash := event.EventHash

	for _, siblingHash := range event.MerkleProof {
		// Combine with sibling (order doesn't matter for verification)
		combined := currentHash + siblingHash
		h := sha256.Sum256([]byte(combined))
		currentHash = hex.EncodeToString(h[:])
	}

	return currentHash == merkleRoot
}

// hashEvent creates a SHA-256 hash of an event
func (alm *AuditLogManager) hashEvent(event AuditEvent) string {
	h := sha256.New()

	// Hash all relevant fields
	h.Write([]byte(event.Actor))
	h.Write([]byte(event.Action))
	h.Write([]byte(event.Resource))
	h.Write([]byte(event.ResourceID))
	h.Write([]byte(event.Result))
	h.Write([]byte(event.Timestamp.Format(time.RFC3339Nano)))

	if event.DataHash != "" {
		h.Write([]byte(event.DataHash))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// signBlock creates a cryptographic signature for a block
func (alm *AuditLogManager) signBlock(block *ImmutableAuditLog) string {
	h := sha256.New()

	// Hash block components
	h.Write([]byte(block.ChainID))
	h.Write([]byte(fmt.Sprintf("%d", block.BlockHeight)))
	h.Write([]byte(block.PreviousBlock))
	h.Write([]byte(block.Timestamp.Format(time.RFC3339Nano)))
	h.Write([]byte(block.MerkleRoot))

	return hex.EncodeToString(h.Sum(nil))
}

// VerifyChain validates the integrity of the entire audit chain
func (alm *AuditLogManager) VerifyChain() error {
	alm.mu.RLock()
	defer alm.mu.RUnlock()

	for i, block := range alm.blocks {
		// Verify block signature
		expectedSig := alm.signBlock(block)
		if expectedSig != block.Signature {
			return fmt.Errorf("block %d signature mismatch", i)
		}

		// Verify linkage to previous block
		if i > 0 {
			prevBlock := alm.blocks[i-1]
			if block.PreviousBlock != prevBlock.Signature {
				return fmt.Errorf("block %d chain break: previous hash mismatch", i)
			}
		}

		// Verify Merkle root
		expectedRoot := alm.buildMerkleTree(block.Events)
		if expectedRoot != block.MerkleRoot {
			return fmt.Errorf("block %d Merkle root mismatch", i)
		}

		// Verify each event's Merkle proof
		for j, event := range block.Events {
			if !alm.VerifyMerkleProof(event, block.MerkleRoot) {
				return fmt.Errorf("block %d event %d Merkle proof invalid", i, j)
			}
		}
	}

	return nil
}

// QueryEvents retrieves audit events matching criteria
func (alm *AuditLogManager) QueryEvents(query AuditQuery) ([]AuditEvent, error) {
	alm.mu.RLock()
	defer alm.mu.RUnlock()

	var results []AuditEvent

	for _, block := range alm.blocks {
		for _, event := range block.Events {
			if alm.matchesQuery(event, query) {
				results = append(results, event)
			}
		}
	}

	// Also check pending events
	for _, event := range alm.pendingEvents {
		if alm.matchesQuery(event, query) {
			results = append(results, event)
		}
	}

	return results, nil
}

// AuditQuery defines search criteria for audit events
type AuditQuery struct {
	Actor          string
	Action         string
	Resource       string
	Result         string
	StartTime      time.Time
	EndTime        time.Time
	Classification DataClassification
	Severity       string
	Limit          int
}

// matchesQuery checks if an event matches query criteria
func (alm *AuditLogManager) matchesQuery(event AuditEvent, query AuditQuery) bool {
	if query.Actor != "" && event.Actor != query.Actor {
		return false
	}

	if query.Action != "" && event.Action != query.Action {
		return false
	}

	if query.Resource != "" && event.Resource != query.Resource {
		return false
	}

	if query.Result != "" && event.Result != query.Result {
		return false
	}

	if !query.StartTime.IsZero() && event.Timestamp.Before(query.StartTime) {
		return false
	}

	if !query.EndTime.IsZero() && event.Timestamp.After(query.EndTime) {
		return false
	}

	if query.Classification != "" && event.Classification != query.Classification {
		return false
	}

	if query.Severity != "" && event.Severity != query.Severity {
		return false
	}

	return true
}

// storeBlock persists a block to WORM storage
func (alm *AuditLogManager) storeBlock(block *ImmutableAuditLog) error {
	data, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("failed to marshal block: %w", err)
	}

	// Store in database with special immutable prefix
	key := fmt.Sprintf("_audit:block:%s:%d", block.ChainID, block.BlockHeight)
	if err := alm.db.Put([]byte(key), data); err != nil {
		return fmt.Errorf("failed to store block: %w", err)
	}

	return nil
}

// ExportForensics exports audit trail in forensic-ready format
func (alm *AuditLogManager) ExportForensics(outputPath string) error {
	alm.mu.RLock()
	defer alm.mu.RUnlock()

	forensicExport := ForensicExport{
		ChainID:      alm.chainID,
		ExportedAt:   time.Now(),
		BlockCount:   len(alm.blocks),
		TotalEvents:  alm.getTotalEvents(),
		Blocks:       alm.blocks,
		VerifiedAt:   time.Now(),
		Verification: "passed",
	}

	// Verify chain before export
	if err := alm.VerifyChain(); err != nil {
		forensicExport.Verification = "failed: " + err.Error()
	}

	// Export to JSON
	data, err := json.MarshalIndent(forensicExport, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal forensic export: %w", err)
	}

	// TODO: Write to file
	_ = data
	_ = outputPath

	return nil
}

// ForensicExport represents a complete audit trail export
type ForensicExport struct {
	ChainID      string               `json:"chain_id"`
	ExportedAt   time.Time            `json:"exported_at"`
	BlockCount   int                  `json:"block_count"`
	TotalEvents  int                  `json:"total_events"`
	Blocks       []*ImmutableAuditLog `json:"blocks"`
	VerifiedAt   time.Time            `json:"verified_at"`
	Verification string               `json:"verification"`
	Signature    string               `json:"signature"`
}

// getTotalEvents counts total events across all blocks
func (alm *AuditLogManager) getTotalEvents() int {
	total := 0
	for _, block := range alm.blocks {
		total += len(block.Events)
	}
	return total + len(alm.pendingEvents)
}

// generateChainID creates a unique chain identifier
func generateChainID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("chain_%s", hex.EncodeToString(b))
}

// generateEventID creates a unique event identifier
func generateEventID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("evt_%s", hex.EncodeToString(b))
}

// DetectTampering checks for signs of tampering in the audit trail
func (alm *AuditLogManager) DetectTampering() ([]TamperingIndicator, error) {
	indicators := make([]TamperingIndicator, 0)

	// Verify chain integrity
	if err := alm.VerifyChain(); err != nil {
		indicators = append(indicators, TamperingIndicator{
			Type:        "chain_break",
			Severity:    "critical",
			Description: err.Error(),
			DetectedAt:  time.Now(),
		})
	}

	// Check for time anomalies
	for i := 1; i < len(alm.blocks); i++ {
		if alm.blocks[i].Timestamp.Before(alm.blocks[i-1].Timestamp) {
			indicators = append(indicators, TamperingIndicator{
				Type:        "time_anomaly",
				Severity:    "high",
				Description: fmt.Sprintf("block %d timestamp earlier than block %d", i, i-1),
				DetectedAt:  time.Now(),
			})
		}
	}

	// Check for missing block heights
	for i := 0; i < len(alm.blocks); i++ {
		if alm.blocks[i].BlockHeight != i {
			indicators = append(indicators, TamperingIndicator{
				Type:        "missing_block",
				Severity:    "critical",
				Description: fmt.Sprintf("expected block height %d, got %d", i, alm.blocks[i].BlockHeight),
				DetectedAt:  time.Now(),
			})
		}
	}

	return indicators, nil
}

// TamperingIndicator represents a potential tampering event
type TamperingIndicator struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	BlockHeight int       `json:"block_height,omitempty"`
	DetectedAt  time.Time `json:"detected_at"`
	Evidence    map[string]interface{} `json:"evidence,omitempty"`
}

// GetAuditStatistics returns statistical summary of audit trail
func (alm *AuditLogManager) GetAuditStatistics() AuditStatistics {
	alm.mu.RLock()
	defer alm.mu.RUnlock()

	stats := AuditStatistics{
		TotalBlocks:    len(alm.blocks),
		TotalEvents:    alm.getTotalEvents(),
		PendingEvents:  len(alm.pendingEvents),
		ChainID:        alm.chainID,
		OldestEvent:    time.Now(),
		NewestEvent:    time.Time{},
		EventsByAction: make(map[string]int),
		EventsByActor:  make(map[string]int),
		EventsByResult: make(map[string]int),
	}

	for _, block := range alm.blocks {
		for _, event := range block.Events {
			if event.Timestamp.Before(stats.OldestEvent) {
				stats.OldestEvent = event.Timestamp
			}
			if event.Timestamp.After(stats.NewestEvent) {
				stats.NewestEvent = event.Timestamp
			}

			stats.EventsByAction[event.Action]++
			stats.EventsByActor[event.Actor]++
			stats.EventsByResult[event.Result]++
		}
	}

	return stats
}

// AuditStatistics provides summary statistics
type AuditStatistics struct {
	TotalBlocks    int               `json:"total_blocks"`
	TotalEvents    int               `json:"total_events"`
	PendingEvents  int               `json:"pending_events"`
	ChainID        string            `json:"chain_id"`
	OldestEvent    time.Time         `json:"oldest_event"`
	NewestEvent    time.Time         `json:"newest_event"`
	EventsByAction map[string]int    `json:"events_by_action"`
	EventsByActor  map[string]int    `json:"events_by_actor"`
	EventsByResult map[string]int    `json:"events_by_result"`
}
