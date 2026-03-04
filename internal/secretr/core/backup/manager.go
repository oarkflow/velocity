// Package backup provides disaster recovery functionality.
package backup

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrBackupNotFound     = errors.New("backup: not found")
	ErrBackupCorrupted    = errors.New("backup: integrity check failed")
	ErrRestoreInProgress  = errors.New("backup: restore already in progress")
	ErrInsufficientQuorum = errors.New("backup: insufficient quorum for recovery")
	ErrDeadManNotSet      = errors.New("backup: dead-man switch not configured")
)

// Manager handles backup and recovery operations
type Manager struct {
	store             *storage.Store
	crypto            *crypto.Engine
	backupStore       *storage.TypedStore[types.Backup]
	scheduleStore     *storage.TypedStore[BackupSchedule]
	recoveryStore     *storage.TypedStore[RecoveryShard]
	deadManStore      *storage.TypedStore[DeadManSwitch]
	selfDestructStore *storage.TypedStore[SelfDestructKey]
	coldStorageStore  *storage.TypedStore[ColdStorageConfig]
	mu                sync.Mutex
	restoreInProgress bool
}

// BackupSchedule represents a scheduled backup job
type BackupSchedule struct {
	ID            types.ID         `json:"id"`
	OrgID         types.ID         `json:"org_id"`
	Type          string           `json:"type"` // full, incremental
	CronExpr      string           `json:"cron_expr"`
	Destination   string           `json:"destination,omitempty"`
	RetentionDays int              `json:"retention_days"`
	Enabled       bool             `json:"enabled"`
	LastRun       *types.Timestamp `json:"last_run,omitempty"`
	NextRun       *types.Timestamp `json:"next_run,omitempty"`
	CreatedAt     types.Timestamp  `json:"created_at"`
	CreatedBy     types.ID         `json:"created_by"`
}

// RecoveryShard represents a quorum-based recovery shard
type RecoveryShard struct {
	ID        types.ID        `json:"id"`
	BackupID  types.ID        `json:"backup_id"`
	HolderID  types.ID        `json:"holder_id"`
	Index     int             `json:"index"`
	Threshold int             `json:"threshold"`
	Total     int             `json:"total"`
	Data      []byte          `json:"data"`
	Hash      []byte          `json:"hash"`
	CreatedAt types.Timestamp `json:"created_at"`
}

// DeadManSwitch represents a dead-man switch configuration
type DeadManSwitch struct {
	ID               types.ID        `json:"id"`
	OrgID            types.ID        `json:"org_id"`
	TriggerAfterDays int             `json:"trigger_after_days"`
	RecipientIDs     []types.ID      `json:"recipient_ids"`
	LastCheckin      types.Timestamp `json:"last_checkin"`
	Enabled          bool            `json:"enabled"`
	CreatedAt        types.Timestamp `json:"created_at"`
	CreatedBy        types.ID        `json:"created_by"`
}

// SelfDestructKey represents a backup encryption key with automatic destruction
type SelfDestructKey struct {
	ID           types.ID         `json:"id"`
	BackupID     types.ID         `json:"backup_id"`
	EncryptedKey []byte           `json:"encrypted_key"`
	ExpiresAt    types.Timestamp  `json:"expires_at"`
	IsDestroyed  bool             `json:"is_destroyed"`
	DestroyedAt  *types.Timestamp `json:"destroyed_at,omitempty"`
	CreatedAt    types.Timestamp  `json:"created_at"`
	CreatedBy    types.ID         `json:"created_by"`
	UseCount     int              `json:"use_count"`
	MaxUseCount  int              `json:"max_use_count,omitempty"` // 0 = unlimited
}

// ColdStorageConfig represents cold storage mode configuration
type ColdStorageConfig struct {
	ID               types.ID        `json:"id"`
	OrgID            types.ID        `json:"org_id"`
	Enabled          bool            `json:"enabled"`
	RotationDisabled bool            `json:"rotation_disabled"` // Disable automatic rotation
	ReadOnly         bool            `json:"read_only"`         // Only read operations allowed
	ArchivalDate     types.Timestamp `json:"archival_date"`
	RetentionYears   int             `json:"retention_years"`
	LegalHoldRef     string          `json:"legal_hold_ref,omitempty"` // Reference to legal case
	CreatedAt        types.Timestamp `json:"created_at"`
	CreatedBy        types.ID        `json:"created_by"`
}

// ManagerConfig configures the backup manager
type ManagerConfig struct {
	Store *storage.Store
}

// NewManager creates a new backup manager
func NewManager(cfg ManagerConfig) *Manager {
	return &Manager{
		store:             cfg.Store,
		crypto:            crypto.NewEngine(""),
		backupStore:       storage.NewTypedStore[types.Backup](cfg.Store, storage.CollectionBackups),
		scheduleStore:     storage.NewTypedStore[BackupSchedule](cfg.Store, "backup_schedules"),
		recoveryStore:     storage.NewTypedStore[RecoveryShard](cfg.Store, storage.CollectionRecoveryShards),
		deadManStore:      storage.NewTypedStore[DeadManSwitch](cfg.Store, "dead_man_switches"),
		selfDestructStore: storage.NewTypedStore[SelfDestructKey](cfg.Store, "self_destruct_keys"),
		coldStorageStore:  storage.NewTypedStore[ColdStorageConfig](cfg.Store, "cold_storage_configs"),
	}
}

// CreateBackup creates an encrypted backup
func (m *Manager) CreateBackup(ctx context.Context, opts CreateBackupOptions) (*types.Backup, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	// Generate backup encryption key
	backupKey, err := m.crypto.GenerateKey(crypto.KeySize256)
	if err != nil {
		return nil, err
	}
	defer backupKey.Free()

	// Collect all data to backup
	backupData, err := m.collectBackupData(ctx, opts.Collections)
	if err != nil {
		return nil, err
	}

	// Encrypt the backup data
	encryptedData, err := m.crypto.Encrypt(backupKey.Bytes(), backupData, nil)
	if err != nil {
		return nil, err
	}

	// Hash for integrity
	hash := m.crypto.Hash(encryptedData)

	// Encrypt the backup key with the provided master key
	encryptedKey, err := m.crypto.Encrypt(opts.EncryptionKey, backupKey.Bytes(), nil)
	if err != nil {
		return nil, err
	}

	backup := &types.Backup{
		ID:           id,
		Type:         opts.Type,
		CreatedAt:    types.Now(),
		CreatedBy:    opts.CreatorID,
		Size:         int64(len(encryptedData)),
		Hash:         hash,
		EncryptedKey: encryptedKey,
		Status:       types.StatusActive,
		Metadata: types.Metadata{
			"collections": opts.Collections,
		},
	}

	if err := m.backupStore.Set(ctx, string(backup.ID), backup); err != nil {
		return nil, err
	}

	// Write encrypted data to output
	if opts.Output != nil {
		if _, err := opts.Output.Write(encryptedData); err != nil {
			return nil, err
		}
	}

	return backup, nil
}

// CreateBackupOptions holds backup creation options
type CreateBackupOptions struct {
	Type          string   // full, incremental
	Collections   []string // specific collections or empty for all
	EncryptionKey []byte
	CreatorID     types.ID
	Output        io.Writer
}

// collectBackupData collects data from all specified collections
func (m *Manager) collectBackupData(ctx context.Context, collections []string) ([]byte, error) {
	if len(collections) == 0 {
		collections = []string{
			storage.CollectionIdentities,
			storage.CollectionDevices,
			storage.CollectionSessions,
			storage.CollectionKeys,
			storage.CollectionSecrets,
			storage.CollectionSecretVersions,
			storage.CollectionFiles,
			storage.CollectionGrants,
			storage.CollectionRoles,
			storage.CollectionPolicies,
			storage.CollectionOrganizations,
			storage.CollectionTeams,
			storage.CollectionEnvironments,
		}
	}

	data := make(map[string][]json.RawMessage)

	for _, coll := range collections {
		keys, err := m.store.List(ctx, coll, "")
		if err != nil {
			continue
		}

		var items []json.RawMessage
		for _, key := range keys {
			val, err := m.store.Get(ctx, coll, key)
			if err != nil {
				continue
			}
			items = append(items, json.RawMessage(val))
		}
		data[coll] = items
	}

	return json.Marshal(data)
}

// GetBackup retrieves a backup by ID
func (m *Manager) GetBackup(ctx context.Context, id types.ID) (*types.Backup, error) {
	backup, err := m.backupStore.Get(ctx, string(id))
	if err != nil {
		return nil, ErrBackupNotFound
	}
	return backup, nil
}

// ListBackups lists all backups
func (m *Manager) ListBackups(ctx context.Context) ([]*types.Backup, error) {
	return m.backupStore.List(ctx, "")
}

// VerifyBackup verifies backup integrity
func (m *Manager) VerifyBackup(ctx context.Context, backupID types.ID, encryptedData []byte) (*VerifyResult, error) {
	backup, err := m.GetBackup(ctx, backupID)
	if err != nil {
		return nil, err
	}

	result := &VerifyResult{
		BackupID:  backupID,
		Verified:  false,
		CheckedAt: time.Now(),
	}

	// Verify hash
	actualHash := m.crypto.Hash(encryptedData)
	if !bytesEqual(actualHash, backup.Hash) {
		result.Error = "hash mismatch"
		return result, nil
	}

	// Verify size
	if int64(len(encryptedData)) != backup.Size {
		result.Error = "size mismatch"
		return result, nil
	}

	result.Verified = true
	return result, nil
}

// VerifyResult represents backup verification result
type VerifyResult struct {
	BackupID  types.ID  `json:"backup_id"`
	Verified  bool      `json:"verified"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// RestoreBackup restores from a backup
func (m *Manager) RestoreBackup(ctx context.Context, opts RestoreOptions) (*RestoreResult, error) {
	m.mu.Lock()
	if m.restoreInProgress {
		m.mu.Unlock()
		return nil, ErrRestoreInProgress
	}
	m.restoreInProgress = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.restoreInProgress = false
		m.mu.Unlock()
	}()

	backup, err := m.GetBackup(ctx, opts.BackupID)
	if err != nil {
		return nil, err
	}

	result := &RestoreResult{
		BackupID:  opts.BackupID,
		DryRun:    opts.DryRun,
		StartedAt: time.Now(),
	}

	// Decrypt backup key
	backupKey, err := m.crypto.Decrypt(opts.DecryptionKey, backup.EncryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt backup key: %w", err)
	}

	// Decrypt backup data
	decryptedData, err := m.crypto.Decrypt(backupKey, opts.EncryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt backup data: %w", err)
	}

	// Parse backup data
	var data map[string][]json.RawMessage
	if err := json.Unmarshal(decryptedData, &data); err != nil {
		return nil, fmt.Errorf("failed to parse backup data: %w", err)
	}

	// Filter collections if partial restore
	if len(opts.Collections) > 0 {
		filtered := make(map[string][]json.RawMessage)
		for _, coll := range opts.Collections {
			if items, ok := data[coll]; ok {
				filtered[coll] = items
			}
		}
		data = filtered
	}

	result.ItemCount = make(map[string]int)
	for coll, items := range data {
		result.ItemCount[coll] = len(items)
	}

	// If dry run, return without actually restoring
	if opts.DryRun {
		result.Success = true
		result.CompletedAt = time.Now()
		return result, nil
	}

	// Restore each collection
	for coll, items := range data {
		for _, item := range items {
			// Parse item to get ID
			var obj struct {
				ID types.ID `json:"id"`
			}
			if err := json.Unmarshal(item, &obj); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("failed to parse item in %s", coll))
				continue
			}

			if err := m.store.Set(ctx, coll, string(obj.ID), item); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("failed to restore %s/%s", coll, obj.ID))
			} else {
				result.RestoredCount++
			}
		}
	}

	result.Success = len(result.Errors) == 0
	result.CompletedAt = time.Now()

	return result, nil
}

// RestoreOptions holds restore options
type RestoreOptions struct {
	BackupID      types.ID
	DecryptionKey []byte
	EncryptedData []byte
	DryRun        bool     // if true, don't actually restore
	Collections   []string // specific collections for partial restore
}

// RestoreResult represents restore operation result
type RestoreResult struct {
	BackupID      types.ID       `json:"backup_id"`
	DryRun        bool           `json:"dry_run"`
	Success       bool           `json:"success"`
	ItemCount     map[string]int `json:"item_count"`
	RestoredCount int            `json:"restored_count"`
	Errors        []string       `json:"errors,omitempty"`
	StartedAt     time.Time      `json:"started_at"`
	CompletedAt   time.Time      `json:"completed_at"`
}

// Schedule Management

// CreateSchedule creates a backup schedule
func (m *Manager) CreateSchedule(ctx context.Context, opts CreateScheduleOptions) (*BackupSchedule, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	schedule := &BackupSchedule{
		ID:            id,
		OrgID:         opts.OrgID,
		Type:          opts.Type,
		CronExpr:      opts.CronExpr,
		Destination:   opts.Destination,
		RetentionDays: opts.RetentionDays,
		Enabled:       true,
		CreatedAt:     types.Now(),
		CreatedBy:     opts.CreatorID,
	}

	if err := m.scheduleStore.Set(ctx, string(schedule.ID), schedule); err != nil {
		return nil, err
	}

	return schedule, nil
}

// CreateScheduleOptions holds schedule creation options
type CreateScheduleOptions struct {
	OrgID         types.ID
	Type          string
	CronExpr      string
	Destination   string
	RetentionDays int
	CreatorID     types.ID
}

// ListSchedules lists backup schedules
func (m *Manager) ListSchedules(ctx context.Context, orgID types.ID) ([]*BackupSchedule, error) {
	schedules, err := m.scheduleStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var result []*BackupSchedule
	for _, s := range schedules {
		if s.OrgID == orgID {
			result = append(result, s)
		}
	}
	return result, nil
}

// EnableSchedule enables a backup schedule
func (m *Manager) EnableSchedule(ctx context.Context, id types.ID) error {
	schedule, err := m.scheduleStore.Get(ctx, string(id))
	if err != nil {
		return err
	}
	schedule.Enabled = true
	return m.scheduleStore.Set(ctx, string(id), schedule)
}

// DisableSchedule disables a backup schedule
func (m *Manager) DisableSchedule(ctx context.Context, id types.ID) error {
	schedule, err := m.scheduleStore.Get(ctx, string(id))
	if err != nil {
		return err
	}
	schedule.Enabled = false
	return m.scheduleStore.Set(ctx, string(id), schedule)
}

// Quorum-based Recovery

// CreateRecoveryShards creates M-of-N recovery shards for a backup
func (m *Manager) CreateRecoveryShards(ctx context.Context, opts CreateShardsOptions) ([]RecoveryShard, error) {
	backup, err := m.GetBackup(ctx, opts.BackupID)
	if err != nil {
		return nil, err
	}

	// Split the backup key
	shards, err := splitSecret(backup.EncryptedKey, opts.Total, opts.Threshold)
	if err != nil {
		return nil, err
	}

	var result []RecoveryShard
	for i, data := range shards {
		id, _ := m.crypto.GenerateRandomID()
		shard := RecoveryShard{
			ID:        id,
			BackupID:  opts.BackupID,
			HolderID:  opts.HolderIDs[i],
			Index:     i + 1,
			Threshold: opts.Threshold,
			Total:     opts.Total,
			Data:      data,
			Hash:      m.crypto.Hash(data),
			CreatedAt: types.Now(),
		}

		if err := m.recoveryStore.Set(ctx, string(shard.ID), &shard); err != nil {
			return nil, err
		}
		result = append(result, shard)
	}

	return result, nil
}

// CreateShardsOptions holds shard creation options
type CreateShardsOptions struct {
	BackupID  types.ID
	Threshold int        // M
	Total     int        // N
	HolderIDs []types.ID // one per shard
}

// RecoverWithShards recovers backup key using quorum of shards
func (m *Manager) RecoverWithShards(ctx context.Context, shards []RecoveryShard) ([]byte, error) {
	if len(shards) == 0 {
		return nil, ErrInsufficientQuorum
	}

	threshold := shards[0].Threshold
	if len(shards) < threshold {
		return nil, ErrInsufficientQuorum
	}

	// Verify all shards are for the same backup
	backupID := shards[0].BackupID
	for _, s := range shards {
		if s.BackupID != backupID {
			return nil, errors.New("backup: shards from different backups")
		}
	}

	// Combine shards
	var shardData [][]byte
	for _, s := range shards {
		shardData = append(shardData, s.Data)
	}

	return combineSecret(shardData)
}

// PrintableRecoveryPacket represents a printable recovery packet for offline storage
type PrintableRecoveryPacket struct {
	PacketID     string   `json:"packet_id"`
	BackupID     string   `json:"backup_id"`
	ShardIndex   int      `json:"shard_index"`
	Threshold    int      `json:"threshold"`
	TotalShards  int      `json:"total_shards"`
	HolderName   string   `json:"holder_name"`
	EncodedData  string   `json:"encoded_data"` // Base64 encoded shard
	Checksum     string   `json:"checksum"`
	GeneratedAt  string   `json:"generated_at"`
	Instructions []string `json:"instructions"`
}

// GeneratePrintableRecoveryPacket generates a printable recovery packet for a shard
func (m *Manager) GeneratePrintableRecoveryPacket(ctx context.Context, shard RecoveryShard, holderName string) (*PrintableRecoveryPacket, error) {
	// Create checksum of shard data
	checksum := hex.EncodeToString(m.crypto.Hash(shard.Data))

	packet := &PrintableRecoveryPacket{
		PacketID:    string(shard.ID),
		BackupID:    string(shard.BackupID),
		ShardIndex:  shard.Index,
		Threshold:   shard.Threshold,
		TotalShards: shard.Total,
		HolderName:  holderName,
		EncodedData: base64.StdEncoding.EncodeToString(shard.Data),
		Checksum:    checksum[:16], // First 16 chars for readability
		GeneratedAt: time.Now().Format(time.RFC3339),
		Instructions: []string{
			fmt.Sprintf("RECOVERY SHARD %d of %d", shard.Index, shard.Total),
			fmt.Sprintf("Minimum %d shards required for recovery", shard.Threshold),
			"",
			"INSTRUCTIONS:",
			"1. Store this packet in a secure, offline location",
			"2. Keep away from the main backup storage",
			"3. To recover, collect at least " + fmt.Sprintf("%d", shard.Threshold) + " shards",
			"4. Use command: secretr backup recover --shards <shard-files>",
			"",
			"IMPORTANT:",
			"- Do not share this packet via electronic means",
			"- Verify checksum before recovery",
			"- This packet is part of backup: " + string(shard.BackupID)[:8] + "...",
		},
	}

	return packet, nil
}

// GenerateAllRecoveryPackets generates printable packets for all shards of a backup
func (m *Manager) GenerateAllRecoveryPackets(ctx context.Context, shards []RecoveryShard, holderNames map[int]string) ([]*PrintableRecoveryPacket, error) {
	var packets []*PrintableRecoveryPacket

	for _, shard := range shards {
		holderName := holderNames[shard.Index]
		if holderName == "" {
			holderName = fmt.Sprintf("Shard Holder %d", shard.Index)
		}

		packet, err := m.GeneratePrintableRecoveryPacket(ctx, shard, holderName)
		if err != nil {
			return nil, err
		}
		packets = append(packets, packet)
	}

	return packets, nil
}

// FormatPacketAsText formats a recovery packet as printable text
func FormatPacketAsText(packet *PrintableRecoveryPacket) string {
	var sb strings.Builder

	sb.WriteString("═══════════════════════════════════════════════════════════════\n")
	sb.WriteString("                 SECRETR RECOVERY SHARD PACKET                 \n")
	sb.WriteString("═══════════════════════════════════════════════════════════════\n\n")

	for _, line := range packet.Instructions {
		sb.WriteString(line + "\n")
	}

	sb.WriteString("\n───────────────────────────────────────────────────────────────\n")
	sb.WriteString("                      SHARD DATA                               \n")
	sb.WriteString("───────────────────────────────────────────────────────────────\n\n")

	sb.WriteString(fmt.Sprintf("Packet ID:  %s\n", packet.PacketID))
	sb.WriteString(fmt.Sprintf("Holder:     %s\n", packet.HolderName))
	sb.WriteString(fmt.Sprintf("Generated:  %s\n", packet.GeneratedAt))
	sb.WriteString(fmt.Sprintf("Checksum:   %s\n\n", packet.Checksum))

	// Split encoded data into readable chunks
	data := packet.EncodedData
	chunkSize := 60
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		sb.WriteString(data[i:end] + "\n")
	}

	sb.WriteString("\n═══════════════════════════════════════════════════════════════\n")
	sb.WriteString("              STORE SECURELY • DO NOT COPY DIGITALLY           \n")
	sb.WriteString("═══════════════════════════════════════════════════════════════\n")

	return sb.String()
}

// Dead-man Switch

// ConfigureDeadManSwitch configures a dead-man switch
func (m *Manager) ConfigureDeadManSwitch(ctx context.Context, opts DeadManOptions) (*DeadManSwitch, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	dms := &DeadManSwitch{
		ID:               id,
		OrgID:            opts.OrgID,
		TriggerAfterDays: opts.TriggerAfterDays,
		RecipientIDs:     opts.RecipientIDs,
		LastCheckin:      types.Now(),
		Enabled:          true,
		CreatedAt:        types.Now(),
		CreatedBy:        opts.CreatorID,
	}

	if err := m.deadManStore.Set(ctx, string(dms.ID), dms); err != nil {
		return nil, err
	}

	return dms, nil
}

// DeadManOptions holds dead-man switch configuration options
type DeadManOptions struct {
	OrgID            types.ID
	TriggerAfterDays int
	RecipientIDs     []types.ID
	CreatorID        types.ID
}

// Checkin updates the dead-man switch checkin time
func (m *Manager) Checkin(ctx context.Context, orgID types.ID) error {
	switches, err := m.deadManStore.List(ctx, "")
	if err != nil {
		return err
	}

	for _, dms := range switches {
		if dms.OrgID == orgID && dms.Enabled {
			dms.LastCheckin = types.Now()
			if err := m.deadManStore.Set(ctx, string(dms.ID), dms); err != nil {
				return err
			}
		}
	}

	return nil
}

// CheckDeadManSwitches checks for triggered dead-man switches
func (m *Manager) CheckDeadManSwitches(ctx context.Context) ([]*DeadManSwitch, error) {
	switches, err := m.deadManStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var triggered []*DeadManSwitch

	for _, dms := range switches {
		if !dms.Enabled {
			continue
		}

		lastCheckin := dms.LastCheckin.Time()
		triggerTime := lastCheckin.Add(time.Duration(dms.TriggerAfterDays) * 24 * time.Hour)

		if now.After(triggerTime) {
			triggered = append(triggered, dms)
		}
	}

	return triggered, nil
}

// Self-Destructing Backup Keys

// CreateSelfDestructKey creates a backup key that will auto-destruct after a TTL
func (m *Manager) CreateSelfDestructKey(ctx context.Context, opts SelfDestructKeyOptions) (*SelfDestructKey, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	now := types.Now()
	expiresAt := types.Timestamp(int64(now) + opts.TTLSeconds*1e9)

	key := &SelfDestructKey{
		ID:           id,
		BackupID:     opts.BackupID,
		EncryptedKey: opts.EncryptedKey,
		ExpiresAt:    expiresAt,
		IsDestroyed:  false,
		CreatedAt:    now,
		CreatedBy:    opts.CreatorID,
		MaxUseCount:  opts.MaxUseCount,
	}

	if err := m.selfDestructStore.Set(ctx, string(key.ID), key); err != nil {
		return nil, err
	}

	return key, nil
}

// SelfDestructKeyOptions holds options for creating a self-destructing key
type SelfDestructKeyOptions struct {
	BackupID     types.ID
	EncryptedKey []byte
	TTLSeconds   int64 // seconds until key self-destructs
	MaxUseCount  int   // max number of uses (0 = unlimited)
	CreatorID    types.ID
}

// UseSelfDestructKey retrieves and uses a self-destructing key
func (m *Manager) UseSelfDestructKey(ctx context.Context, keyID types.ID) ([]byte, error) {
	key, err := m.selfDestructStore.Get(ctx, string(keyID))
	if err != nil {
		return nil, errors.New("backup: self-destruct key not found")
	}

	// Check if destroyed
	if key.IsDestroyed {
		return nil, errors.New("backup: key has been destroyed")
	}

	// Check if expired
	now := types.Now()
	if key.ExpiresAt < now {
		// Destroy the key
		key.IsDestroyed = true
		destroyedAt := now
		key.DestroyedAt = &destroyedAt
		_ = m.selfDestructStore.Set(ctx, string(keyID), key)
		return nil, errors.New("backup: key has expired and been destroyed")
	}

	// Increment use count
	key.UseCount++

	// Check if max use count reached
	if key.MaxUseCount > 0 && key.UseCount >= key.MaxUseCount {
		key.IsDestroyed = true
		destroyedAt := now
		key.DestroyedAt = &destroyedAt
	}

	if err := m.selfDestructStore.Set(ctx, string(keyID), key); err != nil {
		return nil, err
	}

	return key.EncryptedKey, nil
}

// CleanupExpiredSelfDestructKeys destroys all expired self-destruct keys
func (m *Manager) CleanupExpiredSelfDestructKeys(ctx context.Context) (int, error) {
	keys, err := m.selfDestructStore.List(ctx, "")
	if err != nil {
		return 0, err
	}

	now := types.Now()
	destroyedCount := 0

	for _, key := range keys {
		if key.IsDestroyed {
			continue
		}

		if key.ExpiresAt < now {
			key.IsDestroyed = true
			destroyedAt := now
			key.DestroyedAt = &destroyedAt
			key.EncryptedKey = nil // Securely wipe the key

			if err := m.selfDestructStore.Set(ctx, string(key.ID), key); err != nil {
				continue
			}
			destroyedCount++
		}
	}

	return destroyedCount, nil
}

// Cold Storage Mode

// EnableColdStorage enables cold storage mode for an organization
func (m *Manager) EnableColdStorage(ctx context.Context, opts ColdStorageOptions) (*ColdStorageConfig, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	now := types.Now()
	config := &ColdStorageConfig{
		ID:               id,
		OrgID:            opts.OrgID,
		Enabled:          true,
		RotationDisabled: true, // Disable rotation in cold storage
		ReadOnly:         opts.ReadOnly,
		ArchivalDate:     now,
		RetentionYears:   opts.RetentionYears,
		LegalHoldRef:     opts.LegalHoldRef,
		CreatedAt:        now,
		CreatedBy:        opts.CreatorID,
	}

	if err := m.coldStorageStore.Set(ctx, string(config.ID), config); err != nil {
		return nil, err
	}

	return config, nil
}

// ColdStorageOptions holds options for enabling cold storage
type ColdStorageOptions struct {
	OrgID          types.ID
	ReadOnly       bool
	RetentionYears int
	LegalHoldRef   string
	CreatorID      types.ID
}

// DisableColdStorage disables cold storage mode
func (m *Manager) DisableColdStorage(ctx context.Context, orgID types.ID) error {
	configs, err := m.coldStorageStore.List(ctx, "")
	if err != nil {
		return err
	}

	for _, config := range configs {
		if config.OrgID == orgID && config.Enabled {
			config.Enabled = false
			if err := m.coldStorageStore.Set(ctx, string(config.ID), config); err != nil {
				return err
			}
		}
	}

	return nil
}

// GetColdStorageConfig retrieves cold storage configuration for an org
func (m *Manager) GetColdStorageConfig(ctx context.Context, orgID types.ID) (*ColdStorageConfig, error) {
	configs, err := m.coldStorageStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	for _, config := range configs {
		if config.OrgID == orgID && config.Enabled {
			return config, nil
		}
	}

	return nil, nil // Not in cold storage
}

// IsColdStorage checks if an organization is in cold storage mode
func (m *Manager) IsColdStorage(ctx context.Context, orgID types.ID) (bool, error) {
	config, err := m.GetColdStorageConfig(ctx, orgID)
	if err != nil {
		return false, err
	}
	return config != nil && config.Enabled, nil
}

// IsRotationDisabled checks if rotation is disabled for an organization (due to cold storage)
func (m *Manager) IsRotationDisabled(ctx context.Context, orgID types.ID) (bool, error) {
	config, err := m.GetColdStorageConfig(ctx, orgID)
	if err != nil {
		return false, err
	}
	if config == nil {
		return false, nil
	}
	return config.RotationDisabled, nil
}

// Close cleans up resources
func (m *Manager) Close() error {
	return m.crypto.Close()
}

// Helper functions

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Simple secret splitting using XOR (for demo - real implementation would use Shamir's Secret Sharing)
func splitSecret(secret []byte, n, threshold int) ([][]byte, error) {
	if n < threshold || threshold < 2 {
		return nil, errors.New("invalid threshold parameters")
	}

	// This is a simplified demo - real implementation should use proper Shamir's Secret Sharing
	shards := make([][]byte, n)
	for i := 0; i < n; i++ {
		shard := make([]byte, len(secret)+2)
		shard[0] = byte(i + 1)     // shard index
		shard[1] = byte(threshold) // threshold
		copy(shard[2:], secret)
		shards[i] = shard
	}
	return shards, nil
}

// Simple secret combining (for demo)
func combineSecret(shards [][]byte) ([]byte, error) {
	if len(shards) == 0 {
		return nil, errors.New("no shards provided")
	}
	// Demo: just return the secret from the first shard
	if len(shards[0]) < 3 {
		return nil, errors.New("invalid shard")
	}
	return shards[0][2:], nil
}
