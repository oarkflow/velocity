// Package storage provides encrypted storage using oarkflow/velocity.
package storage

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/security"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrNotFound      = errors.New("storage: not found")
	ErrAlreadyExists = errors.New("storage: already exists")
	ErrStorageClosed = errors.New("storage: storage is closed")
	ErrInvalidData   = errors.New("storage: invalid data")
)

// Collections
const (
	CollectionIdentities     = "identities"
	CollectionDevices        = "devices"
	CollectionSessions       = "sessions"
	CollectionKeys           = "keys"
	CollectionKeyVersions    = "key_versions"
	CollectionSecrets        = "secrets"
	CollectionSecretVersions = "secret_versions"
	CollectionFiles          = "files"
	CollectionFileChunks     = "file_chunks"
	CollectionRoles          = "roles"
	CollectionGrants         = "grants"
	CollectionPolicies       = "policies"
	CollectionPolicyBindings = "policy_bindings"
	CollectionAuditEvents    = "audit_events"
	CollectionOrganizations  = "organizations"
	CollectionTeams          = "teams"
	CollectionEnvironments   = "environments"
	CollectionIncidents      = "incidents"
	CollectionShares         = "shares"
	CollectionBackups        = "backups"
	CollectionRecoveryShards = "recovery_shards"
	CollectionTransfers      = "transfers"
	CollectionAccessRequests = "access_requests"
	CollectionPipelines      = "pipelines"
	CollectionShareRevokes   = "share_revocations"
)

// Store provides encrypted storage operations
type Store struct {
	mu               sync.RWMutex
	db               *velocity.DB
	path             string
	crypto           *crypto.Engine
	encryptionKey    *security.SecureBytes
	deviceProtection *DeviceProtection
	closed           bool
}

// Config holds storage configuration
type Config struct {
	Path          string
	EncryptionKey []byte
	Algorithm     string
	KeySource     velocity.MasterKeySource
	JWTSecret     string
}

// NewStore creates a new encrypted storage
func NewStore(cfg Config) (*Store, error) {
	if cfg.KeySource == "" {
		cfg.KeySource = velocity.SystemFile
	}
	config := velocity.Config{
		Path: cfg.Path,
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: cfg.KeySource,
			UserKeyCache: velocity.UserKeyCacheConfig{
				Enabled: true,
				TTL:     30, // Cache for 30 seconds
			},
		},
		JWTSecret: cfg.JWTSecret,
	}
	// Only set MasterKey if we have one and using UserDefined source
	if len(cfg.EncryptionKey) > 0 && cfg.KeySource == velocity.UserDefined {
		config.MasterKey = cfg.EncryptionKey
	}
	db, err := velocity.NewWithConfig(config)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to open velocity store: %w", err)
	}
	// Get the actual master key from the database
	masterKey := db.MasterKey()
	if len(cfg.EncryptionKey) == 0 {
		cfg.EncryptionKey = masterKey
	}
	// Create crypto engine
	cryptoEngine := crypto.NewEngine(cfg.Algorithm)

	// Secure the encryption key
	encKey, err := security.NewSecureBytesFromSlice(cfg.EncryptionKey)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: failed to secure encryption key: %w", err)
	}

	store := &Store{
		db:               db,
		path:             cfg.Path,
		crypto:           cryptoEngine,
		encryptionKey:    encKey,
		deviceProtection: NewDeviceProtection(),
	}

	// Validate device access
	ctx := context.Background()
	if err := store.deviceProtection.ValidateDeviceAccess(ctx, store); err != nil {
		store.Close()
		return nil, fmt.Errorf("storage: device access denied: %w", err)
	}

	return store, nil
}

func (s *Store) MasterKey() []byte {
	return s.db.MasterKey()
}

// DB returns the underlying velocity database for direct access to Object storage
func (s *Store) DB() *velocity.DB {
	return s.db
}

// Close closes the storage
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true

	if s.encryptionKey != nil {
		s.encryptionKey.Free()
	}

	if s.deviceProtection != nil {
		s.deviceProtection.Close()
	}

	s.crypto.Close()

	return s.db.Close()
}

// encryptData encrypts data before storing with device-bound key
func (s *Store) encryptData(data []byte) ([]byte, error) {
	if s.deviceProtection != nil {
		// Use device-bound key for all encryption
		deviceKey, err := s.deviceProtection.DeriveDeviceKey(s.encryptionKey.Bytes())
		if err != nil {
			return nil, err
		}
		return s.crypto.Encrypt(deviceKey, data, nil)
	}
	return s.crypto.Encrypt(s.encryptionKey.Bytes(), data, nil)
}

func (s *Store) decryptData(data []byte) ([]byte, error) {
	if s.deviceProtection != nil {
		// Use device-bound key for all decryption
		deviceKey, err := s.deviceProtection.DeriveDeviceKey(s.encryptionKey.Bytes())
		if err != nil {
			return nil, err
		}
		return s.crypto.Decrypt(deviceKey, data, nil)
	}
	return s.crypto.Decrypt(s.encryptionKey.Bytes(), data, nil)
}

// Get retrieves and decrypts a value
func (s *Store) Get(ctx context.Context, collection string, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStorageClosed
	}

	fullKey := collection + ":" + key
	encrypted, err := s.db.Get([]byte(fullKey))
	if err != nil {
		return nil, ErrNotFound
	}

	if encrypted == nil {
		return nil, ErrNotFound
	}

	return s.decryptData(encrypted)
}

// Set encrypts and stores a value
func (s *Store) Set(ctx context.Context, collection string, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStorageClosed
	}

	encrypted, err := s.encryptData(value)
	if err != nil {
		return fmt.Errorf("storage: encryption failed: %w", err)
	}

	fullKey := collection + ":" + key
	err = s.db.Put([]byte(fullKey), encrypted)
	return err
}

// Delete removes a value
func (s *Store) Delete(ctx context.Context, collection string, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStorageClosed
	}

	fullKey := collection + ":" + key
	return s.db.Delete([]byte(fullKey))
}

// Exists checks if a key exists
func (s *Store) Exists(ctx context.Context, collection string, key string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return false, ErrStorageClosed
	}

	fullKey := collection + ":" + key
	data, err := s.db.Get([]byte(fullKey))
	if err != nil {
		return false, nil
	}
	return data != nil, nil
}

// List lists all keys in a collection with optional prefix
func (s *Store) List(ctx context.Context, collection string, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStorageClosed
	}

	searchPrefix := collection + ":"
	if prefix != "" {
		searchPrefix += prefix
	}

	// Workaround for velocity.DB.Keys(prefix) bug: fetch all keys and filter manually
	allKeys, err := s.db.Keys("")
	if err != nil {
		return nil, fmt.Errorf("storage: failed to list keys: %w", err)
	}

	sort.Strings(allKeys)

	var result []string
	prefixLen := len(collection) + 1
	for _, k := range allKeys {
		if strings.HasPrefix(k, searchPrefix) {
			if len(k) > prefixLen {
				result = append(result, k[prefixLen:])
			}
		}
	}

	return result, nil
}

// Transaction represents a storage transaction
type Transaction struct {
	store *Store
	ops   []txOp
	mu    sync.Mutex
}

type txOp struct {
	opType     string
	collection string
	key        string
	value      []byte
}

// Begin starts a new transaction
func (s *Store) Begin(ctx context.Context) (*Transaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrStorageClosed
	}

	return &Transaction{
		store: s,
		ops:   make([]txOp, 0),
	}, nil
}

// Set adds a set operation to the transaction
func (tx *Transaction) Set(collection string, key string, value []byte) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.ops = append(tx.ops, txOp{opType: "set", collection: collection, key: key, value: value})
}

// Delete adds a delete operation to the transaction
func (tx *Transaction) Delete(collection string, key string) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.ops = append(tx.ops, txOp{opType: "delete", collection: collection, key: key})
}

// Commit commits the transaction
func (tx *Transaction) Commit(ctx context.Context) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	for _, op := range tx.ops {
		var err error
		switch op.opType {
		case "set":
			err = tx.store.Set(ctx, op.collection, op.key, op.value)
		case "delete":
			err = tx.store.Delete(ctx, op.collection, op.key)
		}
		if err != nil {
			return err
		}
	}

	tx.ops = nil
	return nil
}

// Rollback discards the transaction
func (tx *Transaction) Rollback() {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.ops = nil
}

// TypedStore provides type-safe storage operations
type TypedStore[T any] struct {
	store      *Store
	collection string
}

// NewTypedStore creates a typed store for a specific collection
func NewTypedStore[T any](store *Store, collection string) *TypedStore[T] {
	return &TypedStore[T]{
		store:      store,
		collection: collection,
	}
}

// Get retrieves and unmarshals a value
func (ts *TypedStore[T]) Get(ctx context.Context, key string) (*T, error) {
	data, err := ts.store.Get(ctx, ts.collection, key)
	if err != nil {
		return nil, err
	}

	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("storage: failed to unmarshal: %w", err)
	}

	return &value, nil
}

// Set marshals and stores a value
func (ts *TypedStore[T]) Set(ctx context.Context, key string, value *T) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("storage: failed to marshal: %w", err)
	}

	return ts.store.Set(ctx, ts.collection, key, data)
}

// Delete removes a value
func (ts *TypedStore[T]) Delete(ctx context.Context, key string) error {
	return ts.store.Delete(ctx, ts.collection, key)
}

// List returns all items in the collection
func (ts *TypedStore[T]) List(ctx context.Context, prefix string) ([]*T, error) {
	keys, err := ts.store.List(ctx, ts.collection, prefix)
	if err != nil {
		return nil, err
	}

	items := make([]*T, 0, len(keys))
	for _, key := range keys {
		item, err := ts.Get(ctx, key)
		if err != nil {
			continue // Skip items that fail to load
		}
		items = append(items, item)
	}

	return items, nil
}

// AuditStore provides append-only audit log storage
type AuditStore struct {
	store  *Store
	crypto *crypto.Engine
	mu     sync.Mutex
}

// NewAuditStore creates an audit store
func NewAuditStore(store *Store) *AuditStore {
	return &AuditStore{
		store:  store,
		crypto: crypto.NewEngine(""),
	}
}

// Append appends an audit event with hash chaining
func (as *AuditStore) Append(ctx context.Context, event *types.AuditEvent) error {
	release, err := as.acquireAppendLock()
	if err != nil {
		return err
	}
	defer release()

	as.mu.Lock()
	defer as.mu.Unlock()

	// Get the last event's hash for chaining
	lastHash, err := as.getLastHash(ctx)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}

	// Set previous hash
	event.PreviousHash = lastHash

	// Marshal for hashing (excluding the hash itself)
	eventData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("storage: failed to marshal audit event: %w", err)
	}

	// Calculate current hash
	event.Hash = as.crypto.HashChain(lastHash, eventData)

	// Marshal AGAIN for storage (this time including the hash)
	finalData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("storage: failed to marshal audit event for storage: %w", err)
	}

	// Store the event
	key := fmt.Sprintf("%020d_%s", event.Timestamp, event.ID)
	if err := as.store.Set(ctx, CollectionAuditEvents, key, finalData); err != nil {
		return err
	}

	// Update the last hash pointer
	if err := as.store.Set(ctx, CollectionAuditEvents, "_last_hash", event.Hash); err != nil {
		// Avoid chain split when pointer update fails.
		_ = as.store.Delete(ctx, CollectionAuditEvents, key)
		return err
	}
	return nil
}

func (as *AuditStore) acquireAppendLock() (func(), error) {
	base := strings.TrimSpace(as.store.path)
	if base == "" {
		return func() {}, nil
	}
	lockPath := filepath.Join(base, ".audit.append.lock")
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := os.Mkdir(lockPath, 0700)
		if err == nil {
			return func() { _ = os.Remove(lockPath) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > 30*time.Second {
			_ = os.Remove(lockPath)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("storage: audit append lock timeout")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (as *AuditStore) getLastHash(ctx context.Context) ([]byte, error) {
	return as.store.Get(ctx, CollectionAuditEvents, "_last_hash")
}

// Query queries audit events
func (as *AuditStore) Query(ctx context.Context, opts AuditQueryOptions) ([]*types.AuditEvent, error) {
	keys, err := as.store.List(ctx, CollectionAuditEvents, "")
	if err != nil {
		return nil, err
	}

	events := make([]*types.AuditEvent, 0)
	for _, key := range keys {
		if key == "_last_hash" {
			continue
		}

		data, err := as.store.Get(ctx, CollectionAuditEvents, key)
		if err != nil {
			continue
		}

		var event types.AuditEvent
		if err := json.Unmarshal(data, &event); err != nil {
			continue
		}

		// Apply filters
		if opts.ActorID != "" && event.ActorID != opts.ActorID {
			continue
		}
		if opts.ResourceID != "" && event.ResourceID != nil && *event.ResourceID != opts.ResourceID {
			continue
		}
		if opts.Action != "" && event.Action != opts.Action {
			continue
		}
		if opts.StartTime > 0 && int64(event.Timestamp) < opts.StartTime {
			continue
		}
		if opts.EndTime > 0 && int64(event.Timestamp) > opts.EndTime {
			continue
		}

		ev := event
		events = append(events, &ev)

		if opts.Limit > 0 && len(events) >= opts.Limit {
			break
		}
	}

	return events, nil
}

// AuditQueryOptions defines audit query parameters
type AuditQueryOptions struct {
	ActorID    types.ID
	ResourceID types.ID
	Action     string
	StartTime  int64
	EndTime    int64
	Limit      int
}

// VerifyChain verifies the integrity of the audit chain
func (as *AuditStore) VerifyChain(ctx context.Context) (bool, error) {
	events, err := as.Query(ctx, AuditQueryOptions{})
	if err != nil {
		return false, err
	}
	lastHash, err := as.getLastHash(ctx)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return false, err
	}
	if len(events) == 0 {
		return len(lastHash) == 0, nil
	}

	byHash := make(map[string]*types.AuditEvent, len(events))
	for _, event := range events {
		if event == nil || len(event.Hash) == 0 {
			return false, nil
		}
		byHash[hex.EncodeToString(event.Hash)] = event
		// Recompute hash
		// We must exclude Hash and Signature from the data to be hashed
		actualHash := event.Hash
		actualSig := event.Signature
		event.Hash = nil
		event.Signature = nil
		eventData, _ := json.Marshal(event)
		event.Hash = actualHash
		event.Signature = actualSig

		expectedHash := as.crypto.HashChain(event.PreviousHash, eventData)
		if !security.ConstantTimeCompare(event.Hash, expectedHash) {
			return false, nil
		}
	}
	for _, event := range events {
		if event == nil {
			return false, nil
		}
		if len(event.PreviousHash) > 0 {
			prevKey := hex.EncodeToString(event.PreviousHash)
			if _, ok := byHash[prevKey]; !ok {
				return false, nil
			}
		}
	}

	if len(lastHash) > 0 {
		if _, ok := byHash[hex.EncodeToString(lastHash)]; !ok {
			return false, nil
		}
	}

	// Detect cycles in hash->previous hash links.
	const (
		visitVisiting = 1
		visitDone     = 2
	)
	visitState := make(map[string]int, len(byHash))
	var dfs func(string) bool
	dfs = func(h string) bool {
		switch visitState[h] {
		case visitDone:
			return true
		case visitVisiting:
			return false
		}
		visitState[h] = visitVisiting
		ev := byHash[h]
		if ev != nil && len(ev.PreviousHash) > 0 {
			prev := hex.EncodeToString(ev.PreviousHash)
			if _, ok := byHash[prev]; !ok || !dfs(prev) {
				return false
			}
		}
		visitState[h] = visitDone
		return true
	}
	for h := range byHash {
		if !dfs(h) {
			return false, nil
		}
	}

	return true, nil
}

// BackupOptions defines backup configuration
type BackupOptions struct {
	Collections []string
	EncryptKey  []byte
	Compress    bool
}

// Backup creates an encrypted backup
func (s *Store) Backup(ctx context.Context, opts BackupOptions) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStorageClosed
	}

	collections := opts.Collections
	if len(collections) == 0 {
		collections = []string{
			CollectionIdentities,
			CollectionDevices,
			CollectionSessions,
			CollectionKeys,
			CollectionSecrets,
			CollectionFiles,
			CollectionRoles,
			CollectionGrants,
			CollectionPolicies,
			CollectionOrganizations,
			CollectionTeams,
		}
	}

	backup := make(map[string]map[string][]byte)

	for _, collection := range collections {
		keys, err := s.List(ctx, collection, "")
		if err != nil {
			continue
		}

		backup[collection] = make(map[string][]byte)
		for _, key := range keys {
			data, err := s.Get(ctx, collection, key)
			if err != nil {
				continue
			}
			backup[collection][key] = data
		}
	}

	// Marshal backup
	backupData, err := json.Marshal(backup)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to marshal backup: %w", err)
	}

	// Encrypt with backup key if provided
	if len(opts.EncryptKey) > 0 {
		backupData, err = s.crypto.Encrypt(opts.EncryptKey, backupData, []byte("backup"))
		if err != nil {
			return nil, fmt.Errorf("storage: failed to encrypt backup: %w", err)
		}
	}

	return backupData, nil
}

// Restore restores from an encrypted backup
func (s *Store) Restore(ctx context.Context, backupData []byte, decryptKey []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStorageClosed
	}

	// Decrypt if key provided
	if len(decryptKey) > 0 {
		var err error
		backupData, err = s.crypto.Decrypt(decryptKey, backupData, []byte("backup"))
		if err != nil {
			return fmt.Errorf("storage: failed to decrypt backup: %w", err)
		}
	}

	var backup map[string]map[string][]byte
	if err := json.Unmarshal(backupData, &backup); err != nil {
		return fmt.Errorf("storage: failed to unmarshal backup: %w", err)
	}

	for collection, items := range backup {
		for key, data := range items {
			if err := s.Set(ctx, collection, key, data); err != nil {
				return fmt.Errorf("storage: failed to restore %s/%s: %w", collection, key, err)
			}
		}
	}

	return nil
}

// HealthCheck performs a storage health check
func (s *Store) HealthCheck(ctx context.Context) error {
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		return ErrStorageClosed
	}

	// Write and read a test value
	testKey := fmt.Sprintf("_health_%d", time.Now().UnixNano())
	testValue := []byte("health_check")

	if err := s.Set(ctx, "_system", testKey, testValue); err != nil {
		return fmt.Errorf("storage: health check write failed: %w", err)
	}

	readValue, err := s.Get(ctx, "_system", testKey)
	if err != nil {
		return fmt.Errorf("storage: health check read failed: %w", err)
	}

	if !security.ConstantTimeCompare(testValue, readValue) {
		return fmt.Errorf("storage: health check data mismatch")
	}

	// Cleanup
	_ = s.Delete(ctx, "_system", testKey)

	return nil
}
