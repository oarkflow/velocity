package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/types"
)

// getNested attempts to resolve a nested key (e.g., "app.config.db")
func (v *Vault) getNested(ctx context.Context, keyPath string, accessorID types.ID, mfaVerified bool) ([]byte, error) {
	parts := strings.Split(keyPath, ".")
	// Try to find the longest matching secret name
	for i := len(parts) - 1; i > 0; i-- {
		secretName := strings.Join(parts[:i], ".")
		jsonPath := parts[i:]

		// Try getting this secret (recursive call, but ensuring shorter name)
		val, err := v.Get(ctx, secretName, accessorID, mfaVerified)
		if err == nil {
			// Secret found, try to resolve JSON path
			return resolveJSONPath(val, jsonPath)
		}
	}
	return nil, ErrSecretNotFound
}

// setNested sets a nested value using dot notation
func (v *Vault) setNested(ctx context.Context, keyPath string, value []byte, opts CreateSecretOptions) (*types.Secret, error) {
	parts := strings.Split(keyPath, ".")
	if len(parts) == 1 {
		// Not a nested path, use regular create
		opts.Name = keyPath
		return v.createRegular(ctx, opts)
	}

	// Try to find existing parent secret to merge with
	for i := len(parts) - 1; i > 0; i-- {
		secretName := strings.Join(parts[:i], ".")
		jsonPath := parts[i:]

		// Check if parent secret exists
		_, err := v.GetMetadata(ctx, secretName)
		if err == nil {
			// Parent exists, get its value and merge
			return v.mergeNestedValue(ctx, secretName, jsonPath, value, opts.CreatorID)
		}
	}

	// No parent found, create nested structure from scratch
	return v.createNestedStructure(ctx, keyPath, value, opts)
}

// createRegular creates a regular secret (non-nested)
func (v *Vault) createRegular(ctx context.Context, opts CreateSecretOptions) (*types.Secret, error) {
	// Check if secret already exists
	existing, _ := v.secretStore.Get(ctx, opts.Name)
	if existing != nil && existing.Status != types.StatusRevoked {
		return nil, ErrSecretExists
	}

	id, err := v.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	// Get encryption key
	keyID, err := v.keyManager.GetCurrentKeyID(ctx)
	if err != nil {
		return nil, fmt.Errorf("secrets: failed to get key: %w", err)
	}
	key, err := v.keyManager.GetKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("secrets: failed to get key: %w", err)
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// Encrypt the secret value
	encryptedData, err := v.crypto.Encrypt(key, opts.Value, []byte(opts.Name))
	if err != nil {
		return nil, fmt.Errorf("secrets: encryption failed: %w", err)
	}

	now := types.Now()
	var expiresAt *types.Timestamp
	if opts.ExpiresIn > 0 {
		exp := types.Timestamp(time.Now().Add(opts.ExpiresIn).UnixNano())
		expiresAt = &exp
	}

	secret := &types.Secret{
		ID:            id,
		Name:          opts.Name,
		Type:          opts.Type,
		Version:       1,
		Environment:   opts.Environment,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     expiresAt,
		AccessCount:   0,
		ReadOnce:      opts.ReadOnce,
		Immutable:     opts.Immutable,
		RequireMFA:    opts.RequireMFA,
		Status:        types.StatusActive,
		Metadata:      opts.Metadata,
		EncryptedData: encryptedData,
		KeyID:         keyID,
		Provenance: &types.Provenance{
			CreatedBy:   opts.CreatorID,
			CreatedAt:   now,
			CreatedFrom: opts.DeviceFingerprint,
		},
	}

	if err := v.secretStore.Set(ctx, opts.Name, secret); err != nil {
		return nil, err
	}

	// Store initial version
	version := &types.SecretVersion{
		SecretID:      id,
		Version:       1,
		CreatedAt:     now,
		CreatedBy:     opts.CreatorID,
		EncryptedData: encryptedData,
		KeyID:         keyID,
		Hash:          v.crypto.Hash(opts.Value),
	}
	versionKey := fmt.Sprintf("%s:v%d", opts.Name, 1)
	if err := v.versionStore.Set(ctx, versionKey, version); err != nil {
		return nil, err
	}

	return secret, nil
}

// mergeNestedValue merges a new value into existing JSON structure
func (v *Vault) mergeNestedValue(ctx context.Context, secretName string, jsonPath []string, newValue []byte, updaterID types.ID) (*types.Secret, error) {
	// Get current value
	currentVal, err := v.Get(ctx, secretName, updaterID, false)
	if err != nil {
		return nil, err
	}

	// Parse current JSON
	var current interface{}
	if err := json.Unmarshal(currentVal, &current); err != nil {
		// Current value is not JSON, can't merge
		return nil, fmt.Errorf("cannot set nested value: parent is not JSON")
	}

	// Set the nested value
	updated, err := setJSONPath(current, jsonPath, newValue)
	if err != nil {
		return nil, err
	}

	// Marshal back to bytes
	updatedBytes, err := json.Marshal(updated)
	if err != nil {
		return nil, err
	}

	// Update the secret
	return v.Update(ctx, secretName, updatedBytes, updaterID)
}

// createNestedStructure creates a new nested JSON structure
func (v *Vault) createNestedStructure(ctx context.Context, keyPath string, value []byte, opts CreateSecretOptions) (*types.Secret, error) {
	parts := strings.Split(keyPath, ".")

	// Build nested structure starting from the second part
	result := make(map[string]interface{})
	current := result

	// Skip the first part (root name) and build from the second part
	for i, part := range parts[1:] {
		if i == len(parts[1:])-1 {
			// Last part, set the actual value
			var val interface{}
			if json.Unmarshal(value, &val) == nil {
				current[part] = val
			} else {
				current[part] = string(value)
			}
		} else {
			// Intermediate part, create nested map
			next := make(map[string]interface{})
			current[part] = next
			current = next
		}
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	// Create the secret with the root name
	rootName := parts[0]
	opts.Name = rootName
	opts.Value = jsonBytes

	return v.createRegular(ctx, opts)
}

// setJSONPath sets a value at the specified JSON path
func setJSONPath(data interface{}, path []string, value []byte) (interface{}, error) {
	if len(path) == 0 {
		// Parse the new value
		var newVal interface{}
		if json.Unmarshal(value, &newVal) == nil {
			return newVal, nil
		}
		return string(value), nil
	}

	// Ensure data is a map
	m, ok := data.(map[string]interface{})
	if !ok {
		m = make(map[string]interface{})
	}

	key := path[0]
	if len(path) == 1 {
		// Last key, set the value
		var val interface{}
		if json.Unmarshal(value, &val) == nil {
			m[key] = val
		} else {
			m[key] = string(value)
		}
	} else {
		// Recursive case
		next, exists := m[key]
		if !exists {
			next = make(map[string]interface{})
		}
		updated, err := setJSONPath(next, path[1:], value)
		if err != nil {
			return nil, err
		}
		m[key] = updated
	}

	return m, nil
}

func resolveJSONPath(data []byte, path []string) ([]byte, error) {
	var current interface{}
	if err := json.Unmarshal(data, &current); err != nil {
		// Not a JSON object, so can't traverse
		return nil, ErrSecretNotFound
	}

	for _, part := range path {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil, ErrSecretNotFound
		}
		val, exists := m[part]
		if !exists {
			return nil, ErrSecretNotFound
		}
		current = val
	}

	// Convert result back to bytes
	switch v := current.(type) {
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	default:
		return json.Marshal(v)
	}
}
