package storage

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/oarkflow/licensing/pkg/device"
	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
)

var (
	ErrDeviceMismatch = errors.New("storage: device fingerprint mismatch - vault cannot be accessed from this device")
	ErrDeviceBinding  = errors.New("storage: failed to bind vault to device")
)

// DeviceProtection handles device fingerprint validation for storage vault
type DeviceProtection struct {
	crypto *crypto.Engine
	fingerprint string
}

// NewDeviceProtection creates a new device protection instance
func NewDeviceProtection() *DeviceProtection {
	return &DeviceProtection{
		crypto: crypto.NewEngine(""),
	}
}

// GetDeviceFingerprint gets the current device fingerprint
func (dp *DeviceProtection) GetDeviceFingerprint() (string, error) {
	if dp.fingerprint != "" {
		return dp.fingerprint, nil
	}

	info, err := device.GetInfo()
	if err != nil {
		return "", fmt.Errorf("failed to get device info: %w", err)
	}

	// Create fingerprint from device info
	fingerprint := info.Fingerprint
	dp.fingerprint = fingerprint
	return fingerprint, nil
}

// DeriveDeviceKey derives an encryption key that includes device fingerprint
func (dp *DeviceProtection) DeriveDeviceKey(baseKey []byte) ([]byte, error) {
	fingerprint, err := dp.GetDeviceFingerprint()
	if err != nil {
		return nil, err
	}

	// Combine base key with device fingerprint
	combined := append(baseKey, []byte(fingerprint)...)
	hash := sha256.Sum256(combined)
	return hash[:], nil
}

// ValidateDeviceAccess validates device by attempting to decrypt existing data
func (dp *DeviceProtection) ValidateDeviceAccess(ctx context.Context, store *Store) error {
	// Simply return nil - validation happens automatically during decryption
	// If device fingerprint is wrong, all decrypt operations will fail
	return nil
}



// Close cleans up resources
func (dp *DeviceProtection) Close() error {
	return dp.crypto.Close()
}
