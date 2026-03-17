package velocity

import (
	"crypto/sha256"
	"fmt"

	"github.com/oarkflow/licensing/pkg/device"
)

// getDeviceBoundKey derives a device-specific key component
func getDeviceBoundKey() ([]byte, error) {
	info, err := device.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get device info: %w", err)
	}

	hash := sha256.Sum256([]byte(info.Fingerprint))
	return hash[:], nil
}

// combineWithDeviceKey combines master key with device-specific component
func combineWithDeviceKey(masterKey []byte) ([]byte, error) {
	deviceKey, err := getDeviceBoundKey()
	if err != nil {
		return nil, err
	}

	// XOR the keys for combination
	combined := make([]byte, len(masterKey))
	for i := range masterKey {
		combined[i] = masterKey[i] ^ deviceKey[i%len(deviceKey)]
	}

	return combined, nil
}

// GetCurrentDeviceFingerprint returns the current device fingerprint
func GetCurrentDeviceFingerprint() (string, error) {
	info, err := device.GetInfo()
	if err != nil {
		return "", err
	}
	return info.Fingerprint, nil
}
