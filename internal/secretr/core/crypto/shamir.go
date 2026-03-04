package crypto

import (
	"encoding/base64"
	"fmt"

	"github.com/oarkflow/shamir"
)

// Split splits a secret into parts using Shamir's Secret Sharing
func Split(secret []byte, parts, threshold int) ([]string, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("crypto: secret cannot be empty")
	}
	if parts < threshold {
		return nil, fmt.Errorf("crypto: parts cannot be less than threshold")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("crypto: threshold must be at least 2")
	}

	shares, err := shamir.Split(secret, threshold, parts)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to split secret: %w", err)
	}

	// Convert to base64 strings for storage
	encodedShares := make([]string, len(shares))
	for i, share := range shares {
		encodedShares[i] = base64.StdEncoding.EncodeToString(share)
	}

	return encodedShares, nil
}

// Combine reconstructs a secret from parts
func Combine(shares []string) ([]byte, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("crypto: at least 2 parts are required")
	}

	decodedShares := make([][]byte, len(shares))
	for i, share := range shares {
		decoded, err := base64.StdEncoding.DecodeString(share)
		if err != nil {
			return nil, fmt.Errorf("crypto: failed to decode share: %w", err)
		}
		decodedShares[i] = decoded
	}

	secret, err := shamir.Combine(decodedShares)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to combine secret: %w", err)
	}

	return secret, nil
}
