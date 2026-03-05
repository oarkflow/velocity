package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oarkflow/velocity/internal/secretr/securitymode"
)

// resolveOrCreateJWTSecret returns a stable JWT secret for Secretr runtime.
// Priority:
// 1) SECRETR_JWT_SECRET env var
// 2) dataDir/jwt.secret file
// 3) generated random secret persisted to dataDir/jwt.secret
func resolveOrCreateJWTSecret(dataDir string) string {
	if securitymode.AllowJWTSecretEnvOverride() {
		if v := strings.TrimSpace(os.Getenv("SECRETR_JWT_SECRET")); v != "" {
			return v
		}
	}

	secretPath := filepath.Join(dataDir, "jwt.secret")
	if data, err := os.ReadFile(secretPath); err == nil {
		if v := strings.TrimSpace(string(data)); v != "" {
			return v
		}
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("failed to generate JWT secret: %v", err))
	}
	secret := hex.EncodeToString(buf)
	_ = os.MkdirAll(dataDir, 0700)
	_ = os.WriteFile(secretPath, []byte(secret), 0600)
	return secret
}
