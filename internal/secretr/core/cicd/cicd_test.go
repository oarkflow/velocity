package cicd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

func TestPipelineInjection(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := storage.NewStore(storage.Config{Path: tmpDir, EncryptionKey: make([]byte, 32)})
	defer store.Close()

	// Mock Secret Retriever
	secretRetriever := func(ctx context.Context, secretID types.ID, env string) (string, error) {
		if secretID == "db_password" {
			return "secret_value_123", nil
		}
		return "", nil
	}

	manager := NewManager(ManagerConfig{
		Store:           store,
		SecretRetriever: secretRetriever,
	})
	defer manager.Close()

	ctx := context.Background()

	// 1. Create Pipeline Identity
	pipeline, _, err := manager.CreatePipelineIdentity(ctx, PipelineIdentityOptions{
		Name:           "My Pipeline",
		Provider:       types.PipelineProviderGitHub,
		RepositoryID:   "org/repo",
		AllowedSecrets: []types.ID{"db_password"},
		CreatorID:      "admin",
	})
	if err != nil {
		t.Logf("CreatePipelineIdentity error: %v. Assuming ProviderGitHub const might be wrong, checking types...", err)
		// Usually if type mismatch, build fails.
		// If ProviderGitHub is not defined, we'll see build error.
		t.Fatalf("CreatePipelineIdentity failed: %v", err)
	}

	// 2. Inject Secrets (No Policy yet)
	// Default: deny? Or allow if no policy?
	// EnforcePolicy checks `if pipeline.PolicyID == nil { return nil }`. So ALLOW.

	injections, err := manager.InjectSecrets(ctx, pipeline.ID, "prod", "main")
	if err != nil {
		t.Fatalf("InjectSecrets failed: %v", err)
	}

	if len(injections) != 1 {
		t.Errorf("Expected 1 injection, got %d", len(injections))
	}
	if injections[0].Value != "secret_value_123" {
		t.Errorf("Secret value mismatch")
	}

	// 3. Create Policy (Restrict to 'main' branch)
	policy, err := manager.CreatePolicy(ctx, PolicyOptions{
		Name:                "Prod Policy",
		AllowedEnvironments: []string{"prod"},
		BranchRestrictions:  []string{"main"},
	})
	if err != nil {
		t.Fatalf("CreatePolicy failed: %v", err)
	}

	// Attach Policy
	pipeline.PolicyID = &policy.ID
	manager.pipelineStore.Set(ctx, string(pipeline.ID), pipeline)

	// 4. Inject with valid branch
	_, err = manager.InjectSecrets(ctx, pipeline.ID, "prod", "main")
	if err != nil {
		t.Errorf("Injection should succeed for main branch: %v", err)
	}

	// 5. Inject with invalid branch
	_, err = manager.InjectSecrets(ctx, pipeline.ID, "prod", "feature/123")
	if err == nil {
		t.Errorf("Injection should fail for feature branch")
	} else if err != ErrBranchNotAllowed {
		t.Errorf("Expected ErrBranchNotAllowed, got %v", err)
	}
}

func TestVerifyGitHubOIDCTokenWithJWKS(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := storage.NewStore(storage.Config{Path: tmpDir, EncryptionKey: make([]byte, 32)})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	manager := NewManager(ManagerConfig{Store: store})
	defer manager.Close()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	kid := "test-kid-1"

	n := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes())
	eBytes := []byte{byte(privateKey.PublicKey.E >> 16), byte(privateKey.PublicKey.E >> 8), byte(privateKey.PublicKey.E)}
	e := base64.RawURLEncoding.EncodeToString(trimLeadingZeros(eBytes))

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": kid,
					"alg": "RS256",
					"use": "sig",
					"n":   n,
					"e":   e,
				},
			},
		})
	}))
	defer jwksServer.Close()

	t.Setenv("SECRETR_OIDC_JWKS_URL", jwksServer.URL)
	_ = os.Unsetenv("SECRETR_OIDC_ALLOW_INSECURE_MOCK")

	claims := OIDCTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://token.actions.githubusercontent.com",
			Subject:   "repo:org/repo:ref:refs/heads/main",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		Repository: "org/repo",
		Ref:        "refs/heads/main",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	parsed, err := manager.VerifyOIDCToken(context.Background(), tokenString, types.PipelineProviderGitHub)
	if err != nil {
		t.Fatalf("verify oidc token: %v", err)
	}
	if parsed.Repository != "org/repo" {
		t.Fatalf("repository mismatch: %q", parsed.Repository)
	}
}

func trimLeadingZeros(b []byte) []byte {
	for i := 0; i < len(b); i++ {
		if b[i] != 0 {
			return b[i:]
		}
	}
	return []byte{0}
}
