// Package cicd provides CI/CD pipeline identity and policy enforcement functionality.
package cicd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/securitymode"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrPipelineNotFound = errors.New("cicd: pipeline not found")
	ErrPolicyNotFound   = errors.New("cicd: policy not found")
	ErrPolicyViolation  = errors.New("cicd: policy violation")
	ErrAuthFailed       = errors.New("cicd: authentication failed")
	ErrSecretNotAllowed = errors.New("cicd: secret access not allowed")
	ErrBranchNotAllowed = errors.New("cicd: branch not allowed")
	ErrEnvNotAllowed    = errors.New("cicd: environment not allowed")
)

// SecretInjection represents secrets to be injected
type SecretInjection struct {
	SecretID    types.ID `json:"secret_id"`
	Name        string   `json:"name"`
	Value       string   `json:"value,omitempty"` // Only populated on inject
	Environment string   `json:"environment"`
}

// Manager handles CI/CD pipeline operations
type Manager struct {
	store           *storage.Store
	crypto          *crypto.Engine
	auditEngine     *audit.Engine
	pipelineStore   *storage.TypedStore[types.PipelineIdentity]
	policyStore     *storage.TypedStore[types.PipelinePolicy]
	tokenStore      *storage.TypedStore[pipelineToken]
	secretRetriever SecretRetriever
	httpClient      *http.Client
	oidcJWKSURL     string
}

// pipelineToken stores authentication tokens for pipelines
type pipelineToken struct {
	PipelineID types.ID        `json:"pipeline_id"`
	TokenHash  string          `json:"token_hash"`
	CreatedAt  types.Timestamp `json:"created_at"`
	ExpiresAt  types.Timestamp `json:"expires_at"`
}

// SecretRetriever is a callback to retrieve secret values
type SecretRetriever func(ctx context.Context, secretID types.ID, environment string) (string, error)

// ManagerConfig configures the CI/CD manager
type ManagerConfig struct {
	Store           *storage.Store
	AuditEngine     *audit.Engine
	SecretRetriever SecretRetriever
	OIDCJWKSURL     string
}

// NewManager creates a new CI/CD manager
func NewManager(cfg ManagerConfig) *Manager {
	return &Manager{
		store:           cfg.Store,
		crypto:          crypto.NewEngine(""),
		auditEngine:     cfg.AuditEngine,
		pipelineStore:   storage.NewTypedStore[types.PipelineIdentity](cfg.Store, "pipelines"),
		policyStore:     storage.NewTypedStore[types.PipelinePolicy](cfg.Store, "pipeline_policies"),
		tokenStore:      storage.NewTypedStore[pipelineToken](cfg.Store, "pipeline_tokens"),
		secretRetriever: cfg.SecretRetriever,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
		oidcJWKSURL:     strings.TrimSpace(cfg.OIDCJWKSURL),
	}
}

// PipelineIdentityOptions holds pipeline creation options
type PipelineIdentityOptions struct {
	Name           string
	Provider       types.PipelineProvider
	RepositoryID   string
	BranchPatterns []string
	AllowedSecrets []types.ID
	SecretPatterns []string
	PolicyID       *types.ID
	OrgID          types.ID
	CreatorID      types.ID
}

// CreatePipelineIdentity creates a new pipeline identity
func (m *Manager) CreatePipelineIdentity(ctx context.Context, opts PipelineIdentityOptions) (*types.PipelineIdentity, string, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, "", err
	}

	now := types.Now()
	pipeline := &types.PipelineIdentity{
		ID:             id,
		Name:           opts.Name,
		Provider:       opts.Provider,
		RepositoryID:   opts.RepositoryID,
		BranchPatterns: opts.BranchPatterns,
		AllowedSecrets: opts.AllowedSecrets,
		SecretPatterns: opts.SecretPatterns,
		PolicyID:       opts.PolicyID,
		OrgID:          opts.OrgID,
		CreatedAt:      now,
		UpdatedAt:      now,
		Status:         types.StatusActive,
	}

	if err := m.pipelineStore.Set(ctx, string(id), pipeline); err != nil {
		return nil, "", err
	}

	// Generate API token
	token, err := m.generateToken(ctx, id)
	if err != nil {
		return nil, "", err
	}

	// Audit log
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "cicd",
			Action:       "pipeline_create",
			ActorID:      opts.CreatorID,
			ActorType:    "identity",
			ResourceID:   &id,
			ResourceType: "pipeline",
			Success:      true,
			Details: types.Metadata{
				"provider":   string(opts.Provider),
				"repository": opts.RepositoryID,
			},
		})
	}

	return pipeline, token, nil
}

// generateToken generates an authentication token for a pipeline
func (m *Manager) generateToken(ctx context.Context, pipelineID types.ID) (string, error) {
	// Generate random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)

	// Hash for storage
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	now := types.Now()
	expires := types.Timestamp(time.Now().Add(365 * 24 * time.Hour).UnixNano())

	pt := &pipelineToken{
		PipelineID: pipelineID,
		TokenHash:  tokenHash,
		CreatedAt:  now,
		ExpiresAt:  expires,
	}

	if err := m.tokenStore.Set(ctx, string(pipelineID), pt); err != nil {
		return "", err
	}

	return token, nil
}

// GetPipelineIdentity retrieves a pipeline identity
func (m *Manager) GetPipelineIdentity(ctx context.Context, id types.ID) (*types.PipelineIdentity, error) {
	pipeline, err := m.pipelineStore.Get(ctx, string(id))
	if err != nil {
		return nil, ErrPipelineNotFound
	}
	return pipeline, nil
}

// ListPipelineIdentities lists pipelines for an organization
func (m *Manager) ListPipelineIdentities(ctx context.Context, orgID types.ID) ([]*types.PipelineIdentity, error) {
	all, err := m.pipelineStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var pipelines []*types.PipelineIdentity
	for _, p := range all {
		if p.OrgID == orgID && p.Status == types.StatusActive {
			pipelines = append(pipelines, p)
		}
	}
	return pipelines, nil
}

// AuthenticatePipeline authenticates a pipeline using its token
func (m *Manager) AuthenticatePipeline(ctx context.Context, pipelineID types.ID, token string) (*types.PipelineIdentity, error) {
	pipeline, err := m.GetPipelineIdentity(ctx, pipelineID)
	if err != nil {
		return nil, err
	}

	if pipeline.Status != types.StatusActive {
		return nil, ErrAuthFailed
	}

	// Get stored token
	storedToken, err := m.tokenStore.Get(ctx, string(pipelineID))
	if err != nil {
		// If static token not found/failed, try OIDC if provided token looks like OIDC
		// For simplicity in this flow, we might need a separate method or flag, or just try both.
		// However, OIDC usually authenticates the *identity* which then maps to a pipeline.
		// Use case: "Login with OIDC" -> "Get Session".
		// But here we are asked to "AuthenticatePipeline" with a token.

		// If the token starts with "gh_oidc_", try to verify it as OIDC
		if len(token) > 8 && token[:8] == "gh_oidc_" && pipeline.Provider == types.PipelineProviderGitHub {
			claims, errOIDC := m.VerifyOIDCToken(ctx, token, types.PipelineProviderGitHub)
			if errOIDC == nil && claims != nil {
				// Verify claims match pipeline identity (e.g. repository)
				// Simplify: if pipeline.RepositoryID == claims.Repository
				if pipeline.RepositoryID == claims.Repository {
					// Audit OIDC Success
					if m.auditEngine != nil {
						m.auditEngine.Log(ctx, audit.AuditEventInput{
							Type:         "cicd",
							Action:       "pipeline_auth_oidc",
							ActorID:      pipelineID,
							ActorType:    "pipeline",
							ResourceID:   &pipelineID,
							ResourceType: "pipeline",
							Success:      true,
						})
					}
					return pipeline, nil
				}
			}
		}

		return nil, ErrAuthFailed
	}

	// Check expiration
	if types.Now() > storedToken.ExpiresAt {
		return nil, ErrAuthFailed
	}

	// Verify token hash
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])
	if tokenHash != storedToken.TokenHash {
		return nil, ErrAuthFailed
	}

	// Audit log
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "cicd",
			Action:       "pipeline_auth",
			ActorID:      pipelineID,
			ActorType:    "pipeline",
			ResourceID:   &pipelineID,
			ResourceType: "pipeline",
			Success:      true,
		})
	}

	return pipeline, nil
}

// AuthenticatePipelineOIDC authenticates a pipeline using OIDC token (federation)
func (m *Manager) AuthenticatePipelineOIDC(ctx context.Context, token string, provider types.PipelineProvider) (*types.PipelineIdentity, error) {
	claims, err := m.VerifyOIDCToken(ctx, token, provider)
	if err != nil {
		return nil, ErrAuthFailed
	}

	// Find pipeline matching repository and provider
	pipelines, err := m.pipelineStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	for _, p := range pipelines {
		if p.Provider == provider && p.RepositoryID == claims.Repository && p.Status == types.StatusActive {
			// Audit OIDC Success
			if m.auditEngine != nil {
				m.auditEngine.Log(ctx, audit.AuditEventInput{
					Type:         "cicd",
					Action:       "pipeline_auth_oidc_federated",
					ActorID:      p.ID,
					ActorType:    "pipeline",
					ResourceID:   &p.ID,
					ResourceType: "pipeline",
					Success:      true,
					Details: types.Metadata{
						"repository": claims.Repository,
						"ref":        claims.Ref,
					},
				})
			}
			return p, nil
		}
	}

	return nil, ErrPipelineNotFound
}

// PolicyOptions holds policy creation options
type PolicyOptions struct {
	Name                string
	Description         string
	RequiredApprovals   int
	AllowedEnvironments []string
	BranchRestrictions  []string
	MaxSecretAgeSeconds int64
	RequireRotation     bool
	CreatorID           types.ID
}

// CreatePolicy creates a CI/CD policy
func (m *Manager) CreatePolicy(ctx context.Context, opts PolicyOptions) (*types.PipelinePolicy, error) {
	id, err := m.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	now := types.Now()
	policy := &types.PipelinePolicy{
		ID:                  id,
		Name:                opts.Name,
		Description:         opts.Description,
		RequiredApprovals:   opts.RequiredApprovals,
		AllowedEnvironments: opts.AllowedEnvironments,
		BranchRestrictions:  opts.BranchRestrictions,
		MaxSecretAge:        opts.MaxSecretAgeSeconds,
		RequireRotation:     opts.RequireRotation,
		CreatedAt:           now,
		UpdatedAt:           now,
		Status:              types.StatusActive,
	}

	if err := m.policyStore.Set(ctx, string(id), policy); err != nil {
		return nil, err
	}

	return policy, nil
}

// GetPolicy retrieves a policy
func (m *Manager) GetPolicy(ctx context.Context, id types.ID) (*types.PipelinePolicy, error) {
	policy, err := m.policyStore.Get(ctx, string(id))
	if err != nil {
		return nil, ErrPolicyNotFound
	}
	return policy, nil
}

// EnforcePolicy enforces a policy for a pipeline operation
func (m *Manager) EnforcePolicy(ctx context.Context, pipelineID types.ID, branch string, environment string) error {
	pipeline, err := m.GetPipelineIdentity(ctx, pipelineID)
	if err != nil {
		return err
	}

	if pipeline.PolicyID == nil {
		return nil // No policy to enforce
	}

	policy, err := m.GetPolicy(ctx, *pipeline.PolicyID)
	if err != nil {
		return err
	}

	// Check branch restrictions
	if len(policy.BranchRestrictions) > 0 && branch != "" {
		allowed := false
		for _, pattern := range policy.BranchRestrictions {
			if matchPattern(pattern, branch) {
				allowed = true
				break
			}
		}
		if !allowed {
			return ErrBranchNotAllowed
		}
	}

	// Check environment restrictions
	if len(policy.AllowedEnvironments) > 0 && environment != "" {
		allowed := false
		for _, env := range policy.AllowedEnvironments {
			if env == environment || env == "*" {
				allowed = true
				break
			}
		}
		if !allowed {
			return ErrEnvNotAllowed
		}
	}

	return nil
}

// matchPattern matches a branch against a pattern (supports * wildcards)
func matchPattern(pattern, value string) bool {
	// Convert glob to regex
	regexPattern := "^" + regexp.QuoteMeta(pattern)
	regexPattern = regexp.MustCompile(`\\\*`).ReplaceAllString(regexPattern, ".*")
	regexPattern += "$"

	matched, _ := regexp.MatchString(regexPattern, value)
	return matched
}

// ValidateSecretAccess validates if a pipeline can access secrets
func (m *Manager) ValidateSecretAccess(ctx context.Context, pipelineID types.ID, secretIDs []types.ID) error {
	pipeline, err := m.GetPipelineIdentity(ctx, pipelineID)
	if err != nil {
		return err
	}

	allowedSet := make(map[types.ID]bool)
	for _, id := range pipeline.AllowedSecrets {
		allowedSet[id] = true
	}

	for _, secretID := range secretIDs {
		if allowedSet[secretID] {
			continue
		}

		// Check patterns
		matched := false
		for _, pattern := range pipeline.SecretPatterns {
			if matchPattern(pattern, string(secretID)) {
				matched = true
				break
			}
		}

		if !matched {
			return ErrSecretNotAllowed
		}
	}

	return nil
}

// InjectSecrets retrieves secrets for a pipeline to inject
func (m *Manager) InjectSecrets(ctx context.Context, pipelineID types.ID, environment string, branch string) ([]SecretInjection, error) {
	pipeline, err := m.GetPipelineIdentity(ctx, pipelineID)
	if err != nil {
		return nil, err
	}

	// Enforce policy first
	if err := m.EnforcePolicy(ctx, pipelineID, branch, environment); err != nil {
		return nil, err
	}

	if m.secretRetriever == nil {
		return nil, errors.New("cicd: secret retriever not configured")
	}

	var injections []SecretInjection
	for _, secretID := range pipeline.AllowedSecrets {
		value, err := m.secretRetriever(ctx, secretID, environment)
		if err != nil {
			continue // Skip secrets that can't be retrieved
		}

		injections = append(injections, SecretInjection{
			SecretID:    secretID,
			Name:        string(secretID), // Would need secret metadata for proper name
			Value:       value,
			Environment: environment,
		})
	}

	// Audit log
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "cicd",
			Action:       "secret_inject",
			ActorID:      pipelineID,
			ActorType:    "pipeline",
			ResourceID:   &pipelineID,
			ResourceType: "pipeline",
			Success:      true,
			Details: types.Metadata{
				"environment":  environment,
				"branch":       branch,
				"secret_count": len(injections),
			},
		})
	}

	return injections, nil
}

// RotateToken rotates the authentication token for a pipeline
func (m *Manager) RotateToken(ctx context.Context, pipelineID types.ID) (string, error) {
	_, err := m.GetPipelineIdentity(ctx, pipelineID)
	if err != nil {
		return "", err
	}

	return m.generateToken(ctx, pipelineID)
}

// RevokePipeline revokes a pipeline identity
func (m *Manager) RevokePipeline(ctx context.Context, pipelineID types.ID, revokerID types.ID) error {
	pipeline, err := m.GetPipelineIdentity(ctx, pipelineID)
	if err != nil {
		return err
	}

	pipeline.Status = types.StatusRevoked
	pipeline.UpdatedAt = types.Now()

	if err := m.pipelineStore.Set(ctx, string(pipelineID), pipeline); err != nil {
		return err
	}

	// Delete token
	m.tokenStore.Delete(ctx, string(pipelineID))

	// Audit log
	if m.auditEngine != nil {
		m.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "cicd",
			Action:       "pipeline_revoke",
			ActorID:      revokerID,
			ActorType:    "identity",
			ResourceID:   &pipelineID,
			ResourceType: "pipeline",
			Success:      true,
		})
	}

	return nil
}

// Close cleans up resources
func (m *Manager) Close() error {
	return m.crypto.Close()
}

// OIDCTokenClaims represents claims in an OIDC token
// OIDCTokenClaims represents claims in an OIDC token
type OIDCTokenClaims struct {
	jwt.RegisteredClaims
	Repository string                 `json:"repository"`
	Ref        string                 `json:"ref"`
	Custom     map[string]interface{} `json:"-"`
}

// VerifyOIDCToken verifies an OIDC token for a given provider
func (m *Manager) VerifyOIDCToken(ctx context.Context, token string, provider types.PipelineProvider) (*OIDCTokenClaims, error) {
	if provider == types.PipelineProviderGitHub {
		return m.validateGitHubToken(ctx, token)
	}

	// Default fail for unknown providers
	return nil, errors.New("cicd: provider OIDC not supported")
}

// validateGitHubToken validates a GitHub OIDC token
func (m *Manager) validateGitHubToken(ctx context.Context, tokenString string) (*OIDCTokenClaims, error) {
	parser := jwt.NewParser(jwt.WithExpirationRequired(), jwt.WithIssuer("https://token.actions.githubusercontent.com"))

	token, err := parser.ParseWithClaims(tokenString, &OIDCTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		method, ok := token.Method.(*jwt.SigningMethodRSA)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		if method.Alg() != jwt.SigningMethodRS256.Alg() && method.Alg() != jwt.SigningMethodRS512.Alg() && method.Alg() != jwt.SigningMethodRS384.Alg() {
			return nil, fmt.Errorf("unsupported RSA signing algorithm: %s", method.Alg())
		}

		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing OIDC key id (kid)")
		}

		jwksURL := "https://token.actions.githubusercontent.com/.well-known/jwks"
		if override := strings.TrimSpace(m.oidcJWKSURL); override != "" {
			jwksURL = override
		}
		if override, ok := securitymode.OIDCJWKSURLEnvOverride(); ok && strings.TrimSpace(override) != "" {
			jwksURL = strings.TrimSpace(override)
		}

		pubKey, keyErr := m.fetchJWKSRSAKey(ctx, jwksURL, kid)
		if keyErr != nil {
			return nil, keyErr
		}
		return pubKey, nil
	})

	if err != nil {
		if securitymode.AllowInsecureOIDCMock() && len(tokenString) > 8 && tokenString[:8] == "gh_oidc_" {
			return &OIDCTokenClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "https://token.actions.githubusercontent.com",
					Subject:   "repo:org/repo:ref:refs/heads/main",
					Audience:  jwt.ClaimStrings{"secretr"},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				},
				Repository: "org/repo",
				Ref:        "refs/heads/main",
			}, nil
		}
		return nil, err
	}

	if claims, ok := token.Claims.(*OIDCTokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrAuthFailed
}

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

func (m *Manager) fetchJWKSRSAKey(ctx context.Context, jwksURL, kid string) (*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to fetch JWKS: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("invalid JWKS payload: %w", err)
	}

	for _, key := range doc.Keys {
		if key.Kid != kid || key.Kty != "RSA" {
			continue
		}
		nBytes, nErr := base64.RawURLEncoding.DecodeString(key.N)
		if nErr != nil {
			return nil, fmt.Errorf("invalid jwk modulus encoding for kid %s: %w", kid, nErr)
		}
		eBytes, eErr := base64.RawURLEncoding.DecodeString(key.E)
		if eErr != nil {
			return nil, fmt.Errorf("invalid jwk exponent encoding for kid %s: %w", kid, eErr)
		}
		eInt := 0
		for _, b := range eBytes {
			eInt = eInt<<8 + int(b)
		}
		if eInt == 0 {
			return nil, fmt.Errorf("invalid jwk exponent for kid %s", kid)
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: eInt,
		}, nil
	}

	return nil, fmt.Errorf("no matching rsa key found in JWKS for kid %s", kid)
}
