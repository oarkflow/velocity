package velocity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// STS store key prefix
const stsSessionPrefix = "sts:session:"

// STSCredentials represents temporary security credentials.
type STSCredentials struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey  string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token"`
	Expiration      time.Time `json:"expiration"`
}

// STSSession represents an active STS session stored in the DB.
type STSSession struct {
	SessionToken    string    `json:"session_token"`
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey  string    `json:"secret_access_key"`
	UserID          string    `json:"user_id"`
	RoleARN         string    `json:"role_arn,omitempty"`
	SourceIdentity  string    `json:"source_identity,omitempty"`
	PolicyARNs      []string  `json:"policy_arns,omitempty"`
	Expiration      time.Time `json:"expiration"`
	CreatedAt       time.Time `json:"created_at"`
	Revoked         bool      `json:"revoked"`
}

// AssumeRoleInput contains parameters for AssumeRole.
type AssumeRoleInput struct {
	RoleARN         string        `json:"role_arn"`
	RoleSessionName string        `json:"role_session_name"`
	DurationSeconds int           `json:"duration_seconds,omitempty"` // default 3600, max 43200
	PolicyARNs      []string      `json:"policy_arns,omitempty"`
	ExternalID      string        `json:"external_id,omitempty"`
}

// AssumeRoleWithWebIdentityInput contains parameters for AssumeRoleWithWebIdentity.
type AssumeRoleWithWebIdentityInput struct {
	RoleARN          string   `json:"role_arn"`
	RoleSessionName  string   `json:"role_session_name"`
	WebIdentityToken string   `json:"web_identity_token"`
	DurationSeconds  int      `json:"duration_seconds,omitempty"`
	PolicyARNs       []string `json:"policy_arns,omitempty"`
	ProviderID       string   `json:"provider_id,omitempty"`
}

// AssumeRoleWithLDAPInput contains parameters for AssumeRoleWithLDAP.
type AssumeRoleWithLDAPInput struct {
	RoleARN         string   `json:"role_arn"`
	RoleSessionName string   `json:"role_session_name"`
	Username        string   `json:"username"`
	Password        string   `json:"password"`
	DurationSeconds int      `json:"duration_seconds,omitempty"`
	PolicyARNs      []string `json:"policy_arns,omitempty"`
}

// AssumeRoleOutput contains the result of an AssumeRole call.
type AssumeRoleOutput struct {
	Credentials    *STSCredentials `json:"credentials"`
	AssumedRoleID  string          `json:"assumed_role_id"`
	PackedPolicies []string        `json:"packed_policies,omitempty"`
}

// STSService provides Security Token Service functionality.
type STSService struct {
	db           *DB
	iamEngine    *IAMPolicyEngine
	oidcProvider *OIDCProvider
	ldapProvider *LDAPProvider
	mu           sync.RWMutex
	stopCh       chan struct{}
}

// NewSTSService creates a new Security Token Service.
func NewSTSService(db *DB, opts ...STSOption) *STSService {
	s := &STSService{
		db:     db,
		stopCh: make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// STSOption configures the STS service.
type STSOption func(*STSService)

// WithIAMEngine sets the IAM policy engine for role validation.
func WithIAMEngine(engine *IAMPolicyEngine) STSOption {
	return func(s *STSService) {
		s.iamEngine = engine
	}
}

// WithOIDCProvider sets the OIDC provider for web identity federation.
func WithOIDCProvider(provider *OIDCProvider) STSOption {
	return func(s *STSService) {
		s.oidcProvider = provider
	}
}

// WithLDAPProvider sets the LDAP provider for LDAP federation.
func WithLDAPProvider(provider *LDAPProvider) STSOption {
	return func(s *STSService) {
		s.ldapProvider = provider
	}
}

// AssumeRole creates temporary credentials for the specified role.
func (s *STSService) AssumeRole(userID string, input *AssumeRoleInput) (*AssumeRoleOutput, error) {
	if input.RoleARN == "" {
		return nil, fmt.Errorf("sts: RoleARN is required")
	}
	if input.RoleSessionName == "" {
		return nil, fmt.Errorf("sts: RoleSessionName is required")
	}

	duration := time.Duration(input.DurationSeconds) * time.Second
	if duration == 0 {
		duration = 1 * time.Hour
	}
	if duration < 15*time.Minute {
		duration = 15 * time.Minute
	}
	if duration > 12*time.Hour {
		duration = 12 * time.Hour
	}

	creds, err := s.generateCredentials(duration)
	if err != nil {
		return nil, err
	}

	session := &STSSession{
		SessionToken:   creds.SessionToken,
		AccessKeyID:    creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		UserID:         userID,
		RoleARN:        input.RoleARN,
		SourceIdentity: input.RoleSessionName,
		PolicyARNs:     input.PolicyARNs,
		Expiration:     creds.Expiration,
		CreatedAt:      time.Now(),
	}

	if err := s.saveSession(session); err != nil {
		return nil, err
	}

	return &AssumeRoleOutput{
		Credentials:   creds,
		AssumedRoleID: fmt.Sprintf("%s:%s", input.RoleARN, input.RoleSessionName),
	}, nil
}

// AssumeRoleWithWebIdentity creates temporary credentials using an OIDC web identity token.
func (s *STSService) AssumeRoleWithWebIdentity(input *AssumeRoleWithWebIdentityInput) (*AssumeRoleOutput, error) {
	if s.oidcProvider == nil {
		return nil, fmt.Errorf("sts: OIDC provider not configured")
	}
	if input.WebIdentityToken == "" {
		return nil, fmt.Errorf("sts: WebIdentityToken is required")
	}

	// Validate the web identity token
	claims, err := s.oidcProvider.ValidateToken(input.WebIdentityToken)
	if err != nil {
		return nil, fmt.Errorf("sts: web identity token validation failed: %w", err)
	}

	duration := time.Duration(input.DurationSeconds) * time.Second
	if duration == 0 {
		duration = 1 * time.Hour
	}
	if duration < 15*time.Minute {
		duration = 15 * time.Minute
	}
	if duration > 12*time.Hour {
		duration = 12 * time.Hour
	}

	creds, err := s.generateCredentials(duration)
	if err != nil {
		return nil, err
	}

	session := &STSSession{
		SessionToken:   creds.SessionToken,
		AccessKeyID:    creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		UserID:         claims.Subject,
		RoleARN:        input.RoleARN,
		SourceIdentity: input.RoleSessionName,
		PolicyARNs:     input.PolicyARNs,
		Expiration:     creds.Expiration,
		CreatedAt:      time.Now(),
	}

	if err := s.saveSession(session); err != nil {
		return nil, err
	}

	return &AssumeRoleOutput{
		Credentials:   creds,
		AssumedRoleID: fmt.Sprintf("%s:%s", input.RoleARN, input.RoleSessionName),
	}, nil
}

// AssumeRoleWithLDAP creates temporary credentials using LDAP authentication.
func (s *STSService) AssumeRoleWithLDAP(input *AssumeRoleWithLDAPInput) (*AssumeRoleOutput, error) {
	if s.ldapProvider == nil {
		return nil, fmt.Errorf("sts: LDAP provider not configured")
	}
	if input.Username == "" || input.Password == "" {
		return nil, fmt.Errorf("sts: username and password are required")
	}

	// Authenticate via LDAP
	ldapUser, err := s.ldapProvider.Authenticate(input.Username, input.Password)
	if err != nil {
		return nil, fmt.Errorf("sts: LDAP authentication failed: %w", err)
	}

	duration := time.Duration(input.DurationSeconds) * time.Second
	if duration == 0 {
		duration = 1 * time.Hour
	}
	if duration < 15*time.Minute {
		duration = 15 * time.Minute
	}
	if duration > 12*time.Hour {
		duration = 12 * time.Hour
	}

	creds, err := s.generateCredentials(duration)
	if err != nil {
		return nil, err
	}

	session := &STSSession{
		SessionToken:   creds.SessionToken,
		AccessKeyID:    creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		UserID:         ldapUser.DN,
		RoleARN:        input.RoleARN,
		SourceIdentity: input.RoleSessionName,
		PolicyARNs:     input.PolicyARNs,
		Expiration:     creds.Expiration,
		CreatedAt:      time.Now(),
	}

	if err := s.saveSession(session); err != nil {
		return nil, err
	}

	return &AssumeRoleOutput{
		Credentials:   creds,
		AssumedRoleID: fmt.Sprintf("%s:%s", input.RoleARN, input.RoleSessionName),
	}, nil
}

// ValidateSessionToken checks if a session token is valid (not expired and not revoked).
func (s *STSService) ValidateSessionToken(token string) (*STSSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, err := s.loadSession(token)
	if err != nil {
		return nil, fmt.Errorf("sts: invalid session token: %w", err)
	}

	if session.Revoked {
		return nil, fmt.Errorf("sts: session has been revoked")
	}

	if time.Now().After(session.Expiration) {
		return nil, fmt.Errorf("sts: session has expired")
	}

	return session, nil
}

// RevokeSession marks a session as revoked.
func (s *STSService) RevokeSession(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, err := s.loadSession(token)
	if err != nil {
		return fmt.Errorf("sts: session not found: %w", err)
	}

	session.Revoked = true
	return s.saveSession(session)
}

// CleanupExpired removes all expired sessions from the store.
func (s *STSService) CleanupExpired() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keys, err := s.db.Keys(stsSessionPrefix + "*")
	if err != nil {
		return 0, fmt.Errorf("sts: failed to list sessions: %w", err)
	}

	now := time.Now()
	removed := 0
	for _, key := range keys {
		data, err := s.db.Get([]byte(key))
		if err != nil {
			continue
		}
		var session STSSession
		if json.Unmarshal(data, &session) != nil {
			continue
		}
		if now.After(session.Expiration) {
			if err := s.db.Delete([]byte(key)); err == nil {
				removed++
			}
		}
	}

	return removed, nil
}

// StartCleanup starts a background goroutine that periodically cleans up expired sessions.
func (s *STSService) StartCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_, _ = s.CleanupExpired()
			case <-s.stopCh:
				return
			}
		}
	}()
}

// Stop halts background processes.
func (s *STSService) Stop() {
	close(s.stopCh)
}

// generateCredentials creates a new set of temporary security credentials.
func (s *STSService) generateCredentials(duration time.Duration) (*STSCredentials, error) {
	accessKey, err := generateSecureToken(20)
	if err != nil {
		return nil, fmt.Errorf("sts: failed to generate access key: %w", err)
	}

	secretKey, err := generateSecureToken(40)
	if err != nil {
		return nil, fmt.Errorf("sts: failed to generate secret key: %w", err)
	}

	sessionToken, err := generateSecureToken(64)
	if err != nil {
		return nil, fmt.Errorf("sts: failed to generate session token: %w", err)
	}

	return &STSCredentials{
		AccessKeyID:    "AKIA" + strings.ToUpper(accessKey[:16]),
		SecretAccessKey: secretKey,
		SessionToken:   sessionToken,
		Expiration:     time.Now().Add(duration),
	}, nil
}

// generateSecureToken generates a cryptographically secure random hex token.
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	// Hash to get uniform distribution
	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:])[:length], nil
}

func (s *STSService) saveSession(session *STSSession) error {
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("sts: failed to marshal session: %w", err)
	}

	// Use PutWithTTL if available, keyed by session token
	ttl := time.Until(session.Expiration)
	if ttl <= 0 {
		ttl = time.Minute // minimum TTL for already-expired sessions being saved (e.g., revoked)
	}
	return s.db.PutWithTTL([]byte(stsSessionPrefix+session.SessionToken), data, ttl)
}

func (s *STSService) loadSession(token string) (*STSSession, error) {
	data, err := s.db.Get([]byte(stsSessionPrefix + token))
	if err != nil {
		return nil, err
	}
	var session STSSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}
	return &session, nil
}
