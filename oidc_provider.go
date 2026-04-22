package velocity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OIDC store key prefix
const oidcProviderPrefix = "oidc:provider:"

// OIDCConfig holds configuration for an OpenID Connect provider.
type OIDCConfig struct {
	Name         string            `json:"name"`
	ProviderURL  string            `json:"provider_url"`  // e.g. https://accounts.google.com
	ClientID     string            `json:"client_id"`
	ClientSecret string            `json:"client_secret"`
	RedirectURL  string            `json:"redirect_url"`
	Scopes       []string          `json:"scopes"`
	ClaimMapping map[string]string `json:"claim_mapping"` // OIDC claim -> Velocity field
	RoleMapping  map[string]string `json:"role_mapping"`  // OIDC group/role -> Velocity role
}

// OIDCDiscovery represents the OpenID Connect discovery document.
type OIDCDiscovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	SupportedScopes       []string `json:"scopes_supported"`
	SupportedClaims       []string `json:"claims_supported"`
}

// OIDCTokenResponse represents the token endpoint response.
type OIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token"`
}

// OIDCClaims represents parsed JWT claims from an ID token.
type OIDCClaims struct {
	Issuer    string                 `json:"iss"`
	Subject   string                 `json:"sub"`
	Audience  interface{}            `json:"aud"` // string or []string
	ExpiresAt int64                  `json:"exp"`
	IssuedAt  int64                  `json:"iat"`
	Nonce     string                 `json:"nonce,omitempty"`
	Email     string                 `json:"email,omitempty"`
	Name      string                 `json:"name,omitempty"`
	Groups    []string               `json:"groups,omitempty"`
	Extra     map[string]interface{} `json:"-"`
}

// OIDCUser represents a user mapped from OIDC claims to the Velocity user model.
type OIDCUser struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Roles    []string `json:"roles"`
	Groups   []string `json:"groups"`
}

// JWKSDocument represents a JSON Web Key Set.
type JWKSDocument struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key.
type JWK struct {
	Kty string `json:"kty"` // RSA, EC
	Use string `json:"use"` // sig
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`   // RSA modulus
	E   string `json:"e,omitempty"`   // RSA exponent
	Crv string `json:"crv,omitempty"` // EC curve
	X   string `json:"x,omitempty"`   // EC x coordinate
	Y   string `json:"y,omitempty"`   // EC y coordinate

	// PEM encoded key for direct use
	X5c []string `json:"x5c,omitempty"`
}

// OIDCProvider provides OpenID Connect authentication integration.
type OIDCProvider struct {
	config    *OIDCConfig
	db        *DB
	discovery *OIDCDiscovery
	jwks      *JWKSDocument
	jwksMu    sync.RWMutex
	jwksAt    time.Time
	client    *http.Client
	stopCh    chan struct{}
}

// NewOIDCProvider creates a new OIDC provider with the given configuration.
func NewOIDCProvider(db *DB, config *OIDCConfig) *OIDCProvider {
	p := &OIDCProvider{
		config: config,
		db:     db,
		client: &http.Client{Timeout: 10 * time.Second},
		stopCh: make(chan struct{}),
	}
	return p
}

// SaveConfig persists the OIDC provider configuration in the DB.
func (p *OIDCProvider) SaveConfig() error {
	data, err := json.Marshal(p.config)
	if err != nil {
		return fmt.Errorf("oidc: failed to marshal config: %w", err)
	}
	return p.db.Put([]byte(oidcProviderPrefix+p.config.Name), data)
}

// LoadConfig loads an OIDC provider configuration from the DB.
func LoadOIDCConfig(db *DB, name string) (*OIDCConfig, error) {
	data, err := db.Get([]byte(oidcProviderPrefix + name))
	if err != nil {
		return nil, fmt.Errorf("oidc: provider %q not found: %w", name, err)
	}
	var cfg OIDCConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("oidc: failed to unmarshal config: %w", err)
	}
	return &cfg, nil
}

// ListOIDCProviders returns all stored OIDC provider names.
func ListOIDCProviders(db *DB) ([]string, error) {
	keys, err := db.Keys(oidcProviderPrefix + "*")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(keys))
	for _, k := range keys {
		names = append(names, strings.TrimPrefix(k, oidcProviderPrefix))
	}
	return names, nil
}

// Discover fetches the OpenID Connect discovery document from the provider.
func (p *OIDCProvider) Discover() error {
	wellKnown := strings.TrimRight(p.config.ProviderURL, "/") + "/.well-known/openid-configuration"
	resp, err := p.client.Get(wellKnown)
	if err != nil {
		return fmt.Errorf("oidc: failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc: discovery endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("oidc: failed to read discovery document: %w", err)
	}

	var disc OIDCDiscovery
	if err := json.Unmarshal(body, &disc); err != nil {
		return fmt.Errorf("oidc: failed to parse discovery document: %w", err)
	}
	p.discovery = &disc
	return nil
}

// FetchJWKS retrieves the JWKS from the provider's JWKS URI.
func (p *OIDCProvider) FetchJWKS() error {
	if p.discovery == nil {
		return fmt.Errorf("oidc: discovery not performed, call Discover() first")
	}

	resp, err := p.client.Get(p.discovery.JWKSURI)
	if err != nil {
		return fmt.Errorf("oidc: failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc: JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("oidc: failed to read JWKS: %w", err)
	}

	var jwks JWKSDocument
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("oidc: failed to parse JWKS: %w", err)
	}

	p.jwksMu.Lock()
	p.jwks = &jwks
	p.jwksAt = time.Now()
	p.jwksMu.Unlock()

	return nil
}

// StartJWKSRefresh starts a background goroutine that refreshes JWKS at the given interval.
func (p *OIDCProvider) StartJWKSRefresh(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = p.FetchJWKS()
			case <-p.stopCh:
				return
			}
		}
	}()
}

// Stop halts any background processes.
func (p *OIDCProvider) Stop() {
	close(p.stopCh)
}

// GetAuthorizationURL builds the authorization URL for the OIDC provider.
func (p *OIDCProvider) GetAuthorizationURL(state, nonce string) (string, error) {
	if p.discovery == nil {
		if err := p.Discover(); err != nil {
			return "", err
		}
	}

	scopes := p.config.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	params := url.Values{
		"response_type": {"code"},
		"client_id":     {p.config.ClientID},
		"redirect_uri":  {p.config.RedirectURL},
		"scope":         {strings.Join(scopes, " ")},
		"state":         {state},
	}
	if nonce != "" {
		params.Set("nonce", nonce)
	}

	return p.discovery.AuthorizationEndpoint + "?" + params.Encode(), nil
}

// ExchangeCode exchanges an authorization code for tokens.
func (p *OIDCProvider) ExchangeCode(code string) (*OIDCTokenResponse, error) {
	if p.discovery == nil {
		if err := p.Discover(); err != nil {
			return nil, err
		}
	}

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.config.RedirectURL},
		"client_id":     {p.config.ClientID},
		"client_secret": {p.config.ClientSecret},
	}

	resp, err := p.client.PostForm(p.discovery.TokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp OIDCTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("oidc: failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

// ValidateToken validates a raw JWT ID token by parsing header.payload.signature,
// verifying the signature using JWKS keys (RSA or ECDSA), and checking claims.
func (p *OIDCProvider) ValidateToken(rawToken string) (*OIDCClaims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("oidc: invalid JWT format")
	}

	// Decode header
	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode JWT header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("oidc: failed to parse JWT header: %w", err)
	}

	// Decode payload
	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode JWT payload: %w", err)
	}

	// Decode signature
	signatureBytes, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode JWT signature: %w", err)
	}

	// Verify signature
	signedContent := parts[0] + "." + parts[1]
	if err := p.verifySignature(header.Alg, header.Kid, []byte(signedContent), signatureBytes); err != nil {
		return nil, fmt.Errorf("oidc: signature verification failed: %w", err)
	}

	// Parse claims
	var claims OIDCClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("oidc: failed to parse claims: %w", err)
	}

	// Also parse extra fields
	var extra map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &extra); err == nil {
		claims.Extra = extra
	}

	// Validate timing
	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt {
		return nil, fmt.Errorf("oidc: token expired")
	}

	// Validate audience
	if !p.validateAudience(claims.Audience) {
		return nil, fmt.Errorf("oidc: invalid audience")
	}

	return &claims, nil
}

// validateAudience checks if the token audience includes the client ID.
func (p *OIDCProvider) validateAudience(aud interface{}) bool {
	switch v := aud.(type) {
	case string:
		return v == p.config.ClientID
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok && s == p.config.ClientID {
				return true
			}
		}
	}
	return false
}

// verifySignature verifies a JWT signature using the JWKS keys.
func (p *OIDCProvider) verifySignature(alg, kid string, signedContent, signature []byte) error {
	p.jwksMu.RLock()
	jwks := p.jwks
	p.jwksMu.RUnlock()

	if jwks == nil {
		return fmt.Errorf("JWKS not loaded, call FetchJWKS() first")
	}

	// Find key by kid
	var key *JWK
	for i := range jwks.Keys {
		if jwks.Keys[i].Kid == kid {
			key = &jwks.Keys[i]
			break
		}
	}
	if key == nil {
		// Try to refresh JWKS once
		if err := p.FetchJWKS(); err != nil {
			return fmt.Errorf("key %q not found and JWKS refresh failed: %w", kid, err)
		}
		p.jwksMu.RLock()
		jwks = p.jwks
		p.jwksMu.RUnlock()
		for i := range jwks.Keys {
			if jwks.Keys[i].Kid == kid {
				key = &jwks.Keys[i]
				break
			}
		}
		if key == nil {
			return fmt.Errorf("key %q not found in JWKS", kid)
		}
	}

	// Determine hash function from algorithm
	var hashFunc crypto.Hash
	var h hash.Hash
	switch alg {
	case "RS256", "ES256":
		hashFunc = crypto.SHA256
		h = sha256.New()
	case "RS384", "ES384":
		hashFunc = crypto.SHA384
		h = sha512.New384()
	case "RS512", "ES512":
		hashFunc = crypto.SHA512
		h = sha512.New()
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}

	h.Write(signedContent)
	hashed := h.Sum(nil)

	switch key.Kty {
	case "RSA":
		return p.verifyRSA(key, hashFunc, hashed, signature)
	case "EC":
		return p.verifyECDSA(key, hashed, signature, alg)
	default:
		// Try x5c certificate chain
		if len(key.X5c) > 0 {
			return p.verifyWithX5C(key.X5c[0], hashFunc, hashed, signature, alg)
		}
		return fmt.Errorf("unsupported key type: %s", key.Kty)
	}
}

// verifyRSA verifies an RSA signature.
func (p *OIDCProvider) verifyRSA(key *JWK, hashFunc crypto.Hash, hashed, signature []byte) error {
	nBytes, err := base64URLDecode(key.N)
	if err != nil {
		return fmt.Errorf("failed to decode RSA modulus: %w", err)
	}
	eBytes, err := base64URLDecode(key.E)
	if err != nil {
		return fmt.Errorf("failed to decode RSA exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	pubKey := &rsa.PublicKey{N: n, E: e}
	return rsa.VerifyPKCS1v15(pubKey, hashFunc, hashed, signature)
}

// verifyECDSA verifies an ECDSA signature.
func (p *OIDCProvider) verifyECDSA(key *JWK, hashed, signature []byte, alg string) error {
	xBytes, err := base64URLDecode(key.X)
	if err != nil {
		return fmt.Errorf("failed to decode EC x: %w", err)
	}
	yBytes, err := base64URLDecode(key.Y)
	if err != nil {
		return fmt.Errorf("failed to decode EC y: %w", err)
	}

	var curve elliptic.Curve
	var keySize int
	switch key.Crv {
	case "P-256":
		curve = elliptic.P256()
		keySize = 32
	case "P-384":
		curve = elliptic.P384()
		keySize = 48
	case "P-521":
		curve = elliptic.P521()
		keySize = 66
	default:
		return fmt.Errorf("unsupported EC curve: %s", key.Crv)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	// ECDSA JWT signature is r || s concatenated
	if len(signature) != keySize*2 {
		return fmt.Errorf("invalid ECDSA signature length")
	}
	r := new(big.Int).SetBytes(signature[:keySize])
	s := new(big.Int).SetBytes(signature[keySize:])

	if !ecdsa.Verify(pubKey, hashed, r, s) {
		return fmt.Errorf("ECDSA signature verification failed")
	}
	return nil
}

// verifyWithX5C verifies a signature using the first certificate in the x5c chain.
func (p *OIDCProvider) verifyWithX5C(certB64 string, hashFunc crypto.Hash, hashed, signature []byte, alg string) error {
	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		// Try PEM
		block, _ := pem.Decode([]byte(certB64))
		if block == nil {
			return fmt.Errorf("failed to decode x5c certificate")
		}
		certDER = block.Bytes
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse x5c certificate: %w", err)
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, hashFunc, hashed, signature)
	case *ecdsa.PublicKey:
		keySize := (pub.Curve.Params().BitSize + 7) / 8
		if len(signature) != keySize*2 {
			return fmt.Errorf("invalid ECDSA signature length from x5c")
		}
		r := new(big.Int).SetBytes(signature[:keySize])
		s := new(big.Int).SetBytes(signature[keySize:])
		if !ecdsa.Verify(pub, hashed, r, s) {
			return fmt.Errorf("ECDSA signature verification failed (x5c)")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type in x5c")
	}
}

// MapClaimsToUser converts OIDC claims to a Velocity OIDCUser using the configured mappings.
func (p *OIDCProvider) MapClaimsToUser(claims *OIDCClaims) *OIDCUser {
	user := &OIDCUser{
		ID:     claims.Subject,
		Email:  claims.Email,
		Name:   claims.Name,
		Groups: claims.Groups,
	}

	// Apply claim mapping
	if p.config.ClaimMapping != nil && claims.Extra != nil {
		if usernameField, ok := p.config.ClaimMapping["username"]; ok {
			if v, ok := claims.Extra[usernameField]; ok {
				if s, ok := v.(string); ok {
					user.Username = s
				}
			}
		}
		if emailField, ok := p.config.ClaimMapping["email"]; ok {
			if v, ok := claims.Extra[emailField]; ok {
				if s, ok := v.(string); ok {
					user.Email = s
				}
			}
		}
		if nameField, ok := p.config.ClaimMapping["name"]; ok {
			if v, ok := claims.Extra[nameField]; ok {
				if s, ok := v.(string); ok {
					user.Name = s
				}
			}
		}
	}

	// Default username from email or subject
	if user.Username == "" {
		if user.Email != "" {
			parts := strings.SplitN(user.Email, "@", 2)
			user.Username = parts[0]
		} else {
			user.Username = claims.Subject
		}
	}

	// Apply role mapping
	if p.config.RoleMapping != nil {
		roleSet := make(map[string]struct{})
		for _, group := range claims.Groups {
			if role, ok := p.config.RoleMapping[group]; ok {
				roleSet[role] = struct{}{}
			}
		}
		// Also check extra claims for roles
		if claims.Extra != nil {
			if rolesRaw, ok := claims.Extra["roles"]; ok {
				if rolesArr, ok := rolesRaw.([]interface{}); ok {
					for _, r := range rolesArr {
						if rs, ok := r.(string); ok {
							if role, ok := p.config.RoleMapping[rs]; ok {
								roleSet[role] = struct{}{}
							}
						}
					}
				}
			}
		}
		for role := range roleSet {
			user.Roles = append(user.Roles, role)
		}
	}

	if len(user.Roles) == 0 {
		user.Roles = []string{RoleUser}
	}

	return user
}

// base64URLDecode decodes a base64url-encoded string (no padding).
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if necessary
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}
