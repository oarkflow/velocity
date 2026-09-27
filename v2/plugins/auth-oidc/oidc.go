// Package authoidc implements the auth-oidc plugin: real OpenID Connect
// discovery, JWKS fetch/refresh, authorization-code exchange, and RSA/
// ECDSA JWT signature verification, ported from v1's oidc_provider.go
// (adapted from a *DB-coupled provider to a standalone api.AuthProvider
// plugin with no storage dependency of its own — config comes from the
// manifest, not persisted provider records).
package authoidc

import (
	"context"
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

	"github.com/oarkflow/velocity/v2/api"
)

const (
	PluginName  = "auth-oidc"
	ServiceName = "auth.oidc"
)

// Discovery is the OpenID Connect discovery document.
type Discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	SupportedScopes       []string `json:"scopes_supported"`
	SupportedClaims       []string `json:"claims_supported"`
}

// TokenResponse is the token endpoint response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token"`
}

// Claims are the parsed JWT claims from an ID token.
type Claims struct {
	Issuer    string         `json:"iss"`
	Subject   string         `json:"sub"`
	Audience  any            `json:"aud"` // string or []string
	ExpiresAt int64          `json:"exp"`
	IssuedAt  int64          `json:"iat"`
	Nonce     string         `json:"nonce,omitempty"`
	Email     string         `json:"email,omitempty"`
	Name      string         `json:"name,omitempty"`
	Groups    []string       `json:"groups,omitempty"`
	Extra     map[string]any `json:"-"`
}

// JWKSDocument is a JSON Web Key Set.
type JWKSDocument struct {
	Keys []JWK `json:"keys"`
}

// JWK is a single JSON Web Key.
type JWK struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Kid string   `json:"kid"`
	Alg string   `json:"alg"`
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	Crv string   `json:"crv,omitempty"`
	X   string   `json:"x,omitempty"`
	Y   string   `json:"y,omitempty"`
	X5c []string `json:"x5c,omitempty"`
}

// Credential is what callers pass to Authenticate: exactly one of Code
// (to exchange for tokens) or IDToken (to verify directly) should be set.
type Credential struct {
	Code        string // authorization code to exchange
	RedirectURL string // required if Code is set and differs from config default
	IDToken     string // raw ID token to verify directly
}

// Plugin implements api.Plugin and api.AuthProvider.
type Plugin struct {
	providerURL  string
	clientID     string
	clientSecret string
	redirectURL  string
	roleMapping  map[string]string

	client *http.Client

	discMu    sync.RWMutex
	discovery *Discovery

	jwksMu sync.RWMutex
	jwks   *JWKSDocument
	jwksAt time.Time

	events  api.EventBus
	log     api.Logger
	stopCh  chan struct{}
	started bool
}

func New() *Plugin {
	return &Plugin{client: &http.Client{Timeout: 10 * time.Second}, stopCh: make(chan struct{})}
}

var (
	_ api.Plugin       = (*Plugin)(nil)
	_ api.AuthProvider = (*Plugin)(nil)
)

func (p *Plugin) Name() string           { return PluginName }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return nil }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	cfg := k.Config().Scoped(PluginName)
	p.providerURL = cfg.String("provider_url", "")
	p.clientID = cfg.String("client_id", "")
	p.clientSecret = cfg.String("client_secret", "")
	p.redirectURL = cfg.String("redirect_url", "")
	if p.providerURL == "" || p.clientID == "" {
		return fmt.Errorf("auth-oidc: provider_url and client_id are required config keys")
	}
	if rm, ok := cfg.Raw()["role_mapping"].(map[string]any); ok {
		p.roleMapping = make(map[string]string, len(rm))
		for k, v := range rm {
			if s, ok := v.(string); ok {
				p.roleMapping[k] = s
			}
		}
	}
	p.events = k.Events()
	p.log = k.Logger()

	if err := p.discover(); err != nil {
		return fmt.Errorf("auth-oidc: discovery failed: %w", err)
	}
	if err := p.fetchJWKS(); err != nil {
		return fmt.Errorf("auth-oidc: initial JWKS fetch failed: %w", err)
	}

	return k.Registry().Provide(ServiceName, p)
}

func (p *Plugin) Start(ctx context.Context) error {
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = p.fetchJWKS()
			case <-p.stopCh:
				return
			}
		}
	}()
	p.started = true
	return nil
}

func (p *Plugin) Stop(ctx context.Context) error {
	close(p.stopCh)
	p.started = false
	return nil
}

func (p *Plugin) Health() api.Health {
	if p.started {
		return api.Health{Status: "ok"}
	}
	return api.Health{Status: "down"}
}

func (p *Plugin) discover() error {
	wellKnown := strings.TrimRight(p.providerURL, "/") + "/.well-known/openid-configuration"
	resp, err := p.client.Get(wellKnown)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var disc Discovery
	if err := json.Unmarshal(body, &disc); err != nil {
		return err
	}
	p.discMu.Lock()
	p.discovery = &disc
	p.discMu.Unlock()
	return nil
}

func (p *Plugin) fetchJWKS() error {
	p.discMu.RLock()
	disc := p.discovery
	p.discMu.RUnlock()
	if disc == nil {
		return fmt.Errorf("discovery not performed")
	}
	resp, err := p.client.Get(disc.JWKSURI)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var jwks JWKSDocument
	if err := json.Unmarshal(body, &jwks); err != nil {
		return err
	}
	p.jwksMu.Lock()
	p.jwks = &jwks
	p.jwksAt = time.Now()
	p.jwksMu.Unlock()
	return nil
}

// AuthorizationURL builds the OIDC authorization redirect URL.
func (p *Plugin) AuthorizationURL(state, nonce string, scopes []string) string {
	p.discMu.RLock()
	disc := p.discovery
	p.discMu.RUnlock()
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {p.clientID},
		"redirect_uri":  {p.redirectURL},
		"scope":         {strings.Join(scopes, " ")},
		"state":         {state},
	}
	if nonce != "" {
		params.Set("nonce", nonce)
	}
	return disc.AuthorizationEndpoint + "?" + params.Encode()
}

func (p *Plugin) exchangeCode(code string) (*TokenResponse, error) {
	p.discMu.RLock()
	disc := p.discovery
	p.discMu.RUnlock()

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.redirectURL},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
	}
	resp, err := p.client.PostForm(disc.TokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// ValidateToken validates a raw JWT ID token: parses header.payload.signature,
// verifies the signature via JWKS (RSA or ECDSA), and checks exp/aud.
func (p *Plugin) ValidateToken(rawToken string) (*Claims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}
	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWT header: %w", err)
	}
	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	signatureBytes, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT signature: %w", err)
	}

	signedContent := parts[0] + "." + parts[1]
	if err := p.verifySignature(header.Alg, header.Kid, []byte(signedContent), signatureBytes); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}
	var extra map[string]any
	if err := json.Unmarshal(payloadBytes, &extra); err == nil {
		claims.Extra = extra
	}

	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}
	if !p.validateAudience(claims.Audience) {
		return nil, fmt.Errorf("invalid audience")
	}
	return &claims, nil
}

func (p *Plugin) validateAudience(aud any) bool {
	switch v := aud.(type) {
	case string:
		return v == p.clientID
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == p.clientID {
				return true
			}
		}
	}
	return false
}

func (p *Plugin) verifySignature(alg, kid string, signedContent, signature []byte) error {
	p.jwksMu.RLock()
	jwks := p.jwks
	p.jwksMu.RUnlock()
	if jwks == nil {
		return fmt.Errorf("JWKS not loaded")
	}

	key := findKey(jwks, kid)
	if key == nil {
		if err := p.fetchJWKS(); err != nil {
			return fmt.Errorf("key %q not found and JWKS refresh failed: %w", kid, err)
		}
		p.jwksMu.RLock()
		jwks = p.jwks
		p.jwksMu.RUnlock()
		key = findKey(jwks, kid)
		if key == nil {
			return fmt.Errorf("key %q not found in JWKS", kid)
		}
	}

	var hashFunc crypto.Hash
	var h hash.Hash
	switch alg {
	case "RS256", "ES256":
		hashFunc, h = crypto.SHA256, sha256.New()
	case "RS384", "ES384":
		hashFunc, h = crypto.SHA384, sha512.New384()
	case "RS512", "ES512":
		hashFunc, h = crypto.SHA512, sha512.New()
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
	h.Write(signedContent)
	hashed := h.Sum(nil)

	switch key.Kty {
	case "RSA":
		return verifyRSA(key, hashFunc, hashed, signature)
	case "EC":
		return verifyECDSA(key, hashed, signature)
	default:
		if len(key.X5c) > 0 {
			return verifyWithX5C(key.X5c[0], hashFunc, hashed, signature)
		}
		return fmt.Errorf("unsupported key type: %s", key.Kty)
	}
}

func findKey(jwks *JWKSDocument, kid string) *JWK {
	if jwks == nil {
		return nil
	}
	for i := range jwks.Keys {
		if jwks.Keys[i].Kid == kid {
			return &jwks.Keys[i]
		}
	}
	return nil
}

func verifyRSA(key *JWK, hashFunc crypto.Hash, hashed, signature []byte) error {
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

func verifyECDSA(key *JWK, hashed, signature []byte) error {
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
		curve, keySize = elliptic.P256(), 32
	case "P-384":
		curve, keySize = elliptic.P384(), 48
	case "P-521":
		curve, keySize = elliptic.P521(), 66
	default:
		return fmt.Errorf("unsupported EC curve: %s", key.Crv)
	}
	pubKey := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
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

func verifyWithX5C(certB64 string, hashFunc crypto.Hash, hashed, signature []byte) error {
	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
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

func base64URLDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// Authenticate accepts a Credential: either exchanges Code for tokens then
// validates the resulting ID token, or validates IDToken directly.
func (p *Plugin) Authenticate(ctx context.Context, credential any) (api.Principal, error) {
	cred, ok := credential.(Credential)
	if !ok {
		return api.Principal{}, fmt.Errorf("auth-oidc: credential must be an authoidc.Credential, got %T", credential)
	}

	idToken := cred.IDToken
	if idToken == "" {
		if cred.Code == "" {
			return api.Principal{}, fmt.Errorf("auth-oidc: credential must set Code or IDToken")
		}
		tr, err := p.exchangeCode(cred.Code)
		if err != nil {
			p.deny(ctx, "", err)
			return api.Principal{}, err
		}
		idToken = tr.IDToken
	}

	claims, err := p.ValidateToken(idToken)
	if err != nil {
		p.deny(ctx, "", err)
		return api.Principal{}, err
	}

	roles := p.mapRoles(claims)
	principal := api.Principal{
		Subject: claims.Subject,
		Roles:   roles,
		Claims:  claims.Extra,
	}
	if p.events != nil {
		p.events.Publish(ctx, api.Event{Topic: api.TopicAuthLogin, Source: PluginName, Payload: principal.Subject})
	}
	return principal, nil
}

func (p *Plugin) mapRoles(claims *Claims) []string {
	if p.roleMapping == nil {
		return nil
	}
	roleSet := map[string]struct{}{}
	for _, g := range claims.Groups {
		if role, ok := p.roleMapping[g]; ok {
			roleSet[role] = struct{}{}
		}
	}
	roles := make([]string, 0, len(roleSet))
	for r := range roleSet {
		roles = append(roles, r)
	}
	return roles
}

func (p *Plugin) deny(ctx context.Context, subject string, reason error) {
	if p.events == nil {
		return
	}
	p.events.Publish(ctx, api.Event{
		Topic:   api.TopicAuthDenied,
		Source:  PluginName,
		Payload: map[string]any{"subject": subject, "reason": fmt.Sprint(reason)},
	})
}

// Authorize is a minimal placeholder: role "admin" allows everything else
// is denied. Real authorization decisions belong to the compliance
// plugin's PolicyEngine.
func (p *Plugin) Authorize(ctx context.Context, principal api.Principal, action, resource string) (bool, error) {
	for _, r := range principal.Roles {
		if r == "admin" {
			return true, nil
		}
	}
	return false, nil
}
