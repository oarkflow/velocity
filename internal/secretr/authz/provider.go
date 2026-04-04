package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	licclient "github.com/oarkflow/licensing-go"
	"github.com/oarkflow/velocity/internal/secretr/securitymode"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

// EnvEntitlementProvider loads license payload from ~/.secretr/license.json in
// secure builds. Dev builds (tag: secretr_dev) may override path via
// SECRETR_LICENSE_PATH.
// The file is cached and reloaded on mtime changes.
type EnvEntitlementProvider struct {
	mu       sync.RWMutex
	path     string
	cached   *licclient.LicenseData
	cachedAt time.Time
}

func NewEnvEntitlementProvider() *EnvEntitlementProvider {
	return &EnvEntitlementProvider{path: resolveLicensePath()}
}

func resolveLicensePath() string {
	if securitymode.AllowLicensePathEnvOverride() {
		if p := os.Getenv("SECRETR_LICENSE_PATH"); p != "" {
			return p
		}
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".secretr", "license.json")
}

func (p *EnvEntitlementProvider) GetLicenseData(ctx context.Context, actorID types.ID) (*licclient.LicenseData, error) {
	_ = ctx
	_ = actorID
	if p.path == "" {
		if securitymode.IsDevBuild() {
			return fullAccessDevLicenseData(), nil
		}
		return nil, nil
	}

	fi, err := os.Stat(p.path)
	if err != nil {
		if securitymode.IsDevBuild() && errors.Is(err, os.ErrNotExist) {
			return fullAccessDevLicenseData(), nil
		}
		return nil, fmt.Errorf("authz: license file stat failed: %w", err)
	}

	p.mu.RLock()
	if p.cached != nil && !fi.ModTime().After(p.cachedAt) {
		defer p.mu.RUnlock()
		return p.cached, nil
	}
	p.mu.RUnlock()

	b, err := os.ReadFile(p.path)
	if err != nil {
		return nil, fmt.Errorf("authz: license file read failed: %w", err)
	}

	var data licclient.LicenseData
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("authz: invalid license json: %w", err)
	}

	p.mu.Lock()
	p.cached = &data
	p.cachedAt = fi.ModTime()
	p.mu.Unlock()

	return &data, nil
}

func fullAccessDevLicenseData() *licclient.LicenseData {
	features := make(map[string]licclient.FeatureGrant)
	for scope := range knownScopes {
		scopeSlug := strings.TrimSpace(string(scope))
		if scopeSlug == "" {
			continue
		}
		featureSlug := featureFromScope(scopeSlug)
		fg, ok := features[featureSlug]
		if !ok {
			fg = licclient.FeatureGrant{
				FeatureSlug: featureSlug,
				Enabled:     true,
				Scopes:      make(map[string]licclient.ScopeGrant),
			}
		}
		fg.Scopes[scopeSlug] = licclient.ScopeGrant{
			ScopeSlug:    scopeSlug,
			Permission:   licclient.ScopePermissionAllow,
			Restrictions: nil,
		}
		features[featureSlug] = fg
	}

	return &licclient.LicenseData{
		Entitlements: &licclient.LicenseEntitlements{Features: features},
	}
}
