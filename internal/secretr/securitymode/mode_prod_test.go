//go:build !secretr_dev

package securitymode

import "testing"

func TestProductionModeDisablesEnvBypasses(t *testing.T) {
	t.Setenv("SECRETR_ALLOW_INSECURE_PASSWORD_ENV", "true")
	t.Setenv("SECRETR_YES", "true")
	t.Setenv("SECRETR_ALLOW_SELF_APPROVAL", "true")
	t.Setenv("SECRETR_LICENSE_PATH", "/tmp/license.json")
	t.Setenv("SECRETR_JWT_SECRET", "unsafe")
	t.Setenv("SECRETR_OIDC_ALLOW_INSECURE_MOCK", "true")
	t.Setenv("SECRETR_OIDC_JWKS_URL", "https://attacker.invalid/jwks")

	if IsDevBuild() {
		t.Fatalf("expected production build mode")
	}
	if AllowInsecurePasswordEnv() {
		t.Fatalf("insecure password env must be disabled in production mode")
	}
	if AllowYesEnvOverride() {
		t.Fatalf("yes env override must be disabled in production mode")
	}
	if AllowOrgEnvOverride() {
		t.Fatalf("org env override must be disabled in production mode")
	}
	if AllowLicensePathEnvOverride() {
		t.Fatalf("license path env override must be disabled in production mode")
	}
	if AllowSelfApprovalEnvOverride() {
		t.Fatalf("self-approval env override must be disabled in production mode")
	}
	if v, ok := OIDCJWKSURLEnvOverride(); ok || v != "" {
		t.Fatalf("OIDC JWKS env override must be disabled in production mode")
	}
	if AllowInsecureOIDCMock() {
		t.Fatalf("OIDC insecure mock must be disabled in production mode")
	}
	if AllowJWTSecretEnvOverride() {
		t.Fatalf("JWT secret env override must be disabled in production mode")
	}
}
