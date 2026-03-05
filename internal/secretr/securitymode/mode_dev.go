//go:build secretr_dev

package securitymode

import "os"

func IsDevBuild() bool { return true }

func AllowInsecurePasswordEnv() bool {
	return os.Getenv("SECRETR_ALLOW_INSECURE_PASSWORD_ENV") == "true"
}

func AllowYesEnvOverride() bool {
	return os.Getenv("SECRETR_YES") == "true"
}

func AllowOrgEnvOverride() bool { return true }

func AllowLicensePathEnvOverride() bool { return true }

func AllowSelfApprovalEnvOverride() bool {
	return os.Getenv("SECRETR_ALLOW_SELF_APPROVAL") == "true"
}

func OIDCJWKSURLEnvOverride() (string, bool) {
	v := os.Getenv("SECRETR_OIDC_JWKS_URL")
	return v, v != ""
}

func AllowInsecureOIDCMock() bool {
	return os.Getenv("SECRETR_OIDC_ALLOW_INSECURE_MOCK") == "true"
}

func AllowJWTSecretEnvOverride() bool {
	return os.Getenv("SECRETR_JWT_SECRET") != ""
}
