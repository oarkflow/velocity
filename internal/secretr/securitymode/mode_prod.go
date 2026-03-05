//go:build !secretr_dev

package securitymode

func IsDevBuild() bool { return false }

func AllowInsecurePasswordEnv() bool { return false }

func AllowYesEnvOverride() bool { return false }

func AllowOrgEnvOverride() bool { return false }

func AllowLicensePathEnvOverride() bool { return false }

func AllowSelfApprovalEnvOverride() bool { return false }

func OIDCJWKSURLEnvOverride() (string, bool) {
	return "", false
}

func AllowInsecureOIDCMock() bool { return false }

func AllowJWTSecretEnvOverride() bool { return false }
