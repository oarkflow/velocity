package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/securitymode"
	"github.com/urfave/cli/v3"
)

type healthCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Details string `json:"details,omitempty"`
}

type systemStatus struct {
	Status             string        `json:"status"`
	Mode               string        `json:"mode"`
	GoVersion          string        `json:"go_version"`
	OS                 string        `json:"os"`
	Arch               string        `json:"arch"`
	DataDir            string        `json:"data_dir"`
	LicensePath        string        `json:"license_path"`
	InsecureEnvSet     []string      `json:"insecure_env_set,omitempty"`
	Checks             []healthCheck `json:"checks"`
	ReleaseBlockers    []string      `json:"release_blockers,omitempty"`
	ProductionEligible bool          `json:"production_eligible"`
}

func AdminSystem(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}

	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".secretr")
	licensePath := filepath.Join(homeDir, ".secretr", "license.json")
	mode := "production"
	if securitymode.IsDevBuild() {
		mode = "development"
	}

	checks := make([]healthCheck, 0, 8)
	checks = append(checks, verifyDataDir(dataDir))
	checks = append(checks, verifyDataDirPermissions(dataDir))
	checks = append(checks, verifyStoreHealth(ctx, c))
	checks = append(checks, verifyAuditHealth(ctx, c))
	checks = append(checks, verifySession(c))
	checks = append(checks, verifyLicense(mode, licensePath))
	checks = append(checks, verifyJWTSecretPermissions(dataDir))
	checks = append(checks, verifyLicensePermissions(mode, licensePath))

	insecureVars := insecureEnvVarsPresent()
	releaseBlockers := make([]string, 0, 6)
	if mode == "development" {
		releaseBlockers = append(releaseBlockers, "binary built with secretr_dev build tag")
	}
	if len(insecureVars) > 0 {
		releaseBlockers = append(releaseBlockers, "insecure runtime env vars detected: "+strings.Join(insecureVars, ", "))
	}
	for _, chk := range checks {
		if chk.Status == "fail" {
			releaseBlockers = append(releaseBlockers, chk.Name+": "+chk.Details)
		}
	}

	status := "healthy"
	if len(releaseBlockers) > 0 {
		status = "degraded"
	}

	report := systemStatus{
		Status:             status,
		Mode:               mode,
		GoVersion:          runtime.Version(),
		OS:                 runtime.GOOS,
		Arch:               runtime.GOARCH,
		DataDir:            dataDir,
		LicensePath:        licensePath,
		InsecureEnvSet:     insecureVars,
		Checks:             checks,
		ReleaseBlockers:    releaseBlockers,
		ProductionEligible: len(releaseBlockers) == 0,
	}

	if err := output(cmd, report); err != nil {
		return err
	}

	return strictProductionEligibilityError(cmd.Bool("strict"), report)
}

func strictProductionEligibilityError(strict bool, report systemStatus) error {
	if !strict || report.ProductionEligible {
		return nil
	}

	return fmt.Errorf("system is not production-eligible")
}

func verifyDataDir(dataDir string) healthCheck {
	if dataDir == "" {
		return healthCheck{Name: "data_dir", Status: "fail", Details: "data dir is empty"}
	}
	if st, err := os.Stat(dataDir); err != nil {
		return healthCheck{Name: "data_dir", Status: "fail", Details: err.Error()}
	} else if !st.IsDir() {
		return healthCheck{Name: "data_dir", Status: "fail", Details: "path exists but is not a directory"}
	}
	return healthCheck{Name: "data_dir", Status: "pass"}
}

func verifyDataDirPermissions(dataDir string) healthCheck {
	if dataDir == "" {
		return healthCheck{Name: "data_dir_permissions", Status: "fail", Details: "data dir is empty"}
	}
	st, err := os.Stat(dataDir)
	if err != nil {
		return healthCheck{Name: "data_dir_permissions", Status: "fail", Details: err.Error()}
	}
	if !st.IsDir() {
		return healthCheck{Name: "data_dir_permissions", Status: "fail", Details: "path exists but is not a directory"}
	}
	if st.Mode().Perm()&0o077 != 0 {
		return healthCheck{Name: "data_dir_permissions", Status: "fail", Details: fmt.Sprintf("permissions too open: %04o; expected no group/other bits", st.Mode().Perm())}
	}
	return healthCheck{Name: "data_dir_permissions", Status: "pass"}
}

func verifyStoreHealth(ctx context.Context, c *client.Client) healthCheck {
	if c == nil || c.Store == nil {
		return healthCheck{Name: "store", Status: "fail", Details: "store not initialized"}
	}
	if err := c.Store.HealthCheck(ctx); err != nil {
		return healthCheck{Name: "store", Status: "fail", Details: err.Error()}
	}
	return healthCheck{Name: "store", Status: "pass"}
}

func verifyAuditHealth(ctx context.Context, c *client.Client) healthCheck {
	if c == nil || c.Audit == nil {
		return healthCheck{Name: "audit", Status: "fail", Details: "audit engine not initialized"}
	}
	chainOK, err := c.Audit.VerifyIntegrity(ctx)
	if err != nil {
		return healthCheck{Name: "audit", Status: "fail", Details: fmt.Sprintf("chain verify failed: %v", err)}
	}
	if !chainOK {
		return healthCheck{Name: "audit", Status: "fail", Details: "audit chain integrity invalid"}
	}
	ledgerOK, err := c.Audit.VerifyLedgerIntegrity(ctx)
	if err != nil {
		return healthCheck{Name: "audit", Status: "fail", Details: fmt.Sprintf("ledger verify failed: %v", err)}
	}
	if !ledgerOK {
		return healthCheck{Name: "audit", Status: "fail", Details: "audit ledger integrity invalid"}
	}
	return healthCheck{Name: "audit", Status: "pass"}
}

func verifySession(c *client.Client) healthCheck {
	if c == nil {
		return healthCheck{Name: "session", Status: "fail", Details: "client unavailable"}
	}
	sess := c.CurrentSession()
	if sess == nil {
		return healthCheck{Name: "session", Status: "warn", Details: "no active session"}
	}
	if !sess.IsActive() {
		return healthCheck{Name: "session", Status: "warn", Details: "session is not active"}
	}
	return healthCheck{Name: "session", Status: "pass"}
}

func verifyLicense(mode, licensePath string) healthCheck {
	if mode == "development" {
		return healthCheck{Name: "license", Status: "warn", Details: "dev build bypasses license and ACL checks"}
	}
	if st, err := os.Stat(licensePath); err != nil {
		return healthCheck{Name: "license", Status: "fail", Details: err.Error()}
	} else if st.IsDir() {
		return healthCheck{Name: "license", Status: "fail", Details: "license path points to a directory"}
	}
	return healthCheck{Name: "license", Status: "pass"}
}

func verifyJWTSecretPermissions(dataDir string) healthCheck {
	if dataDir == "" {
		return healthCheck{Name: "jwt_secret_permissions", Status: "fail", Details: "data dir is empty"}
	}
	secretPath := filepath.Join(dataDir, "jwt.secret")
	st, err := os.Stat(secretPath)
	if err != nil {
		if os.IsNotExist(err) {
			return healthCheck{Name: "jwt_secret_permissions", Status: "pass"}
		}
		return healthCheck{Name: "jwt_secret_permissions", Status: "fail", Details: err.Error()}
	}
	if st.IsDir() {
		return healthCheck{Name: "jwt_secret_permissions", Status: "fail", Details: "jwt.secret path points to a directory"}
	}
	if st.Mode().Perm()&0o077 != 0 {
		return healthCheck{Name: "jwt_secret_permissions", Status: "fail", Details: fmt.Sprintf("permissions too open: %04o; expected no group/other bits", st.Mode().Perm())}
	}
	return healthCheck{Name: "jwt_secret_permissions", Status: "pass"}
}

func verifyLicensePermissions(mode, licensePath string) healthCheck {
	if mode != "production" {
		return healthCheck{Name: "license_permissions", Status: "pass"}
	}
	st, err := os.Stat(licensePath)
	if err != nil {
		if os.IsNotExist(err) {
			return healthCheck{Name: "license_permissions", Status: "pass"}
		}
		return healthCheck{Name: "license_permissions", Status: "fail", Details: err.Error()}
	}
	if st.IsDir() {
		return healthCheck{Name: "license_permissions", Status: "fail", Details: "license path points to a directory"}
	}
	if st.Mode().Perm()&0o077 != 0 {
		return healthCheck{Name: "license_permissions", Status: "fail", Details: fmt.Sprintf("permissions too open: %04o; expected no group/other bits", st.Mode().Perm())}
	}
	return healthCheck{Name: "license_permissions", Status: "pass"}
}

func insecureEnvVarsPresent() []string {
	keys := []string{
		"SECRETR_ALLOW_INSECURE_PASSWORD_ENV",
		"SECRETR_YES",
		"SECRETR_ALLOW_SELF_APPROVAL",
		"SECRETR_OIDC_ALLOW_INSECURE_MOCK",
		"SECRETR_JWT_SECRET",
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if strings.TrimSpace(os.Getenv(k)) != "" {
			out = append(out, k)
		}
	}
	return out
}
