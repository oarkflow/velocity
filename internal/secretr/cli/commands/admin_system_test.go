package commands

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	secretrcli "github.com/oarkflow/velocity/internal/secretr/cli"
)

func TestVerifyDataDir(t *testing.T) {
	t.Run("missing dir fails", func(t *testing.T) {
		c := verifyDataDir(filepath.Join(t.TempDir(), "missing"))
		if c.Status != "fail" {
			t.Fatalf("expected fail, got %s", c.Status)
		}
	})

	t.Run("existing dir passes", func(t *testing.T) {
		d := t.TempDir()
		c := verifyDataDir(d)
		if c.Status != "pass" {
			t.Fatalf("expected pass, got %s", c.Status)
		}
	})

	t.Run("permissions too open fail", func(t *testing.T) {
		d := t.TempDir()
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		c := verifyDataDirPermissions(d)
		if c.Status != "fail" {
			t.Fatalf("expected fail, got %s", c.Status)
		}
	})

	t.Run("permissions 0700 pass", func(t *testing.T) {
		d := t.TempDir()
		if err := os.Chmod(d, 0o700); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		c := verifyDataDirPermissions(d)
		if c.Status != "pass" {
			t.Fatalf("expected pass, got %s (%s)", c.Status, c.Details)
		}
	})
}

func TestVerifyStoreHealth(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	c, err := secretrcli.NewClient(secretrcli.DefaultConfig())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	h := verifyStoreHealth(context.Background(), c)
	if h.Status != "pass" {
		t.Fatalf("expected pass, got %s (%s)", h.Status, h.Details)
	}
}

func TestInsecureEnvVarsPresent(t *testing.T) {
	t.Setenv("SECRETR_YES", "true")
	t.Setenv("SECRETR_JWT_SECRET", "demo")
	v := insecureEnvVarsPresent()
	if len(v) != 2 {
		t.Fatalf("expected 2 vars, got %d: %v", len(v), v)
	}
}

func TestVerifyLicenseProd(t *testing.T) {
	t.Run("missing fails", func(t *testing.T) {
		lc := verifyLicense("production", filepath.Join(t.TempDir(), "license.json"))
		if lc.Status != "fail" {
			t.Fatalf("expected fail, got %s", lc.Status)
		}
	})

	t.Run("file passes", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "license.json")
		if err := os.WriteFile(p, []byte("{}"), 0600); err != nil {
			t.Fatalf("write license: %v", err)
		}
		lc := verifyLicense("production", p)
		if lc.Status != "pass" {
			t.Fatalf("expected pass, got %s (%s)", lc.Status, lc.Details)
		}
	})
}

func TestVerifyPermissionChecks(t *testing.T) {
	t.Run("jwt secret missing passes", func(t *testing.T) {
		c := verifyJWTSecretPermissions(t.TempDir())
		if c.Status != "pass" {
			t.Fatalf("expected pass, got %s (%s)", c.Status, c.Details)
		}
	})

	t.Run("jwt secret group readable fails", func(t *testing.T) {
		d := t.TempDir()
		p := filepath.Join(d, "jwt.secret")
		if err := os.WriteFile(p, []byte("secret"), 0o640); err != nil {
			t.Fatalf("write jwt.secret: %v", err)
		}
		c := verifyJWTSecretPermissions(d)
		if c.Status != "fail" {
			t.Fatalf("expected fail, got %s", c.Status)
		}
	})

	t.Run("jwt secret mode 0600 passes", func(t *testing.T) {
		d := t.TempDir()
		p := filepath.Join(d, "jwt.secret")
		if err := os.WriteFile(p, []byte("secret"), 0o600); err != nil {
			t.Fatalf("write jwt.secret: %v", err)
		}
		c := verifyJWTSecretPermissions(d)
		if c.Status != "pass" {
			t.Fatalf("expected pass, got %s (%s)", c.Status, c.Details)
		}
	})

	t.Run("production missing license permissions passes", func(t *testing.T) {
		c := verifyLicensePermissions("production", filepath.Join(t.TempDir(), "license.json"))
		if c.Status != "pass" {
			t.Fatalf("expected pass, got %s (%s)", c.Status, c.Details)
		}
	})

	t.Run("production open license permissions fail", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "license.json")
		if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
			t.Fatalf("write license: %v", err)
		}
		c := verifyLicensePermissions("production", p)
		if c.Status != "fail" {
			t.Fatalf("expected fail, got %s", c.Status)
		}
	})

	t.Run("production restrictive license permissions pass", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "license.json")
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatalf("write license: %v", err)
		}
		c := verifyLicensePermissions("production", p)
		if c.Status != "pass" {
			t.Fatalf("expected pass, got %s (%s)", c.Status, c.Details)
		}
	})

	t.Run("development skips license permission check", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "license.json")
		if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
			t.Fatalf("write license: %v", err)
		}
		c := verifyLicensePermissions("development", p)
		if c.Status != "pass" {
			t.Fatalf("expected pass, got %s (%s)", c.Status, c.Details)
		}
	})
}

func TestStrictProductionEligibilityError(t *testing.T) {
	t.Run("non-strict does not error when ineligible", func(t *testing.T) {
		err := strictProductionEligibilityError(false, systemStatus{ProductionEligible: false})
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("strict does not error when eligible", func(t *testing.T) {
		err := strictProductionEligibilityError(true, systemStatus{ProductionEligible: true})
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("strict errors when ineligible", func(t *testing.T) {
		err := strictProductionEligibilityError(true, systemStatus{ProductionEligible: false})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if err.Error() != "system is not production-eligible" {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
