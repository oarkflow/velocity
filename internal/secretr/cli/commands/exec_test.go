package commands

import "testing"

func TestFlattenSecretToEnv_NestedJSON(t *testing.T) {
	raw := `{"processgate":{"aws":{"client_id":"id123","secret":"sec123"}}}`
	out := flattenSecretToEnv("ignored", raw, "")

	if out["PROCESSGATE_AWS_CLIENT_ID"] != "id123" {
		t.Fatalf("expected PROCESSGATE_AWS_CLIENT_ID=id123, got %q", out["PROCESSGATE_AWS_CLIENT_ID"])
	}
	if out["PROCESSGATE_AWS_SECRET"] != "sec123" {
		t.Fatalf("expected PROCESSGATE_AWS_SECRET=sec123, got %q", out["PROCESSGATE_AWS_SECRET"])
	}
}

func TestFlattenSecretToEnv_NonJSONUsesSecretName(t *testing.T) {
	out := flattenSecretToEnv("app/db-password", "p@ss", "")
	if out["APP_DB_PASSWORD"] != "p@ss" {
		t.Fatalf("expected APP_DB_PASSWORD=p@ss, got %q", out["APP_DB_PASSWORD"])
	}
}

func TestFlattenSecretToEnv_CategoryPrefixedNameUsesLeafVar(t *testing.T) {
	out := flattenSecretToEnv(secretNameForEnv("general:ENCRYPTED_SECRET", "general"), "hello", "")
	if out["ENCRYPTED_SECRET"] != "hello" {
		t.Fatalf("expected ENCRYPTED_SECRET=hello, got %q", out["ENCRYPTED_SECRET"])
	}
}

func TestSecretNameForEnv_DefaultGeneralPrefix(t *testing.T) {
	got := secretNameForEnv("general:ENCRYPTED_SECRET", "general")
	if got != "ENCRYPTED_SECRET" {
		t.Fatalf("expected ENCRYPTED_SECRET, got %q", got)
	}
}

func TestParseVelocitySecretKey(t *testing.T) {
	cat, name, ok := parseVelocitySecretKey("secret:general:ENCRYPTED_SECRET")
	if !ok {
		t.Fatal("expected velocity secret key to parse")
	}
	if cat != "general" || name != "ENCRYPTED_SECRET" {
		t.Fatalf("unexpected parse result: cat=%q name=%q", cat, name)
	}
}

func TestFlattenSecretToEnv_WithEnvPrefix(t *testing.T) {
	raw := `{"aws":{"client_id":"id123"}}`
	out := flattenSecretToEnv("ignored", raw, "prod")
	if out["PROD_AWS_CLIENT_ID"] != "id123" {
		t.Fatalf("expected PROD_AWS_CLIENT_ID=id123, got %q", out["PROD_AWS_CLIENT_ID"])
	}
}

func TestNormalizeEnvToken(t *testing.T) {
	got := normalizeEnvToken(" prod/api ")
	if got != "PROD_API" {
		t.Fatalf("expected PROD_API, got %q", got)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	got := firstNonEmpty(" ", "", "namespace", "tenant")
	if got != "namespace" {
		t.Fatalf("expected namespace, got %q", got)
	}
}
