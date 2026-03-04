package app

import (
	"testing"

	"github.com/oarkflow/velocity/internal/secretr/cli/middleware"
)

func TestCLICommandCompatibilitySnapshot(t *testing.T) {
	a := &App{
		gate: middleware.NewPermissionGate(nil, nil),
	}
	root := a.buildCLI()
	expected := map[string]bool{
		"auth": true, "identity": true, "device": true, "session": true, "key": true,
		"secret": true, "object": true, "folder": true, "backup": true, "data": true,
		"export": true, "import": true,
		"access": true, "role": true, "policy": true, "audit": true, "share": true,
		"org": true, "incident": true, "envelope": true, "admin": true, "ssh": true,
		"cicd": true, "exec": true, "env": true, "load-env": true, "enrich": true,
		"monitoring": true, "alert": true, "compliance": true, "dlp": true, "pipeline": true,
	}

	seen := map[string]bool{}
	for _, cmd := range root.Commands {
		seen[cmd.Name] = true
	}
	for name := range expected {
		if !seen[name] {
			t.Fatalf("expected command %q not found", name)
		}
	}

	// Ensure backup keeps schedule extension.
	var backupFound bool
	var scheduleFound bool
	for _, cmd := range root.Commands {
		if cmd.Name != "backup" {
			continue
		}
		backupFound = true
		for _, sub := range cmd.Commands {
			if sub.Name == "schedule" {
				scheduleFound = true
				break
			}
		}
	}
	if !backupFound || !scheduleFound {
		t.Fatalf("backup schedule command missing")
	}
}
