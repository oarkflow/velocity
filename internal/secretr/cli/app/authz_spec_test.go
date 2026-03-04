package app

import (
	"strings"
	"testing"

	"github.com/oarkflow/velocity/internal/secretr/authz"
	"github.com/oarkflow/velocity/internal/secretr/cli/middleware"
	"github.com/urfave/cli/v3"
)

func TestCLIAuthzSpecsCoverAllCommandsAndFlags(t *testing.T) {
	a := &App{gate: middleware.NewPermissionGate(nil, nil)}
	root := a.buildCLI()
	if missing := authz.MissingCLICommandScopes(root, nil); len(missing) > 0 {
		t.Fatalf("commands missing strict scope metadata (%d): %s", len(missing), strings.Join(missing, ", "))
	}
	if missing := authz.MissingCLICommandSurface(root); len(missing) > 0 {
		t.Fatalf("commands missing strict surface metadata (%d): %s", len(missing), strings.Join(missing, ", "))
	}
	specs := authz.BuildCLIAuthSpecs(root, nil)
	if len(specs) == 0 {
		t.Fatal("no authz specs generated")
	}

	for _, cmd := range root.Commands {
		validateCommandSpec(t, specs, "", cmd)
	}
}

func validateCommandSpec(t *testing.T, specs map[string]authz.CommandAuthSpec, prefix string, cmd *cli.Command) {
	if cmd == nil {
		return
	}
	name := strings.TrimSpace(cmd.Name)
	if name == "" || name == "help" || name == "h" {
		return
	}
	path := strings.TrimSpace(strings.TrimSpace(prefix + " " + name))
	spec, ok := specs[path]
	if !ok {
		t.Fatalf("missing authz spec for command: %s", path)
	}
	if spec.SpecMissing {
		t.Fatalf("scope metadata unresolved for command: %s", path)
	}
	if !spec.AllowUnauth && len(spec.RequiredScopes) == 0 {
		t.Fatalf("missing required scopes in authz spec for command: %s", path)
	}

	for _, f := range cmd.Flags {
		names := f.Names()
		if len(names) == 0 {
			continue
		}
		fspec, exists := spec.Flags[names[0]]
		if !exists {
			t.Fatalf("missing flag authz spec for %s flag %s", path, names[0])
		}
		if fspec.SpecMissing {
			t.Fatalf("scope metadata unresolved for %s flag %s", path, names[0])
		}
		if !spec.AllowUnauth && len(fspec.RequiredScopes) == 0 {
			t.Fatalf("missing required scopes in flag authz spec for %s flag %s", path, names[0])
		}
	}

	if len(spec.Args) == 0 {
		t.Fatalf("missing arg authz spec for command: %s", path)
	}
	if !spec.AllowUnauth {
		for _, as := range spec.Args {
			if as.SpecMissing {
				t.Fatalf("scope metadata unresolved for command: %s arg %s", path, as.Name)
			}
			if len(as.RequiredScopes) == 0 {
				t.Fatalf("missing required scopes in arg authz spec for command: %s arg %s", path, as.Name)
			}
		}
	}

	for _, sub := range cmd.Commands {
		validateCommandSpec(t, specs, path, sub)
	}
}
