package app

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/oarkflow/velocity/internal/secretr/api"
	"github.com/oarkflow/velocity/internal/secretr/cli/middleware"
	"github.com/urfave/cli/v3"
)

func TestCLIToAPICommandDispatchParity(t *testing.T) {
	a := &App{
		gate: middleware.NewPermissionGate(nil, nil),
	}
	root := a.buildCLI()

	paths := listCommandPaths(root, "")
	if len(paths) == 0 {
		t.Fatal("no CLI command paths discovered")
	}

	srv := api.NewServer(api.Config{Address: ":0"})

	var missing []string
	for _, path := range paths {
		route := "/api/v1/commands/" + strings.ReplaceAll(path, " ", "/")
		req := httptest.NewRequest(http.MethodPost, route, nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			missing = append(missing, path)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("missing API handler route for CLI commands (%d): %s", len(missing), strings.Join(missing, ", "))
	}
}

func listCommandPaths(cmd *cli.Command, prefix string) []string {
	if cmd == nil {
		return nil
	}

	var paths []string
	for _, sub := range cmd.Commands {
		name := strings.TrimSpace(sub.Name)
		if name == "" || name == "help" || name == "h" {
			continue
		}

		full := strings.TrimSpace(strings.TrimSpace(prefix + " " + name))
		paths = append(paths, full)
		paths = append(paths, listCommandPaths(sub, full)...)
	}
	return paths
}
