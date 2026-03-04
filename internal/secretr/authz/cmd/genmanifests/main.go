package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/oarkflow/velocity/internal/secretr/authz"
	app "github.com/oarkflow/velocity/internal/secretr/cli/app"
)

type scopeManifestEntry struct {
	Path   string   `json:"path"`
	Scopes []string `json:"scopes"`
}

type surfaceFlagEntry struct {
	Name       string `json:"name"`
	Class      string `json:"class"`
	RequireACL bool   `json:"require_acl"`
}

type surfaceArgEntry struct {
	Position   int    `json:"position"`
	Name       string `json:"name"`
	RequireACL bool   `json:"require_acl"`
}

type surfaceManifestEntry struct {
	Path  string             `json:"path"`
	Flags []surfaceFlagEntry `json:"flags"`
	Args  []surfaceArgEntry  `json:"args"`
}

func main() {
	var outDir string
	flag.StringVar(&outDir, "out", "internal/secretr/authz", "output directory for manifests")
	flag.Parse()

	root := app.BuildCLIRootForAuthz()
	specs := authz.BuildCLIAuthSpecs(root, nil)
	paths := sortedPaths(specs)

	scopesOut := make([]scopeManifestEntry, 0, len(paths))
	surfaceOut := make([]surfaceManifestEntry, 0, len(paths))

	for _, p := range paths {
		s := specs[p]
		scopes := make([]string, 0, len(s.RequiredScopes))
		for _, sc := range s.RequiredScopes {
			scopes = append(scopes, string(sc))
		}
		scopesOut = append(scopesOut, scopeManifestEntry{Path: p, Scopes: scopes})

		flags := make([]surfaceFlagEntry, 0, len(s.Flags))
		flagNames := make([]string, 0, len(s.Flags))
		for n := range s.Flags {
			flagNames = append(flagNames, n)
		}
		sort.Strings(flagNames)
		for _, n := range flagNames {
			f := s.Flags[n]
			flags = append(flags, surfaceFlagEntry{Name: f.Name, Class: string(f.Class), RequireACL: f.RequireACL})
		}

		args := make([]surfaceArgEntry, 0, len(s.Args))
		for _, a := range s.Args {
			args = append(args, surfaceArgEntry{Position: a.Position, Name: a.Name, RequireACL: a.RequireACL})
		}
		sort.Slice(args, func(i, j int) bool {
			if args[i].Position == args[j].Position {
				return args[i].Name < args[j].Name
			}
			return args[i].Position < args[j].Position
		})
		surfaceOut = append(surfaceOut, surfaceManifestEntry{Path: p, Flags: flags, Args: args})
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fatalf("create output dir: %v", err)
	}
	if err := writeJSON(filepath.Join(outDir, "command_scope_manifest.json"), scopesOut); err != nil {
		fatalf("write scope manifest: %v", err)
	}
	if err := writeJSON(filepath.Join(outDir, "command_surface_manifest.json"), surfaceOut); err != nil {
		fatalf("write surface manifest: %v", err)
	}
}

func writeJSON(path string, value any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func sortedPaths(specs map[string]authz.CommandAuthSpec) []string {
	paths := make([]string, 0, len(specs))
	for p := range specs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
