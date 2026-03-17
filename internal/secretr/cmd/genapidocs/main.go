package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/oarkflow/velocity/internal/secretr/api"
	"github.com/oarkflow/velocity/internal/secretr/authz"
)

type routeDoc struct {
	Method string
	Path   string
	Spec   authz.APIRouteAuthSpec
}

func main() {
	outPath := filepath.Join("internal", "secretr", "API_REFERENCE.md")
	s := api.NewServer(api.Config{Address: ":0"})
	routes := s.RouteMethods()
	specs := s.RouteAuthSpecs()

	docs := make([]routeDoc, 0, len(routes))
	for _, r := range routes {
		spec, _ := authz.ResolveAPIRouteSpec(r.Method, r.Path, specs)
		docs = append(docs, routeDoc{
			Method: r.Method,
			Path:   r.Path,
			Spec:   spec,
		})
	}
	sort.Slice(docs, func(i, j int) bool {
		if docs[i].Path == docs[j].Path {
			return docs[i].Method < docs[j].Method
		}
		return docs[i].Path < docs[j].Path
	})

	var b bytes.Buffer
	b.WriteString("# Secretr API Reference\n\n")
	b.WriteString("This file is auto-generated from live route registration.\n")
	b.WriteString("Do not edit manually. Regenerate with:\n\n")
	b.WriteString("```bash\n")
	b.WriteString("go run ./internal/secretr/cmd/genapidocs\n")
	b.WriteString("```\n\n")
	b.WriteString("## Common Notes\n")
	b.WriteString("- Base URL: `http://127.0.0.1:9090`\n")
	b.WriteString("- Auth header: `Authorization: Bearer <session_id>`\n")
	b.WriteString("- Routes with `AllowUnauth=true` do not require a session token.\n")
	b.WriteString("- Command dispatch endpoint: `POST /api/v1/commands/<cli path as slashes>`\n\n")

	for _, d := range docs {
		writeRouteDoc(&b, d)
	}

	if err := os.WriteFile(outPath, b.Bytes(), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", outPath, err)
		os.Exit(1)
	}
}

func writeRouteDoc(b *bytes.Buffer, d routeDoc) {
	b.WriteString("## " + d.Method + " " + d.Path + "\n\n")
	b.WriteString("| Property | Value |\n")
	b.WriteString("|---|---|\n")
	b.WriteString("| AllowUnauth | `" + fmt.Sprintf("%v", d.Spec.AllowUnauth) + "` |\n")
	b.WriteString("| RequireACL | `" + fmt.Sprintf("%v", d.Spec.RequireACL) + "` |\n")
	if d.Spec.ResourceType == "" {
		b.WriteString("| ResourceType | `-` |\n")
	} else {
		b.WriteString("| ResourceType | `" + d.Spec.ResourceType + "` |\n")
	}
	if len(d.Spec.RequiredScopes) == 0 {
		b.WriteString("| RequiredScopes | `-` |\n")
	} else {
		scopes := make([]string, 0, len(d.Spec.RequiredScopes))
		for _, s := range d.Spec.RequiredScopes {
			scopes = append(scopes, string(s))
		}
		b.WriteString("| RequiredScopes | `" + strings.Join(scopes, ", ") + "` |\n")
	}
	b.WriteString("\n")

	curl := "curl -i -X " + d.Method + " http://127.0.0.1:9090" + d.Path
	if !d.Spec.AllowUnauth {
		curl += " \\\n  -H 'Authorization: Bearer <session_id>'"
	}
	if d.Method == "POST" || d.Method == "PUT" {
		curl += " \\\n  -H 'Content-Type: application/json' \\\n  -d '{}'"
	}
	b.WriteString("Copy-paste example:\n\n")
	b.WriteString("```bash\n" + curl + "\n```\n\n")
}
