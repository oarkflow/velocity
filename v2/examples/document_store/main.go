// Command document_store demonstrates Velocity v2's JSON document surface
// (api.DocumentService): whole-document storage plus dot-notation
// get/set/delete on a single nested field, without loading and re-saving
// the document by hand.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/document"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "velocity-document-store-*")
	must(err)
	defer os.RemoveAll(dir)

	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
		{Name: "document", Enabled: true},
	}}

	k := kernel.New(manifest)
	must(k.Boot(ctx, []api.Plugin{
		storagelsm.New(),
		document.NewPlugin("storage-lsm"),
	}, manifest.Enabled()))
	defer k.Shutdown(ctx)

	docs := k.Registry().MustLookup("document").(api.DocumentService)

	fmt.Println("=== SetJSON / GetJSON (whole document) ===")
	profile := json.RawMessage(`{"name":"alice","tags":["admin","ops"]}`)
	must(docs.SetJSON(ctx, "user:alice", profile))
	got, ok, err := docs.GetJSON(ctx, "user:alice")
	must(err)
	fmt.Printf("GetJSON(user:alice) found=%v -> %s\n", ok, got)

	fmt.Println("\n=== Set (dot-notation, creates nested structure) ===")
	must(docs.Set(ctx, "config", "database.connection.host", "localhost"))
	must(docs.Set(ctx, "config", "database.connection.port", 5432))
	full, _, err := docs.GetJSON(ctx, "config")
	must(err)
	fmt.Printf("config document after two Sets: %s\n", full)

	fmt.Println("\n=== Get (dot-notation) ===")
	host, ok, err := docs.Get(ctx, "config", "database.connection.host")
	must(err)
	fmt.Printf("Get(config, database.connection.host) = %v, found=%v\n", host, ok)

	fmt.Println("\n=== Set on an array index ===")
	must(docs.Set(ctx, "user:alice", "tags.0", "superadmin"))
	tag0, _, err := docs.Get(ctx, "user:alice", "tags.0")
	must(err)
	fmt.Printf("tags.0 is now %v\n", tag0)

	fmt.Println("\n=== Delete ===")
	must(docs.Delete(ctx, "config", "database.connection.port"))
	full, _, err = docs.GetJSON(ctx, "config")
	must(err)
	fmt.Printf("config document after deleting port: %s\n", full)

	fmt.Println("\n=== not-found vs. type-mismatch ===")
	_, ok, err = docs.Get(ctx, "config", "database.connection.password")
	fmt.Printf("Get on a missing path:  ok=%v, err=%v (expected: ok=false, err=nil)\n", ok, err)

	_, ok, err = docs.Get(ctx, "config", "database.connection.host.extra")
	// "host" is a string leaf value — continuing the path past it (asking
	// for a field *inside* a string) is a real type error, not a normal
	// "not found", and DocumentService distinguishes the two on purpose:
	// this returns a non-nil error, unlike the missing-path case above.
	fmt.Printf("Get past a leaf value:  ok=%v, err=%v (expected: a distinct non-nil error, not just ok=false)\n", ok, err)

	fmt.Println("\ndone.")
}
