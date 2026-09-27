// Command config_import_export demonstrates Velocity v2's config
// import/export surface (api.ConfigIOService): moving data between a KV
// namespace and common config file formats (.env, flat/nested JSON).
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/configio"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "velocity-config-io-*")
	must(err)
	defer os.RemoveAll(dir)

	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
		{Name: "kv", Enabled: true},
		{Name: "configio", Enabled: true},
	}}

	k := kernel.New(manifest)
	must(k.Boot(ctx, []api.Plugin{
		storagelsm.New(),
		kv.New("storage-lsm"),
		configio.NewPlugin("kv"),
	}, manifest.Enabled()))
	defer k.Shutdown(ctx)

	kvSvc := k.Registry().MustLookup("kv").(api.KVService)
	cfg := k.Registry().MustLookup("configio").(api.ConfigIOService)

	fmt.Println("=== Put a few kv keys under 'app.' ===")
	must(kvSvc.Put(ctx, "app.name", []byte("velocity")))
	must(kvSvc.Put(ctx, "app.version", []byte("2.0")))
	must(kvSvc.Put(ctx, "app.tagline", []byte("fast and flexible")))
	fmt.Println("put app.name, app.version, app.tagline")

	fmt.Println("\n=== ExportEnv(\"app.\") ===")
	envBytes, err := cfg.ExportEnv(ctx, "app.")
	must(err)
	fmt.Print(string(envBytes))

	fmt.Println("\n=== ImportEnv into a DIFFERENT prefix (\"app2.\") ===")
	n, err := cfg.ImportEnv(ctx, "app2.", envBytes)
	must(err)
	fmt.Printf("imported %d keys\n", n)
	// ImportEnv writes back under prefix+KEY using the LITERAL (uppercase)
	// key from the .env text — it's the inverse of ExportEnv's
	// lowercase-to-UPPER_SNAKE_CASE conversion, not a case-insensitive
	// merge back onto the original key names.
	name, _, err := kvSvc.Get(ctx, "app2.NAME")
	must(err)
	tagline, _, err := kvSvc.Get(ctx, "app2.TAGLINE")
	must(err)
	fmt.Printf("app2.NAME    = %q\n", name)
	fmt.Printf("app2.TAGLINE = %q (round-tripped correctly, including the space)\n", tagline)

	fmt.Println("\n=== ImportJSON (nested) into a third prefix (\"cfg.\") ===")
	jsonBlob := []byte(`{"db":{"host":"localhost","port":5432},"debug":true}`)
	n, err = cfg.ImportJSON(ctx, "cfg.", jsonBlob)
	must(err)
	fmt.Printf("imported %d keys from nested JSON\n", n)
	dbHost, _, err := kvSvc.Get(ctx, "cfg.db.host")
	must(err)
	dbPort, _, err := kvSvc.Get(ctx, "cfg.db.port")
	must(err)
	fmt.Printf("cfg.db.host = %q (flattened from {\"db\":{\"host\":...}})\n", dbHost)
	fmt.Printf("cfg.db.port = %q\n", dbPort)

	fmt.Println("\n=== ExportJSON(\"cfg.\") ===")
	flatJSON, err := cfg.ExportJSON(ctx, "cfg.")
	must(err)
	fmt.Printf("%s\n", flatJSON)

	fmt.Println("\ndone.")
}
