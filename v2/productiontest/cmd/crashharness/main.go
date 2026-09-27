// Command crashharness is a throwaway child-process workload used only by
// productiontest's crash_recovery_test.go: it boots a real kernel against
// a real data directory (passed as argv[1]) and writes a continuous
// stream of KV/object/secret data, printing "ACK <n>" to stdout after
// each acknowledged write so the parent test knows exactly how many
// writes were durably confirmed before it sends SIGKILL. It never exits
// on its own — the parent always kills it.
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	cryptoxchacha "github.com/oarkflow/velocity/v2/plugins/crypto-xchacha"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	"github.com/oarkflow/velocity/v2/plugins/secret"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func main() {
	dir := os.Args[1]

	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir, "always_sync": true}},
		{Name: "crypto-xchacha", Enabled: true, Config: map[string]any{"key": "crashharness-demo-key-32-bytes!!"}},
		{Name: "kv", Enabled: true},
		{Name: "secret", Enabled: true},
	}}

	k := kernel.New(manifest)
	plugins := []api.Plugin{
		storagelsm.New(),
		cryptoxchacha.New(),
		kv.New("storage-lsm"),
		secret.NewPlugin("storage-lsm", "crypto-xchacha"),
	}
	if err := k.Boot(context.Background(), plugins, manifest.Enabled()); err != nil {
		fmt.Fprintln(os.Stderr, "boot:", err)
		os.Exit(1)
	}

	kvSvc := k.Registry().MustLookup("kv").(api.KVService)

	ctx := context.Background()
	for i := 0; ; i++ {
		key := "crash:key:" + strconv.Itoa(i)
		if err := kvSvc.Put(ctx, key, []byte("value-"+strconv.Itoa(i))); err != nil {
			fmt.Fprintln(os.Stderr, "put:", err)
			os.Exit(1)
		}
		// Printed AFTER Put returns, so the parent only trusts an ACK
		// count once this write has actually been acknowledged as
		// durable (always_sync: true) — a count the parent reads before
		// killing us is guaranteed to be durably on disk already.
		fmt.Println("ACK", i)
	}
}
