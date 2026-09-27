// Command cross_plugin_transactions demonstrates Velocity v2's cross-plugin
// atomic write coordinator (api.TxCoordinator / api.CrossTx, plugins/transaction):
// a single Commit can atomically apply writes staged by DIFFERENT plugins
// (here, kv and secret) in one real StorageBackend.Batch call, because both
// plugins resolve to the same underlying storage-lsm instance. Commit either
// applies everything staged, or nothing — see plugins/transaction/integration_test.go's
// TestCrossPluginTx_GenuineAtomicityUnderPartialFailure for the deeper,
// forced-mid-batch-failure version of this proof (this example demonstrates
// the two forms of atomicity that are practical to show against a real,
// unmodified kernel-booted backend: Commit-applies-both and
// Rollback/never-commit-applies-neither, plus the "refuses a mismatched
// backend" safety check).
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	cryptoxchacha "github.com/oarkflow/velocity/v2/plugins/crypto-xchacha"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	"github.com/oarkflow/velocity/v2/plugins/secret"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
	storagemem "github.com/oarkflow/velocity/v2/plugins/storage-mem"
	"github.com/oarkflow/velocity/v2/plugins/transaction"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "velocity-cross-tx-*")
	must(err)
	defer os.RemoveAll(dir)

	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
		{Name: "crypto-xchacha", Enabled: true, Config: map[string]any{"key": "01234567890123456789012345678901"}},
		{Name: "kv", Enabled: true},
		{Name: "secret", Enabled: true},
		{Name: "transaction", Enabled: true},
	}}

	k := kernel.New(manifest)
	must(k.Boot(ctx, []api.Plugin{
		storagelsm.New(),
		cryptoxchacha.New(),
		kv.New("storage-lsm"),
		secret.NewPlugin("storage-lsm", "crypto-xchacha"),
		transaction.NewPlugin(),
	}, manifest.Enabled()))
	defer k.Shutdown(ctx)

	kvSvc := k.Registry().MustLookup("kv").(api.KVService)
	kvPlugin := k.Registry().MustLookup("kv").(*kv.Plugin)
	secretPlugin := k.Registry().MustLookup("secret").(*secret.Plugin)
	secretSvc := k.Registry().MustLookup("secret").(api.SecretService)
	coordinator := k.Registry().MustLookup("transaction").(api.TxCoordinator)

	fmt.Println("=== Commit: a kv write and a secret write, staged together ===")
	tx, err := coordinator.Begin(ctx)
	must(err)
	must(kvPlugin.PutStaged(ctx, tx, "order:1", []byte("pending")))
	version, err := secretPlugin.SetStaged(ctx, tx, "order:1:token", []byte("s3cr3t-token-1"))
	must(err)
	fmt.Printf("staged kv.Put(order:1) and secret.Set(order:1:token) [version %d] — neither has taken effect yet\n", version)

	_, foundBefore, _ := kvSvc.Get(ctx, "order:1")
	fmt.Printf("before Commit: kv.Get(order:1) found=%v (expected false)\n", foundBefore)

	must(tx.Commit(ctx))
	fmt.Println("Commit succeeded")

	val, found, err := kvSvc.Get(ctx, "order:1")
	must(err)
	fmt.Printf("after Commit: kv.Get(order:1) = %q, found=%v\n", val, found)
	secretVal, err := secretSvc.Get(ctx, "order:1:token", 0)
	must(err)
	fmt.Printf("after Commit: secret.Get(order:1:token) = %q\n", secretVal)
	fmt.Println("confirmed: BOTH writes took effect atomically")

	fmt.Println("\n=== Rollback: staged writes that are never committed take effect nowhere ===")
	tx2, err := coordinator.Begin(ctx)
	must(err)
	must(kvPlugin.PutStaged(ctx, tx2, "order:2", []byte("pending")))
	_, err = secretPlugin.SetStaged(ctx, tx2, "order:2:token", []byte("s3cr3t-token-2"))
	must(err)
	tx2.Rollback()
	fmt.Println("staged kv.Put(order:2) and secret.Set(order:2:token), then Rollback()")

	_, found2, _ := kvSvc.Get(ctx, "order:2")
	_, err2 := secretSvc.Get(ctx, "order:2:token", 0)
	fmt.Printf("kv.Get(order:2) found=%v (expected false)\n", found2)
	fmt.Printf("secret.Get(order:2:token) err=%v (expected a not-found error)\n", err2)
	if found2 || err2 == nil {
		log.Fatal("ATOMICITY FAILURE: a rolled-back write took effect")
	}
	fmt.Println("confirmed: NEITHER write took effect")

	fmt.Println("\n=== Safety check: Stage refuses a second, mismatched storage backend ===")
	tx3, err := coordinator.Begin(ctx)
	must(err)
	must(kvPlugin.PutStaged(ctx, tx3, "order:3", []byte("pending")))
	otherBackend := storagemem.NewEngine() // a real, but DIFFERENT, StorageBackend instance
	err = tx3.Stage(otherBackend, []api.BatchOp{{Entry: api.Entry{Key: []byte("x"), Value: []byte("y")}}})
	if err == nil {
		log.Fatal("expected Stage to refuse a mismatched backend instance, got nil error")
	}
	fmt.Printf("Stage against a different backend instance correctly refused: %v\n", err)
	tx3.Rollback()

	fmt.Println("\nNote: the deeper guarantee — that a genuine mid-batch failure (e.g. a")
	fmt.Println("corrupted write among several staged ops) leaves NEITHER write applied,")
	fmt.Println("not just the ones after the failure — is proven directly against a forced")
	fmt.Println("failure in plugins/transaction/integration_test.go's")
	fmt.Println("TestCrossPluginTx_GenuineAtomicityUnderPartialFailure, which this example")
	fmt.Println("does not reproduce since it requires a deliberately-poisoned backend not")
	fmt.Println("practical to construct against a real, unmodified storage-lsm instance.")

	fmt.Println("\ndone.")
}
