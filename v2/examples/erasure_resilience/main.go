// Command erasure_resilience demonstrates Velocity v2's erasure-coded
// shard store: Reed-Solomon-style parity, bit-rot detection, and
// self-healing. It stores a payload, directly corrupts one underlying
// shard (bypassing the plugin, simulating real disk bit-rot), and shows
// the corruption is both transparently tolerated on read AND repairable.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/erasure"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func main() {
	dir, err := os.MkdirTemp("", "velocity-erasure-example-*")
	must(err)
	defer os.RemoveAll(dir)

	manifest := kernel.Manifest{
		Plugins: []kernel.PluginSpec{
			{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
			{Name: "erasure", Enabled: true},
		},
	}
	k := kernel.New(manifest)
	ctx := context.Background()

	all := []api.Plugin{storagelsm.New(), erasure.NewPlugin("storage-lsm")}
	must(k.Boot(ctx, all, manifest.Enabled()))
	defer k.Shutdown(ctx)

	shards := k.Registry().MustLookup("erasure").(api.ShardStore)
	storage := k.Registry().MustLookup("storage").(api.StorageBackend)

	const id = "document-42"
	original := bytes.Repeat([]byte("Velocity erasure-coded storage survives bit-rot. "), 100)

	fmt.Println("=== Step 1: store a payload, erasure-encoded across data+parity shards ===")
	must(shards.StoreShards(ctx, id, original))
	fmt.Printf("stored %d bytes under id %q\n", len(original), id)

	fmt.Println("\n=== Step 2: verify — healthy, no corruption ===")
	ok, corrupt, err := shards.VerifyShards(ctx, id)
	must(err)
	fmt.Printf("VerifyShards: ok=%v corrupt=%v\n", ok, corrupt)

	fmt.Println("\n=== Step 3: simulate real disk bit-rot — corrupt shard 0 directly on disk ===")
	shardKey := []byte(fmt.Sprintf("erasure/%s/shard/%d", id, 0))
	raw, found, err := storage.Get(ctx, shardKey)
	must(err)
	if !found {
		log.Fatal("expected shard 0 to exist")
	}
	corrupted := append([]byte(nil), raw...)
	for i := range corrupted {
		corrupted[i] ^= 0xFF // flip every bit — this bypasses the plugin entirely,
	} // exactly like real bit-rot would corrupt a block on disk
	must(storage.Put(ctx, api.Entry{Key: shardKey, Value: corrupted}))
	fmt.Println("shard 0 corrupted directly via the storage backend (plugin was never called)")

	fmt.Println("\n=== Step 4: verify again — corruption is now detected ===")
	ok, corrupt, err = shards.VerifyShards(ctx, id)
	must(err)
	fmt.Printf("VerifyShards: ok=%v corrupt=%v\n", ok, corrupt)
	if ok || len(corrupt) == 0 {
		log.Fatal("expected corruption to be detected")
	}

	fmt.Println("\n=== Step 5: read despite corruption — parity reconstructs the correct data ===")
	recovered, err := shards.ReadShards(ctx, id)
	must(err)
	if !bytes.Equal(recovered, original) {
		log.Fatal("recovered data does not match original — reconstruction failed")
	}
	fmt.Printf("ReadShards returned all %d original bytes correctly, DESPITE the corrupted shard\n", len(recovered))

	fmt.Println("\n=== Step 6: heal — repair the corrupted shard on disk ===")
	must(shards.HealShards(ctx, id))
	fmt.Println("HealShards completed")

	fmt.Println("\n=== Step 7: verify once more — fully healed ===")
	ok, corrupt, err = shards.VerifyShards(ctx, id)
	must(err)
	fmt.Printf("VerifyShards: ok=%v corrupt=%v\n", ok, corrupt)
	if !ok {
		log.Fatal("expected shard set to be healthy after healing")
	}

	fmt.Println("\ndone. Self-healing storage proven end to end: corrupt -> detect -> " +
		"transparently reconstruct on read -> repair on disk -> healthy again.")
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
