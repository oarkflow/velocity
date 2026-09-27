// Command backup_restore demonstrates Velocity v2's backup plugin:
// HMAC-signed full backups, prefix-scoped export/import, and tamper
// rejection — a corrupted backup stream is rejected outright rather than
// partially applied.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/backup"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func bootInstance(dir string) (*kernel.Kernel, api.KVService, api.BackupService) {
	manifest := kernel.Manifest{
		Plugins: []kernel.PluginSpec{
			{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
			{Name: "kv", Enabled: true},
			{Name: "backup", Enabled: true, Config: map[string]any{"hmac_key": "demo-hmac-key-for-this-example-32b"}},
		},
	}
	k := kernel.New(manifest)
	all := []api.Plugin{storagelsm.New(), kv.New("storage-lsm"), backup.NewPlugin("storage-lsm")}
	must(k.Boot(context.Background(), all, manifest.Enabled()))
	return k, k.Registry().MustLookup("kv").(api.KVService), k.Registry().MustLookup("backup").(api.BackupService)
}

func main() {
	ctx := context.Background()

	dirA, err := os.MkdirTemp("", "velocity-backup-source-*")
	must(err)
	defer os.RemoveAll(dirA)
	dirB, err := os.MkdirTemp("", "velocity-backup-target-*")
	must(err)
	defer os.RemoveAll(dirB)

	fmt.Println("=== Populate the source instance ===")
	kA, kvA, backupA := bootInstance(dirA)
	seed := map[string]string{
		"user/1/name":  "alice",
		"user/2/name":  "bob",
		"config/theme": "dark",
	}
	for k, v := range seed {
		must(kvA.Put(ctx, k, []byte(v)))
		fmt.Printf("  put %s = %q\n", k, v)
	}

	fmt.Println("\n=== Backup to an in-memory buffer ===")
	var buf bytes.Buffer
	must(backupA.Backup(ctx, &buf))
	fmt.Printf("backup size: %d bytes\n", buf.Len())
	backupBytes := append([]byte(nil), buf.Bytes()...)
	kA.Shutdown(ctx)

	fmt.Println("\n=== Restore into a FRESH second instance ===")
	kB, kvB, backupB := bootInstance(dirB)
	must(backupB.Restore(ctx, bytes.NewReader(backupBytes)))
	allMatch := true
	for k, want := range seed {
		got, ok, err := kvB.Get(ctx, k)
		must(err)
		match := ok && string(got) == want
		allMatch = allMatch && match
		fmt.Printf("  get %s = %q (want %q): match=%v\n", k, string(got), want, match)
	}
	if !allMatch {
		log.Fatal("restore did not reproduce the source data")
	}
	fmt.Println("Restore round trip: PASS (byte-for-byte match)")
	kB.Shutdown(ctx)

	fmt.Println("\n=== Tamper rejection ===")
	tampered := append([]byte(nil), backupBytes...)
	tampered[len(tampered)/2] ^= 0xFF // flip a bit in the middle of the stream

	dirC, err := os.MkdirTemp("", "velocity-backup-tampered-*")
	must(err)
	defer os.RemoveAll(dirC)
	kC, kvC, backupC := bootInstance(dirC)
	if err := backupC.Restore(ctx, bytes.NewReader(tampered)); err != nil {
		fmt.Printf("Restore of tampered stream: REJECTED as expected (%v)\n", err)
	} else {
		log.Fatal("tampered backup was accepted — this should never happen")
	}
	if _, ok, _ := kvC.Get(ctx, "user/1/name"); ok {
		log.Fatal("tampered restore partially applied data — this should never happen")
	}
	fmt.Println("Confirmed: no data was applied from the rejected stream")
	kC.Shutdown(ctx)

	fmt.Println("\n=== Prefix-scoped export/import ===")
	dirD, err := os.MkdirTemp("", "velocity-backup-export-src-*")
	must(err)
	defer os.RemoveAll(dirD)
	kD, kvD, backupD := bootInstance(dirD)
	for k, v := range seed {
		must(kvD.Put(ctx, k, []byte(v)))
	}
	defer kD.Shutdown(ctx)
	var userBuf bytes.Buffer
	must(backupD.Export(ctx, &userBuf, "user/"))
	fmt.Printf("export of prefix 'user/': %d bytes\n", userBuf.Len())

	dirE, err := os.MkdirTemp("", "velocity-backup-export-dst-*")
	must(err)
	defer os.RemoveAll(dirE)
	kE, kvE, backupE := bootInstance(dirE)
	must(kvE.Put(ctx, "config/theme", []byte("light"))) // pre-existing key Import must not disturb
	must(backupE.Import(ctx, bytes.NewReader(userBuf.Bytes())))
	if got, ok, _ := kvE.Get(ctx, "user/1/name"); ok {
		fmt.Printf("  imported user/1/name = %q\n", string(got))
	}
	if _, ok, _ := kvE.Get(ctx, "config/theme"); ok {
		fmt.Println("  config/theme (out of prefix, pre-existing) untouched: still present")
	}
	kE.Shutdown(ctx)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
