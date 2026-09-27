// Command envelope_custody demonstrates Velocity v2's envelope plugin: a
// sealed, auditable container with an append-only hash-chained
// chain-of-custody ledger (v1's "secure evidence cabinet" concept),
// tamper-evident export/import, and bundle envelopes that reference
// content stored elsewhere (kv keys, inline bytes) rather than copying it
// in.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	cryptoxchacha "github.com/oarkflow/velocity/v2/plugins/crypto-xchacha"
	"github.com/oarkflow/velocity/v2/plugins/envelope"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func main() {
	dir, err := os.MkdirTemp("", "velocity-envelope-example-*")
	must(err)
	defer os.RemoveAll(dir)

	manifest := kernel.Manifest{
		Plugins: []kernel.PluginSpec{
			{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
			{Name: "crypto-xchacha", Enabled: true, Config: map[string]any{"key": "demo-envelope-key-32-bytes-long!"}},
			{Name: "kv", Enabled: true},
			{Name: "envelope", Enabled: true},
		},
	}
	k := kernel.New(manifest)
	ctx := context.Background()
	all := []api.Plugin{
		storagelsm.New(),
		cryptoxchacha.New(),
		kv.New("storage-lsm"),
		envelope.NewPlugin("storage-lsm", "crypto-xchacha"),
	}
	must(k.Boot(ctx, all, manifest.Enabled()))
	defer k.Shutdown(ctx)

	svc := k.Registry().MustLookup("envelope").(api.EnvelopeService)
	kvSvc := k.Registry().MustLookup("kv").(api.KVService)

	fmt.Println("=== Create a sealed evidence envelope ===")
	env, err := svc.Create(ctx, "officer-jane", api.Envelope{
		Label: "Case #2026-0091 — dashcam footage manifest",
		Kind:  "inline",
		Inline: []byte("SHA256:9f8e...  dashcam_2026-09-27_0800.mp4\n" +
			"SHA256:1a2b...  incident_report.pdf"),
		Metadata: map[string]string{"case_id": "2026-0091"},
	})
	must(err)
	fmt.Printf("created envelope id=%s custody entries=%d\n", env.ID, len(env.Custody))

	fmt.Println("\n=== Extend the custody chain ===")
	env, err = svc.AppendCustodyEvent(ctx, env.ID, "officer-jane", "transferred", "handed to evidence locker")
	must(err)
	env, err = svc.AppendCustodyEvent(ctx, env.ID, "clerk-sam", "received", "logged into evidence locker B-14")
	must(err)
	fmt.Printf("custody chain now has %d entries:\n", len(env.Custody))
	for _, c := range env.Custody {
		fmt.Printf("  #%d %-12s by %-12s prevHash=%s… eventHash=%s…\n",
			c.Sequence, c.Action, c.Actor, short(c.PrevHash), short(c.EventHash))
	}

	fmt.Println("\n=== Get reloads and unseals correctly ===")
	reloaded, err := svc.Get(ctx, env.ID)
	must(err)
	fmt.Printf("reloaded label=%q inline content matches original: %v\n",
		reloaded.Label, bytes.Equal(reloaded.Inline, env.Inline))

	fmt.Println("\n=== Export / Import round trip ===")
	var exported bytes.Buffer
	must(svc.Export(ctx, env.ID, &exported))
	fmt.Printf("exported %d bytes\n", exported.Len())
	exportedBytes := append([]byte(nil), exported.Bytes()...)

	imported, err := svc.Import(ctx, bytes.NewReader(exportedBytes))
	must(err)
	fmt.Printf("imported envelope id=%s custody entries=%d inline matches=%v\n",
		imported.ID, len(imported.Custody), bytes.Equal(imported.Inline, env.Inline))

	fmt.Println("\n=== Tamper rejection on Import ===")
	tampered := append([]byte(nil), exportedBytes...)
	tampered[len(tampered)/2] ^= 0xFF
	if _, err := svc.Import(ctx, bytes.NewReader(tampered)); err != nil {
		fmt.Printf("Import of tampered export: REJECTED as expected (%v)\n", err)
	} else {
		log.Fatal("tampered envelope export was accepted — this should never happen")
	}

	fmt.Println("\n=== Bundle envelope referencing external resources ===")
	must(kvSvc.Put(ctx, "evidence/2026-0091/gps-log", []byte("47.6062,-122.3321 @ 2026-09-27T08:00:00Z")))
	bundle, err := svc.Create(ctx, "officer-jane", api.Envelope{
		Label: "Case #2026-0091 — evidence bundle",
		Kind:  "bundle",
		Resources: []api.EnvelopeResource{
			{ID: "gps-log", Type: "kv", Ref: "evidence/2026-0091/gps-log"},
			{ID: "note", Type: "inline", Inline: []byte("Officer note: suspect vehicle matched APB.")},
		},
	})
	must(err)
	fmt.Printf("created bundle id=%s with %d resource references\n", bundle.ID, len(bundle.Resources))

	resolved, err := svc.ResolveResources(ctx, bundle.ID)
	must(err)
	for id, data := range resolved {
		fmt.Printf("  resolved %-8s -> %q\n", id, string(data))
	}
}

func short(hash string) string {
	if len(hash) > 8 {
		return hash[:8]
	}
	return hash
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
