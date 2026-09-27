// Command secrets_and_crypto demonstrates Velocity v2's secrets surface
// (api.SecretService) plus using the underlying CryptoProvider directly.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	cryptoxchacha "github.com/oarkflow/velocity/v2/plugins/crypto-xchacha"
	"github.com/oarkflow/velocity/v2/plugins/secret"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "velocity-secrets-*")
	must(err)
	defer os.RemoveAll(dir)

	// A real deployment must NOT hardcode a key like this — load it from
	// an environment variable, a KMS, or a secret manager. This fixed
	// 32-byte demo key exists only so this example is reproducible and
	// does not depend on an ephemeral, process-only random key.
	const demoKey = "velocity-demo-32-byte-secret-ok!"

	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
		{Name: "crypto-xchacha", Enabled: true, Config: map[string]any{"key": demoKey}},
		{Name: "secret", Enabled: true},
	}}

	k := kernel.New(manifest)
	must(k.Boot(ctx, []api.Plugin{
		storagelsm.New(),
		cryptoxchacha.New(),
		secret.NewPlugin("storage-lsm", "crypto-xchacha"),
	}, manifest.Enabled()))
	defer k.Shutdown(ctx)

	secrets := k.Registry().MustLookup("secret").(api.SecretService)

	fmt.Println("=== Set (version 1) ===")
	v1, err := secrets.Set(ctx, "db_password", []byte("hunter2"))
	must(err)
	fmt.Printf("set version %d\n", v1)

	fmt.Println("\n=== Get (latest) ===")
	val, err := secrets.Get(ctx, "db_password", 0)
	must(err)
	fmt.Printf("latest value: %q\n", val)

	fmt.Println("\n=== Set again (version 2) ===")
	v2, err := secrets.Set(ctx, "db_password", []byte("correct-horse-battery-staple"))
	must(err)
	fmt.Printf("set version %d\n", v2)

	fmt.Println("\n=== Versions ===")
	versions, err := secrets.Versions(ctx, "db_password")
	must(err)
	for _, v := range versions {
		fmt.Printf("  version %d, created %s\n", v.Version, v.CreatedAt.Format("15:04:05.000"))
	}

	fmt.Println("\n=== Get explicit version 1 vs latest ===")
	old, err := secrets.Get(ctx, "db_password", 1)
	must(err)
	latest, err := secrets.Get(ctx, "db_password", 0)
	must(err)
	fmt.Printf("version 1: %q\n", old)
	fmt.Printf("latest:    %q\n", latest)

	fmt.Println("\n=== Rotate ===")
	must(secrets.Rotate(ctx, "db_password"))
	afterRotate, err := secrets.Get(ctx, "db_password", 0)
	must(err)
	fmt.Printf("value unchanged after rotate (re-sealed under current key): %q\n", afterRotate)

	fmt.Println("\n=== Delete ===")
	must(secrets.Delete(ctx, "db_password"))
	_, err = secrets.Get(ctx, "db_password", 0)
	fmt.Printf("Get after Delete: err=%v (expected: not found)\n", err)

	fmt.Println("\n=== CryptoProvider used directly ===")
	crypto := k.Registry().MustLookup("crypto").(api.CryptoProvider)
	plaintext := []byte("a message that needs sealing")
	ciphertext, err := crypto.Encrypt(ctx, plaintext, []byte("example-aad"))
	must(err)
	fmt.Printf("encrypted %d bytes -> %d bytes ciphertext\n", len(plaintext), len(ciphertext))
	decrypted, err := crypto.Decrypt(ctx, ciphertext, []byte("example-aad"))
	must(err)
	fmt.Printf("decrypted: %q\n", decrypted)

	// Wrong AAD must fail — proves the AEAD tag is actually checked, not
	// just decoration.
	_, err = crypto.Decrypt(ctx, ciphertext, []byte("wrong-aad"))
	fmt.Printf("decrypt with wrong AAD: err=%v (expected: rejected)\n", err)

	fmt.Println("\ndone.")
}
