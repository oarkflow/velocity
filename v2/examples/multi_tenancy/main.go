// Command multi_tenancy demonstrates Velocity v2's multi-tenant isolation:
// api.WithTenant/api.TenantFromContext scope kv and object storage calls
// to a tenant's own key prefix (enforced directly by kv/object, not by
// the tenancy plugin itself), while plugins/tenancy adds the optional
// quota/lifecycle layer (CreateTenant, SetQuota, DeleteTenant) on top.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"sort"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	"github.com/oarkflow/velocity/v2/plugins/object"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
	"github.com/oarkflow/velocity/v2/plugins/tenancy"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "velocity-multi-tenancy-*")
	must(err)
	defer os.RemoveAll(dir)

	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
		{Name: "kv", Enabled: true},
		{Name: "object", Enabled: true},
		{Name: "tenancy", Enabled: true},
	}}

	k := kernel.New(manifest)
	must(k.Boot(ctx, []api.Plugin{
		storagelsm.New(),
		kv.New("storage-lsm"),
		object.New("storage-lsm"),
		tenancy.NewPlugin("storage-lsm"),
	}, manifest.Enabled()))
	defer k.Shutdown(ctx)

	kvSvc := k.Registry().MustLookup("kv").(api.KVService)
	objSvc := k.Registry().MustLookup("object").(api.ObjectService)
	tenants := k.Registry().MustLookup("tenancy").(api.TenantService)

	fmt.Println("=== CreateTenant: tenant-a (unlimited), tenant-b (MaxKeys: 3) ===")
	must(tenants.CreateTenant(ctx, "tenant-a", api.TenantQuota{}))
	must(tenants.CreateTenant(ctx, "tenant-b", api.TenantQuota{MaxKeys: 3}))

	ctxA := api.WithTenant(ctx, "tenant-a")
	ctxB := api.WithTenant(ctx, "tenant-b")

	fmt.Println("\n=== kv isolation: same key, different tenants ===")
	must(kvSvc.Put(ctxA, "config", []byte("tenant-a's config")))
	must(kvSvc.Put(ctxB, "config", []byte("tenant-b's config")))
	valA, _, err := kvSvc.Get(ctxA, "config")
	must(err)
	valB, _, err := kvSvc.Get(ctxB, "config")
	must(err)
	fmt.Printf("tenant-a Get(config) = %q\n", valA)
	fmt.Printf("tenant-b Get(config) = %q\n", valB)
	if string(valA) == string(valB) {
		log.Fatal("ISOLATION FAILURE: both tenants saw the same value")
	}
	fmt.Println("confirmed: tenants never see each other's value for the same key")

	fmt.Println("\n=== kv isolation: Keys()/Scan() never cross tenant boundaries ===")
	must(kvSvc.Put(ctxA, "secret-a-only", []byte("x")))
	keysA, err := kvSvc.Keys(ctxA, "*")
	must(err)
	sort.Strings(keysA)
	fmt.Printf("tenant-a Keys(*) = %v\n", keysA)
	keysB, err := kvSvc.Keys(ctxB, "*")
	must(err)
	sort.Strings(keysB)
	fmt.Printf("tenant-b Keys(*) = %v\n", keysB)
	for _, key := range keysB {
		if key == "secret-a-only" {
			log.Fatal("ISOLATION FAILURE: tenant-b enumerated tenant-a's key")
		}
	}
	fmt.Println("confirmed: tenant-b's Keys() never surfaces tenant-a's data")

	fmt.Println("\n=== quota enforcement: tenant-b's MaxKeys=3 ===")
	// tenant-b already has "config" and "secret-a-only" is tenant-a's, so
	// tenant-b currently has 1 key ("config"). Two more should succeed,
	// a fourth should be rejected.
	for i, k2 := range []string{"k1", "k2"} {
		must(kvSvc.Put(ctxB, k2, []byte("v")))
		fmt.Printf("tenant-b Put(%s) succeeded (%d/3)\n", k2, i+2)
	}
	err = kvSvc.Put(ctxB, "k3", []byte("v"))
	if err == nil {
		log.Fatal("expected quota rejection, got nil error")
	}
	fmt.Printf("tenant-b Put(k3) correctly rejected: %v\n", err)

	fmt.Println("\n=== object isolation: same bucket/key, different tenants ===")
	must(objSvc.CreateBucket(ctxA, "docs"))
	must(objSvc.CreateBucket(ctxB, "docs"))
	_, err = objSvc.PutObject(ctxA, "docs", "readme.txt", bytes.NewReader([]byte("tenant-a's document")), api.ObjectMeta{ContentType: "text/plain"})
	must(err)
	_, err = objSvc.PutObject(ctxB, "docs", "readme.txt", bytes.NewReader([]byte("tenant-b's document")), api.ObjectMeta{ContentType: "text/plain"})
	must(err)

	rA, _, err := objSvc.GetObject(ctxA, "docs", "readme.txt", "")
	must(err)
	bodyA, _ := io.ReadAll(rA)
	rA.Close()
	rB, _, err := objSvc.GetObject(ctxB, "docs", "readme.txt", "")
	must(err)
	bodyB, _ := io.ReadAll(rB)
	rB.Close()
	fmt.Printf("tenant-a GetObject(docs/readme.txt) = %q\n", bodyA)
	fmt.Printf("tenant-b GetObject(docs/readme.txt) = %q\n", bodyB)
	if string(bodyA) == string(bodyB) {
		log.Fatal("ISOLATION FAILURE: both tenants saw the same object body")
	}
	fmt.Println("confirmed: object storage isolates tenants the same way kv does")

	fmt.Println("\n=== DeleteTenant: tenant-b's data is removed, tenant-a's is untouched ===")
	must(tenants.DeleteTenant(ctx, "tenant-b"))
	_, ok, err := kvSvc.Get(ctxB, "config")
	must(err)
	fmt.Printf("tenant-b Get(config) after DeleteTenant: found=%v (expected false)\n", ok)
	valA, ok, err = kvSvc.Get(ctxA, "config")
	must(err)
	fmt.Printf("tenant-a Get(config) after tenant-b deleted: found=%v, value=%q (untouched)\n", ok, valA)

	fmt.Println("\ndone.")
}
