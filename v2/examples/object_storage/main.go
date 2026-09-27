// Command object_storage demonstrates Velocity v2's object-storage surface
// (api.ObjectService): buckets, versioning, HEAD, range reads, copy, and
// S3-style Object Lock retention.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/object"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func read(r io.ReadCloser) string {
	defer r.Close()
	b, err := io.ReadAll(r)
	must(err)
	return string(b)
}

func main() {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "velocity-object-*")
	must(err)
	defer os.RemoveAll(dir)

	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
		{Name: "object", Enabled: true},
	}}

	k := kernel.New(manifest)
	must(k.Boot(ctx, []api.Plugin{storagelsm.New(), object.New("storage-lsm")}, manifest.Enabled()))
	defer k.Shutdown(ctx)

	svc := k.Registry().MustLookup("object").(api.ObjectService)

	fmt.Println("=== CreateBucket ===")
	must(svc.CreateBucket(ctx, "docs"))

	fmt.Println("\n=== PutObject (version 1) ===")
	v1, err := svc.PutObject(ctx, "docs", "readme.txt", bytes.NewReader([]byte("hello v1")), api.ObjectMeta{ContentType: "text/plain"})
	must(err)
	fmt.Printf("stored version %s, size=%d\n", v1.VersionID, v1.Size)

	fmt.Println("\n=== PutObject again (version 2) ===")
	v2, err := svc.PutObject(ctx, "docs", "readme.txt", bytes.NewReader([]byte("hello v2, now longer")), api.ObjectMeta{ContentType: "text/plain"})
	must(err)
	fmt.Printf("stored version %s, size=%d\n", v2.VersionID, v2.Size)

	fmt.Println("\n=== GetObject (latest) ===")
	r, meta, err := svc.GetObject(ctx, "docs", "readme.txt", "")
	must(err)
	fmt.Printf("latest (version %s): %q\n", meta.VersionID, read(r))

	fmt.Println("\n=== GetObject (explicit version 1) ===")
	r, meta, err = svc.GetObject(ctx, "docs", "readme.txt", v1.VersionID)
	must(err)
	fmt.Printf("version %s: %q\n", meta.VersionID, read(r))

	fmt.Println("\n=== ListObjects ===")
	objs, err := svc.ListObjects(ctx, "docs", "")
	must(err)
	for _, o := range objs {
		fmt.Printf("  %s/%s (version %s, %d bytes)\n", o.Bucket, o.Key, o.VersionID, o.Size)
	}

	fmt.Println("\n=== HeadObject (metadata only) ===")
	head, err := svc.HeadObject(ctx, "docs", "readme.txt", "")
	must(err)
	fmt.Printf("HEAD: size=%d contentType=%s etag=%s\n", head.Size, head.ContentType, head.ETag)

	fmt.Println("\n=== GetObjectRange (partial read) ===")
	rr, _, err := svc.GetObjectRange(ctx, "docs", "readme.txt", "", 0, 4)
	must(err)
	fmt.Printf("bytes [0,4]: %q\n", read(rr))

	fmt.Println("\n=== CopyObject ===")
	cp, err := svc.CopyObject(ctx, "docs", "readme.txt", "", "docs", "readme-copy.txt")
	must(err)
	r, _, err = svc.GetObject(ctx, "docs", "readme-copy.txt", "")
	must(err)
	fmt.Printf("copied to %s: %q\n", cp.Key, read(r))

	fmt.Println("\n=== PutRetention (GOVERNANCE) + DeleteObject rejection ===")
	must(svc.PutRetention(ctx, "docs", "readme.txt", api.RetentionPolicy{
		Mode:        api.LockGovernance,
		RetainUntil: time.Now().Add(1 * time.Hour),
	}))
	err = svc.DeleteObject(ctx, "docs", "readme.txt", "", false)
	fmt.Printf("DeleteObject without bypass: err=%v (expected: rejected)\n", err)
	err = svc.DeleteObject(ctx, "docs", "readme.txt", "", true)
	fmt.Printf("DeleteObject with bypassGovernance=true: err=%v (expected: nil)\n", err)

	fmt.Println("\n=== Cleanup ===")
	must(svc.DeleteObject(ctx, "docs", "readme-copy.txt", "", false))
	must(svc.DeleteBucket(ctx, "docs"))
	fmt.Println("bucket deleted.")

	fmt.Println("\ndone.")
}
