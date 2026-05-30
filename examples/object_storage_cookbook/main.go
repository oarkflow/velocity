package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/oarkflow/velocity"
)

func main() {
	dir := mustTempDir()
	defer os.RemoveAll(dir)

	db, err := velocity.NewWithConfig(velocity.Config{Path: dir, MasterKey: []byte("0123456789abcdef0123456789abcdef")})
	check(err)
	defer db.Close()

	acl := &velocity.ObjectACL{
		Owner: "alice",
		Permissions: map[string][]string{
			"bob": {velocity.PermissionRead},
		},
		Public: false,
	}
	meta, err := db.StoreObject("docs/report.txt", "text/plain", "alice", []byte("v1 report"), &velocity.ObjectOptions{
		Version:        "v1",
		Tags:           map[string]string{"team": "risk"},
		CustomMetadata: map[string]string{"case": "alpha"},
		Encrypt:        true,
		ACL:            acl,
		StorageClass:   "STANDARD",
	})
	check(err)

	meta2, err := db.StoreObjectStream("docs/report.txt", "text/plain", "alice", strings.NewReader("v2 report"), int64(len("v2 report")), &velocity.ObjectOptions{
		Version: "v2",
		Tags:    map[string]string{"team": "risk", "state": "final"},
		Encrypt: true,
	})
	check(err)

	savedACL, err := db.GetObjectACL("docs/report.txt")
	check(err)
	stream, got, err := db.GetObjectStream("docs/report.txt", "alice")
	check(err)
	body, err := io.ReadAll(stream)
	check(err)
	check(stream.Close())

	objects, err := db.ListObjects(velocity.ObjectListOptions{Prefix: "docs/", Recursive: true, MaxKeys: 10, User: "alice", IncludeACL: true})
	check(err)
	versions, err := db.ListObjectVersions("docs/report.txt")
	check(err)
	v1Body, _, err := db.GetObjectVersion("docs/report.txt", meta.VersionID, "alice")
	check(err)

	record, err := db.PutObject(context.Background(), velocity.PutObjectRequest{
		Path: "uploads/raw.bin", User: "system", ContentType: "application/octet-stream",
		Reader: strings.NewReader("raw payload"), Size: int64(len("raw payload")),
		Options: &velocity.ObjectOptions{Encrypt: false, SystemOperation: true},
	})
	check(err)
	objectStream, err := db.GetObjectStreamV2(context.Background(), velocity.GetObjectRequest{Path: "uploads/raw.bin", User: "system", System: true})
	check(err)
	check(objectStream.Close())

	check(db.DeleteObject("docs/report.txt", "alice"))
	check(db.HardDeleteObject("uploads/raw.bin", "system"))
	repair, err := db.RepairObjectStorage(context.Background(), velocity.RepairOptions{DryRun: true})
	check(err)

	fmt.Printf("stored versions: %s -> %s acl_public=%t\n", meta.VersionID, meta2.VersionID, savedACL.Public)
	fmt.Printf("latest: %s %q size=%d\n", got.Version, string(body), got.Size)
	fmt.Printf("objects listed: %d, versions: %d, v1=%q\n", len(objects), len(versions), string(v1Body))
	fmt.Printf("v2 request object: %s, repair missing=%d rebuilt=%d\n", record.Path, repair.MissingFiles, repair.IndexesRebuilt)
}

func mustTempDir() string {
	dir, err := os.MkdirTemp("", "velocity_object_storage_cookbook_")
	check(err)
	return dir
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
