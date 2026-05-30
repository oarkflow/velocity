package main

import (
	"context"
	"fmt"
	"github.com/oarkflow/velocity/pkg/s3"
	"os"
	"strings"
	"time"

	"github.com/oarkflow/velocity"
)

func main() {
	dir := mustTempDir()
	defer os.RemoveAll(dir)

	db, err := velocity.NewWithConfig(velocity.Config{Path: dir, MasterKey: []byte("0123456789abcdef0123456789abcdef")})
	check(err)
	defer db.Close()

	buckets := s3.NewBucketManager(db, db)
	check(buckets.CreateBucket("source-bucket", "alice", "us-east-1"))
	check(buckets.CreateBucket("archive-bucket", "alice", "us-east-1"))
	check(buckets.SetBucketVersioning("source-bucket", "Enabled"))
	check(buckets.SetBucketEncryption("source-bucket", &s3.BucketEncryption{SSEAlgorithm: "AES256"}))
	check(buckets.SetBucketQuota("source-bucket", &s3.BucketQuota{MaxSizeBytes: 1 << 20, MaxObjects: 100}))

	locker := velocity.NewObjectLockManager(db)
	check(locker.SetBucketObjectLock("source-bucket", velocity.ObjectLockConfig{
		Enabled: true,
		DefaultRetention: &velocity.ObjectLockRetentionRule{
			Mode: velocity.LockModeGovernance,
			Days: 1,
		},
	}))

	_, err = db.PutObject(context.Background(), velocity.PutObjectRequest{
		Bucket: "source-bucket", Key: "docs/a.txt", User: "alice", ContentType: "text/plain",
		Reader: stringsReader("hello from s3 cookbook"), Size: int64(len("hello from s3 cookbook")),
		Options:       &velocity.ObjectOptions{Tags: map[string]string{"class": "demo"}, StorageClass: s3.S3StorageStandard},
		EnforceBucket: true,
	})
	check(err)
	check(locker.ApplyDefaultRetention("source-bucket", "docs/a.txt"))
	check(locker.SetObjectLegalHold("source-bucket", "docs/a.txt", velocity.ObjectLegalHold{Status: "ON"}))
	locked, err := locker.IsObjectLocked("source-bucket", "docs/a.txt")
	check(err)

	replication := velocity.NewBucketReplicationManager(db)
	check(replication.PutReplicationConfig(&velocity.BucketReplicationConfig{
		SourceBucket: "source-bucket",
		Rules: []velocity.ReplicationRule{{
			ID: "archive-docs", Status: velocity.ReplicationRuleEnabled, Priority: 1,
			SourceBucket: "source-bucket", DestinationBucket: "archive-bucket",
			Prefix: "docs/", TagFilter: map[string]string{"class": "demo"},
		}},
	}))

	copyMeta, err := db.CopyObject("source-bucket", "docs/a.txt", "archive-bucket", "docs/a-copy.txt", "alice")
	check(err)
	check(db.PutObjectTagging("source-bucket", "docs/a.txt", map[string]string{"project": "cookbook"}))
	tags, err := db.GetObjectTagging("source-bucket", "docs/a.txt")
	check(err)
	head, err := db.GetHeadObjectInfo("source-bucket", "docs/a.txt", "alice")
	check(err)
	ranged, _, ranges, err := db.GetObjectWithRange("source-bucket", "docs/a.txt", "alice", "bytes=0-4")
	check(err)

	creds := s3.NewS3CredentialStore(db, db)
	cred, err := creds.GenerateCredentials("alice", "cookbook")
	check(err)
	presigner := s3.NewPresignedURLGenerator(creds, "us-east-1", "http://localhost:8080")
	getURL, err := presigner.GeneratePresignedGetURL(cred.AccessKeyID, "source-bucket", "docs/a.txt", 15*time.Minute)
	check(err)
	putURL, err := presigner.GeneratePresignedPutURL(cred.AccessKeyID, "source-bucket", "docs/new.txt", "text/plain", time.Hour)
	check(err)
	bucket, key, err := presigner.ValidatePresignedURL(getURL)
	check(err)

	quota, err := buckets.GetBucketQuota("source-bucket")
	check(err)
	fmt.Printf("locked=%t copy=%s tags=%d range=%q ranges=%d head=%s quota_objects=%d\n", locked, copyMeta.Path, len(tags), string(ranged), len(ranges), head.ETag, quota.MaxObjects)
	fmt.Printf("validated presigned GET: %s/%s, put url bytes=%d\n", bucket, key, len(putURL))
}

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }

func mustTempDir() string {
	dir, err := os.MkdirTemp("", "velocity_s3_bucket_cookbook_")
	check(err)
	return dir
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
