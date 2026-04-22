package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	velocity "github.com/oarkflow/velocity"
)

func main() {
	// =====================================================================
	// 1. DB Setup
	// =====================================================================
	fmt.Println("\n=== DB Setup ===")

	tempDir, err := os.MkdirTemp("", "velocity-s3-demo-*")
	if err != nil {
		log.Fatal("failed to create temp dir:", err)
	}
	defer os.RemoveAll(tempDir)

	db, err := velocity.New(tempDir)
	if err != nil {
		log.Fatal("failed to create DB:", err)
	}
	defer db.Close()

	fmt.Println("Created temp DB at:", tempDir)

	// =====================================================================
	// 2. S3 Credentials
	// =====================================================================
	fmt.Println("\n=== S3 Credentials ===")

	credStore := velocity.NewS3CredentialStore(db)

	cred, err := credStore.GenerateCredentials("demo-user", "Demo access key")
	if err != nil {
		log.Fatal("failed to generate credentials:", err)
	}
	fmt.Printf("Access Key ID:     %s\n", cred.AccessKeyID)
	fmt.Printf("Secret Access Key: %s\n", cred.SecretAccessKey)
	fmt.Printf("User ID:           %s\n", cred.UserID)
	fmt.Printf("Active:            %v\n", cred.Active)

	// Retrieve the credential back
	retrieved, err := credStore.GetCredential(cred.AccessKeyID)
	if err != nil {
		log.Fatal("failed to retrieve credential:", err)
	}
	fmt.Printf("Retrieved user:    %s\n", retrieved.UserID)

	// List credentials for user
	creds, err := credStore.ListCredentials("demo-user")
	if err != nil {
		log.Fatal("failed to list credentials:", err)
	}
	fmt.Printf("Credentials for demo-user: %d\n", len(creds))

	// =====================================================================
	// 3. Bucket Operations
	// =====================================================================
	fmt.Println("\n=== Bucket Operations ===")

	bm := velocity.NewBucketManager(db)

	// Create buckets
	if err := bm.CreateBucket("my-data-bucket", "demo-user", "us-east-1"); err != nil {
		log.Fatal("failed to create bucket:", err)
	}
	fmt.Println("Created bucket: my-data-bucket")

	if err := bm.CreateBucket("my-backup-bucket", "demo-user", "us-west-2"); err != nil {
		log.Fatal("failed to create backup bucket:", err)
	}
	fmt.Println("Created bucket: my-backup-bucket")

	// List buckets
	buckets, err := bm.ListBuckets("demo-user")
	if err != nil {
		log.Fatal("failed to list buckets:", err)
	}
	fmt.Printf("Buckets owned by demo-user: %d\n", len(buckets))
	for _, b := range buckets {
		fmt.Printf("  - %s (region: %s, created: %s)\n", b.Name, b.Region, b.CreationDate.Format(time.RFC3339))
	}

	// Head bucket
	info, err := bm.HeadBucket("my-data-bucket")
	if err != nil {
		log.Fatal("failed to head bucket:", err)
	}
	fmt.Printf("HeadBucket: name=%s, owner=%s, region=%s\n", info.Name, info.Owner, info.Region)

	// =====================================================================
	// 4. Object Operations
	// =====================================================================
	fmt.Println("\n=== Object Operations ===")

	// Store objects
	objData := []byte("Hello, Velocity S3! This is a test object with some content for demonstration purposes.")
	opts := &velocity.ObjectOptions{
		Version:      velocity.DefaultVersion,
		StorageClass: "STANDARD",
		Tags:         map[string]string{"env": "demo", "purpose": "testing"},
		CustomMetadata: map[string]string{
			"x-custom-header": "example-value",
		},
		SystemOperation: true,
	}

	meta, err := db.StoreObject("my-data-bucket/documents/hello.txt", "text/plain", "demo-user", objData, opts)
	if err != nil {
		log.Fatal("failed to store object:", err)
	}
	fmt.Printf("Stored object: path=%s, size=%d, id=%s\n", meta.Path, meta.Size, meta.ObjectID)

	// Store a second object for copy test
	objData2 := []byte("Second object content for copy demonstration.")
	meta2, err := db.StoreObject("my-data-bucket/documents/copy-source.txt", "text/plain", "demo-user", objData2, &velocity.ObjectOptions{
		Version:         velocity.DefaultVersion,
		SystemOperation: true,
	})
	if err != nil {
		log.Fatal("failed to store second object:", err)
	}
	fmt.Printf("Stored object: path=%s, size=%d\n", meta2.Path, meta2.Size)

	// Copy object
	copyMeta, err := db.CopyObject("my-data-bucket", "documents/copy-source.txt", "my-backup-bucket", "backup/copy-source.txt", "demo-user")
	if err != nil {
		log.Fatal("failed to copy object:", err)
	}
	fmt.Printf("Copied object to: %s (size=%d)\n", copyMeta.Path, copyMeta.Size)

	// Get object with range
	rangeData, rangeMeta, ranges, err := db.GetObjectWithRange("my-data-bucket", "documents/hello.txt", "demo-user", "bytes=0-12")
	if err != nil {
		log.Fatal("failed to get object with range:", err)
	}
	fmt.Printf("Range read: got %d bytes, range=[%d-%d], content=%q\n",
		len(rangeData), ranges[0].Start, ranges[0].End, string(rangeData))
	_ = rangeMeta

	// Object Tagging
	err = db.PutObjectTagging("my-data-bucket", "documents/hello.txt", map[string]string{
		"department": "engineering",
		"project":    "velocity",
		"priority":   "high",
	})
	if err != nil {
		log.Fatal("failed to put object tagging:", err)
	}
	fmt.Println("Set object tags")

	tags, err := db.GetObjectTagging("my-data-bucket", "documents/hello.txt")
	if err != nil {
		log.Fatal("failed to get object tagging:", err)
	}
	fmt.Printf("Object tags: %v\n", tags)

	// Compute ETag
	etag := velocity.ComputeETag(objData)
	fmt.Printf("ETag: %s\n", etag)

	// =====================================================================
	// 5. Multipart Upload
	// =====================================================================
	fmt.Println("\n=== Multipart Upload ===")

	mm := velocity.NewMultipartManager(db)

	// Create multipart upload
	upload, err := mm.CreateMultipartUpload("my-data-bucket", "large-file.bin", "application/octet-stream", "demo-user", map[string]string{"upload-type": "demo"})
	if err != nil {
		log.Fatal("failed to create multipart upload:", err)
	}
	fmt.Printf("Created multipart upload: id=%s, bucket=%s, key=%s\n", upload.UploadID, upload.Bucket, upload.Key)

	// Upload parts
	part1Data := bytes.Repeat([]byte("A"), 1024) // Small parts for demo
	part2Data := bytes.Repeat([]byte("B"), 1024)
	part3Data := bytes.Repeat([]byte("C"), 512)

	part1, err := mm.UploadPart(upload.UploadID, 1, bytes.NewReader(part1Data), int64(len(part1Data)))
	if err != nil {
		log.Fatal("failed to upload part 1:", err)
	}
	fmt.Printf("Uploaded part 1: etag=%s, size=%d\n", part1.ETag, part1.Size)

	part2, err := mm.UploadPart(upload.UploadID, 2, bytes.NewReader(part2Data), int64(len(part2Data)))
	if err != nil {
		log.Fatal("failed to upload part 2:", err)
	}
	fmt.Printf("Uploaded part 2: etag=%s, size=%d\n", part2.ETag, part2.Size)

	part3, err := mm.UploadPart(upload.UploadID, 3, bytes.NewReader(part3Data), int64(len(part3Data)))
	if err != nil {
		log.Fatal("failed to upload part 3:", err)
	}
	fmt.Printf("Uploaded part 3: etag=%s, size=%d\n", part3.ETag, part3.Size)

	// List parts
	parts, err := mm.ListParts(upload.UploadID)
	if err != nil {
		log.Fatal("failed to list parts:", err)
	}
	fmt.Printf("Listed %d parts for upload\n", len(parts))

	// Complete multipart upload
	completeParts := []velocity.CompletePart{
		{PartNumber: 1, ETag: part1.ETag},
		{PartNumber: 2, ETag: part2.ETag},
		{PartNumber: 3, ETag: part3.ETag},
	}

	completeMeta, err := mm.CompleteMultipartUpload(upload.UploadID, completeParts)
	if err != nil {
		log.Fatal("failed to complete multipart upload:", err)
	}
	fmt.Printf("Completed multipart upload: path=%s, size=%d, hash=%s\n", completeMeta.Path, completeMeta.Size, completeMeta.Hash)

	// =====================================================================
	// 6. Bucket Versioning
	// =====================================================================
	fmt.Println("\n=== Bucket Versioning ===")

	// Enable versioning
	err = bm.SetBucketVersioning("my-data-bucket", "Enabled")
	if err != nil {
		log.Fatal("failed to set bucket versioning:", err)
	}
	fmt.Println("Enabled versioning on my-data-bucket")

	// Check versioning status
	versioningState, err := bm.GetBucketVersioning("my-data-bucket")
	if err != nil {
		log.Fatal("failed to get bucket versioning:", err)
	}
	fmt.Printf("Versioning status: %s\n", versioningState)

	// Suspend versioning
	err = bm.SetBucketVersioning("my-data-bucket", "Suspended")
	if err != nil {
		log.Fatal("failed to suspend versioning:", err)
	}
	suspendedState, _ := bm.GetBucketVersioning("my-data-bucket")
	fmt.Printf("Versioning status after suspend: %s\n", suspendedState)

	// Re-enable for subsequent tests
	_ = bm.SetBucketVersioning("my-data-bucket", "Enabled")

	// =====================================================================
	// 7. Object Lock
	// =====================================================================
	fmt.Println("\n=== Object Lock ===")

	olm := velocity.NewObjectLockManager(db)

	// Enable object lock on bucket
	lockConfig := velocity.ObjectLockConfig{
		Enabled: true,
		DefaultRetention: &velocity.ObjectLockRetentionRule{
			Mode: velocity.LockModeGovernance,
			Days: 30,
		},
	}
	err = olm.SetBucketObjectLock("my-data-bucket", lockConfig)
	if err != nil {
		log.Fatal("failed to enable object lock:", err)
	}
	fmt.Println("Enabled Object Lock with GOVERNANCE mode, 30-day default retention")

	// Get bucket lock config
	lockCfg, err := olm.GetBucketObjectLock("my-data-bucket")
	if err != nil {
		log.Fatal("failed to get lock config:", err)
	}
	fmt.Printf("Lock enabled: %v, mode: %s, days: %d\n",
		lockCfg.Enabled, lockCfg.DefaultRetention.Mode, lockCfg.DefaultRetention.Days)

	// Set object-level retention
	retention := velocity.ObjectRetention{
		Mode:            velocity.LockModeCompliance,
		RetainUntilDate: time.Now().Add(365 * 24 * time.Hour),
	}
	err = olm.SetObjectRetention("my-data-bucket", "documents/hello.txt", retention)
	if err != nil {
		log.Fatal("failed to set object retention:", err)
	}
	fmt.Println("Set COMPLIANCE retention on documents/hello.txt for 1 year")

	// Check if object is locked
	locked, err := olm.IsObjectLocked("my-data-bucket", "documents/hello.txt")
	if err != nil {
		log.Fatal("failed to check lock:", err)
	}
	fmt.Printf("Object locked: %v\n", locked)

	// Check if deletion is allowed
	canDelete, reason, err := olm.CanDeleteObject("my-data-bucket", "documents/hello.txt", "demo-user", false)
	if err != nil {
		log.Fatal("failed to check delete:", err)
	}
	fmt.Printf("Can delete: %v, reason: %s\n", canDelete, reason)

	// Set legal hold
	err = olm.SetObjectLegalHold("my-data-bucket", "documents/hello.txt", velocity.ObjectLegalHold{Status: "ON"})
	if err != nil {
		log.Fatal("failed to set legal hold:", err)
	}
	hold, _ := olm.GetObjectLegalHold("my-data-bucket", "documents/hello.txt")
	fmt.Printf("Legal hold status: %s\n", hold.Status)

	// =====================================================================
	// 8. IAM Policies
	// =====================================================================
	fmt.Println("\n=== IAM Policies ===")

	iam := velocity.NewIAMPolicyEngine(db)

	// Create an Allow policy
	allowPolicy := &velocity.IAMPolicy{
		Name: "s3-read-policy",
		Statements: []velocity.IAMStatement{
			{
				Sid:       "AllowGetObject",
				Effect:    velocity.IAMEffectAllow,
				Principal: []string{"demo-user"},
				Action:    []string{"s3:GetObject", "s3:ListBucket"},
				Resource:  []string{"arn:velocity:s3:::my-data-bucket/*"},
			},
		},
	}
	err = iam.CreatePolicy(allowPolicy)
	if err != nil {
		log.Fatal("failed to create allow policy:", err)
	}
	fmt.Println("Created IAM allow policy: s3-read-policy")

	// Create a Deny policy
	denyPolicy := &velocity.IAMPolicy{
		Name: "deny-delete-policy",
		Statements: []velocity.IAMStatement{
			{
				Sid:       "DenyDeleteObject",
				Effect:    velocity.IAMEffectDeny,
				Principal: []string{"demo-user"},
				Action:    []string{"s3:DeleteObject"},
				Resource:  []string{"arn:velocity:s3:::my-data-bucket/*"},
			},
		},
	}
	err = iam.CreatePolicy(denyPolicy)
	if err != nil {
		log.Fatal("failed to create deny policy:", err)
	}
	fmt.Println("Created IAM deny policy: deny-delete-policy")

	// Attach policies to user
	err = iam.AttachUserPolicy("demo-user", "s3-read-policy")
	if err != nil {
		log.Fatal("failed to attach allow policy:", err)
	}
	err = iam.AttachUserPolicy("demo-user", "deny-delete-policy")
	if err != nil {
		log.Fatal("failed to attach deny policy:", err)
	}
	fmt.Println("Attached both policies to demo-user")

	// List user policies
	userPolicies := iam.GetUserPolicies("demo-user")
	fmt.Printf("Policies for demo-user: %v\n", userPolicies)

	// Evaluate access - GetObject (should be allowed)
	getResult := iam.EvaluateAccess(&velocity.IAMEvalRequest{
		Principal: "demo-user",
		Action:    "s3:GetObject",
		Resource:  "arn:velocity:s3:::my-data-bucket/documents/hello.txt",
	})
	fmt.Printf("Evaluate s3:GetObject: allowed=%v, reason=%s\n", getResult.Allowed, getResult.Reason)

	// Evaluate access - DeleteObject (should be denied)
	deleteResult := iam.EvaluateAccess(&velocity.IAMEvalRequest{
		Principal: "demo-user",
		Action:    "s3:DeleteObject",
		Resource:  "arn:velocity:s3:::my-data-bucket/documents/hello.txt",
	})
	fmt.Printf("Evaluate s3:DeleteObject: allowed=%v, explicit_deny=%v, reason=%s\n",
		deleteResult.Allowed, deleteResult.ExplicitDeny, deleteResult.Reason)

	// Evaluate access - PutObject (should be denied - no matching policy)
	putResult := iam.EvaluateAccess(&velocity.IAMEvalRequest{
		Principal: "demo-user",
		Action:    "s3:PutObject",
		Resource:  "arn:velocity:s3:::my-data-bucket/documents/hello.txt",
	})
	fmt.Printf("Evaluate s3:PutObject: allowed=%v, reason=%s\n", putResult.Allowed, putResult.Reason)

	// =====================================================================
	// 9. Erasure Coding
	// =====================================================================
	fmt.Println("\n=== Erasure Coding ===")

	config := velocity.ErasureConfig{
		DataShards:   4,
		ParityShards: 2,
	}
	encoder, err := velocity.NewErasureEncoder(config)
	if err != nil {
		log.Fatal("failed to create erasure encoder:", err)
	}
	fmt.Printf("Erasure config: %d data + %d parity = %d total shards\n",
		config.DataShards, config.ParityShards, config.TotalShards())

	// Encode data
	originalData := []byte("This is important data that must survive disk failures! " +
		"Erasure coding provides redundancy without full replication overhead.")
	shards, err := encoder.Encode(originalData)
	if err != nil {
		log.Fatal("failed to encode data:", err)
	}
	fmt.Printf("Encoded %d bytes into %d shards of %d bytes each\n",
		len(originalData), len(shards), len(shards[0]))

	// Verify shards
	valid := encoder.Verify(shards)
	fmt.Printf("Shards valid: %v\n", valid)

	// Simulate shard loss - lose 2 shards (parity count)
	fmt.Println("Simulating loss of shard 1 and shard 4...")
	damagedShards := make([][]byte, len(shards))
	for i, s := range shards {
		if i == 1 || i == 4 {
			damagedShards[i] = nil // lost shard
		} else {
			cp := make([]byte, len(s))
			copy(cp, s)
			damagedShards[i] = cp
		}
	}

	// Decode from damaged shards
	recovered, err := encoder.Decode(damagedShards, len(originalData))
	if err != nil {
		log.Fatal("failed to decode data:", err)
	}

	if string(recovered) == string(originalData) {
		fmt.Println("Successfully recovered original data from damaged shards!")
	} else {
		fmt.Println("ERROR: recovered data does not match original")
	}

	// =====================================================================
	// 10. Consistent Hash Ring
	// =====================================================================
	fmt.Println("\n=== Consistent Hash Ring ===")

	ring := velocity.NewConsistentHashRing(150)

	// Add nodes
	ring.AddNode("node-1")
	ring.AddNode("node-2")
	ring.AddNode("node-3")
	ring.AddNode("node-4")
	fmt.Printf("Added 4 nodes to hash ring (total: %d)\n", ring.NodeCount())
	fmt.Printf("Nodes: %v\n", ring.ListNodes())

	// Get node for keys
	testKeys := []string{"user:1001", "user:1002", "document:abc", "image:xyz", "config:main"}
	for _, key := range testKeys {
		node := ring.GetNode(key)
		fmt.Printf("Key %q -> %s\n", key, node)
	}

	// Get replication nodes (3 replicas)
	replNodes := ring.GetNodes("user:1001", 3)
	fmt.Printf("Replication nodes for 'user:1001' (3 replicas): %v\n", replNodes)

	// Show rebalancing impact
	rebalance := ring.GetRebalanceMap("node-5")
	fmt.Printf("Rebalance map for adding node-5: %d source nodes affected\n", len(rebalance))
	for src, ranges := range rebalance {
		fmt.Printf("  %s -> node-5: %d virtual node ranges\n", src, len(ranges))
	}

	// =====================================================================
	// 11. Metrics
	// =====================================================================
	fmt.Println("\n=== Metrics ===")

	mc := velocity.NewMetricsCollector()

	// Record some requests
	mc.RecordRequest("GET", "200", 5*time.Millisecond)
	mc.RecordRequest("GET", "200", 12*time.Millisecond)
	mc.RecordRequest("PUT", "201", 50*time.Millisecond)
	mc.RecordRequest("GET", "404", 3*time.Millisecond)
	mc.RecordRequest("DELETE", "200", 8*time.Millisecond)
	mc.RecordRequest("GET", "200", 150*time.Millisecond)

	// Set some gauge values
	mc.SetGauge("velocity_objects_total", nil, 42)
	mc.SetGauge("velocity_bytes_stored_total", nil, 1048576)

	fmt.Println("Recorded 6 requests and set gauge metrics")

	// Render Prometheus format
	output := mc.RenderMetrics()
	fmt.Println("Prometheus metrics output (first 800 chars):")
	if len(output) > 800 {
		fmt.Println(output[:800])
		fmt.Println("... (truncated)")
	} else {
		fmt.Println(output)
	}

	// =====================================================================
	// 12. Storage Tiering
	// =====================================================================
	fmt.Println("\n=== Storage Tiering ===")

	stm := velocity.NewStorageTierManager(db, 24*time.Hour)

	// Set lifecycle configuration
	lifecycleConfig := &velocity.LifecycleConfig{
		Rules: []velocity.LifecycleRule{
			{
				ID:     "transition-to-ia",
				Status: "Enabled",
				Filter: velocity.LifecycleRuleFilter{
					Prefix: "documents/",
				},
				Transitions: []velocity.Transition{
					{Days: 30, StorageClass: velocity.ClassInfrequentAccess},
					{Days: 90, StorageClass: velocity.ClassGlacier},
					{Days: 365, StorageClass: velocity.ClassDeepArchive},
				},
			},
			{
				ID:     "expire-temp-files",
				Status: "Enabled",
				Filter: velocity.LifecycleRuleFilter{
					Prefix: "tmp/",
					Tags:   map[string]string{"temporary": "true"},
				},
				Expiration: &velocity.Expiration{
					Days: 7,
				},
			},
		},
	}

	err = stm.PutBucketLifecycle("my-data-bucket", lifecycleConfig)
	if err != nil {
		log.Fatal("failed to set lifecycle config:", err)
	}
	fmt.Println("Set lifecycle configuration with 2 rules")

	// Retrieve lifecycle config
	retrieved2, err := stm.GetBucketLifecycle("my-data-bucket")
	if err != nil {
		log.Fatal("failed to get lifecycle config:", err)
	}
	fmt.Printf("Retrieved %d lifecycle rules:\n", len(retrieved2.Rules))
	for _, rule := range retrieved2.Rules {
		fmt.Printf("  - %s (status: %s, prefix: %q)\n", rule.ID, rule.Status, rule.Filter.Prefix)
		for _, t := range rule.Transitions {
			fmt.Printf("      Transition after %d days -> %s\n", t.Days, t.StorageClass)
		}
		if rule.Expiration != nil {
			fmt.Printf("      Expire after %d days\n", rule.Expiration.Days)
		}
	}

	// Check lifecycle status
	status := stm.GetLifecycleStatus()
	fmt.Printf("Lifecycle status: running=%v, interval=%s\n", status.Running, status.EvaluationInterval)

	// Validate storage classes
	fmt.Printf("STANDARD is valid: %v (tier=%d)\n",
		velocity.IsValidStorageClass("STANDARD"), velocity.StorageClassTier("STANDARD"))
	fmt.Printf("GLACIER is valid: %v (tier=%d)\n",
		velocity.IsValidStorageClass("GLACIER"), velocity.StorageClassTier("GLACIER"))

	// =====================================================================
	// 13. Presigned URLs
	// =====================================================================
	fmt.Println("\n=== Presigned URLs ===")

	presigner := velocity.NewPresignedURLGenerator(credStore, "us-east-1", "http://localhost:8080")

	// Generate presigned GET URL
	getURL, err := presigner.GeneratePresignedGetURL(cred.AccessKeyID, "my-data-bucket", "documents/hello.txt", 15*time.Minute)
	if err != nil {
		log.Fatal("failed to generate presigned GET URL:", err)
	}
	fmt.Println("Presigned GET URL:")
	// Print URL truncated to keep output readable
	if len(getURL) > 120 {
		fmt.Printf("  %s...\n", getURL[:120])
	} else {
		fmt.Printf("  %s\n", getURL)
	}

	// Verify it contains expected components
	if strings.Contains(getURL, "X-Amz-Algorithm") && strings.Contains(getURL, "X-Amz-Signature") {
		fmt.Println("  (contains valid SigV4 query parameters)")
	}

	// Generate presigned PUT URL
	putURL, err := presigner.GeneratePresignedPutURL(cred.AccessKeyID, "my-data-bucket", "uploads/new-file.txt", "text/plain", 1*time.Hour)
	if err != nil {
		log.Fatal("failed to generate presigned PUT URL:", err)
	}
	fmt.Println("Presigned PUT URL:")
	if len(putURL) > 120 {
		fmt.Printf("  %s...\n", putURL[:120])
	} else {
		fmt.Printf("  %s\n", putURL)
	}

	// Validate presigned URL
	bucket, key, err := presigner.ValidatePresignedURL(getURL)
	if err != nil {
		log.Fatal("failed to validate presigned URL:", err)
	}
	fmt.Printf("Validated presigned URL: bucket=%s, key=%s\n", bucket, key)

	// =====================================================================
	// Done
	// =====================================================================
	fmt.Println("\nAll examples completed successfully!")
}
