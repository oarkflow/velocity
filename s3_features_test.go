package velocity

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// 1. S3CredentialStore tests
// ============================================================================

func TestS3CredentialStore(t *testing.T) {
	t.Run("GenerateCredentials_creates_valid_credentials_with_VK_prefix", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		store := NewS3CredentialStore(db)
		cred, err := store.GenerateCredentials("user1", "test key")
		if err != nil {
			t.Fatalf("GenerateCredentials failed: %v", err)
		}

		if !strings.HasPrefix(cred.AccessKeyID, "VK") {
			t.Errorf("AccessKeyID should start with VK, got %q", cred.AccessKeyID)
		}
		if len(cred.AccessKeyID) < 4 {
			t.Errorf("AccessKeyID too short: %q", cred.AccessKeyID)
		}
		if cred.SecretAccessKey == "" {
			t.Error("SecretAccessKey should not be empty")
		}
		if cred.UserID != "user1" {
			t.Errorf("UserID = %q, want %q", cred.UserID, "user1")
		}
		if cred.Description != "test key" {
			t.Errorf("Description = %q, want %q", cred.Description, "test key")
		}
		if !cred.Active {
			t.Error("new credential should be active")
		}
		if cred.CreatedAt.IsZero() {
			t.Error("CreatedAt should not be zero")
		}
	})

	t.Run("GetCredential_retrieves_stored_credentials", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		store := NewS3CredentialStore(db)
		cred, err := store.GenerateCredentials("user1", "my key")
		if err != nil {
			t.Fatalf("GenerateCredentials failed: %v", err)
		}

		retrieved, err := store.GetCredential(cred.AccessKeyID)
		if err != nil {
			t.Fatalf("GetCredential failed: %v", err)
		}

		if retrieved.AccessKeyID != cred.AccessKeyID {
			t.Errorf("AccessKeyID = %q, want %q", retrieved.AccessKeyID, cred.AccessKeyID)
		}
		if retrieved.SecretAccessKey != cred.SecretAccessKey {
			t.Errorf("SecretAccessKey mismatch")
		}
		if retrieved.UserID != "user1" {
			t.Errorf("UserID = %q, want %q", retrieved.UserID, "user1")
		}
	})

	t.Run("DeleteCredential_deactivates_credential", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		store := NewS3CredentialStore(db)
		cred, err := store.GenerateCredentials("user1", "to delete")
		if err != nil {
			t.Fatalf("GenerateCredentials failed: %v", err)
		}

		// Should be retrievable before delete
		_, err = store.GetCredential(cred.AccessKeyID)
		if err != nil {
			t.Fatalf("GetCredential before delete should succeed: %v", err)
		}

		// Delete (deactivate)
		if err := store.DeleteCredential(cred.AccessKeyID); err != nil {
			t.Fatalf("DeleteCredential failed: %v", err)
		}

		// Should not be retrievable after delete
		_, err = store.GetCredential(cred.AccessKeyID)
		if err == nil {
			t.Error("GetCredential after delete should return error")
		}
	})

	t.Run("ListCredentials_filters_by_user_ID", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		store := NewS3CredentialStore(db)

		// Create credentials for two users
		_, err = store.GenerateCredentials("alice", "key1")
		if err != nil {
			t.Fatalf("GenerateCredentials failed: %v", err)
		}
		_, err = store.GenerateCredentials("alice", "key2")
		if err != nil {
			t.Fatalf("GenerateCredentials failed: %v", err)
		}
		_, err = store.GenerateCredentials("bob", "key3")
		if err != nil {
			t.Fatalf("GenerateCredentials failed: %v", err)
		}

		aliceCreds, err := store.ListCredentials("alice")
		if err != nil {
			t.Fatalf("ListCredentials failed: %v", err)
		}
		if len(aliceCreds) != 2 {
			t.Errorf("expected 2 credentials for alice, got %d", len(aliceCreds))
		}

		bobCreds, err := store.ListCredentials("bob")
		if err != nil {
			t.Fatalf("ListCredentials failed: %v", err)
		}
		if len(bobCreds) != 1 {
			t.Errorf("expected 1 credential for bob, got %d", len(bobCreds))
		}

		// Non-existent user
		emptyCreds, err := store.ListCredentials("charlie")
		if err != nil {
			t.Fatalf("ListCredentials failed: %v", err)
		}
		if len(emptyCreds) != 0 {
			t.Errorf("expected 0 credentials for charlie, got %d", len(emptyCreds))
		}
	})

	t.Run("Expired_credentials_are_rejected", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		store := NewS3CredentialStore(db)
		cred, err := store.GenerateCredentials("user1", "expiring key")
		if err != nil {
			t.Fatalf("GenerateCredentials failed: %v", err)
		}

		// Manually set expiration in the past
		pastTime := time.Now().Add(-1 * time.Hour)
		cred.ExpiresAt = &pastTime
		data, err := json.Marshal(cred)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		if err := db.PutWithTTL([]byte("s3:cred:"+cred.AccessKeyID), data, 0); err != nil {
			t.Fatalf("PutWithTTL failed: %v", err)
		}

		_, err = store.GetCredential(cred.AccessKeyID)
		if err == nil {
			t.Error("GetCredential should reject expired credential")
		}
		if err != nil && !strings.Contains(err.Error(), "expired") {
			t.Errorf("error should mention expired, got: %v", err)
		}
	})
}

// ============================================================================
// 2. SigV4Auth tests
// ============================================================================

func TestSigV4Auth(t *testing.T) {
	t.Run("ParseAuthorization_parses_valid_header", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		store := NewS3CredentialStore(db)
		auth := NewSigV4Auth(store, "us-east-1")

		header := "AWS4-HMAC-SHA256 Credential=VKABCDEF1234567890AB/20240101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abcdef1234567890abcdef1234567890"

		parsed, err := auth.ParseAuthorization(header)
		if err != nil {
			t.Fatalf("ParseAuthorization failed: %v", err)
		}

		if parsed.AccessKeyID != "VKABCDEF1234567890AB" {
			t.Errorf("AccessKeyID = %q, want %q", parsed.AccessKeyID, "VKABCDEF1234567890AB")
		}
		if parsed.Date != "20240101" {
			t.Errorf("Date = %q, want %q", parsed.Date, "20240101")
		}
		if parsed.Region != "us-east-1" {
			t.Errorf("Region = %q, want %q", parsed.Region, "us-east-1")
		}
		if parsed.Service != "s3" {
			t.Errorf("Service = %q, want %q", parsed.Service, "s3")
		}
		if len(parsed.SignedHeaders) != 2 {
			t.Errorf("expected 2 signed headers, got %d", len(parsed.SignedHeaders))
		}
		if parsed.Signature != "abcdef1234567890abcdef1234567890" {
			t.Errorf("Signature = %q, want %q", parsed.Signature, "abcdef1234567890abcdef1234567890")
		}
	})

	t.Run("ParseAuthorization_rejects_invalid_algorithm", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		store := NewS3CredentialStore(db)
		auth := NewSigV4Auth(store, "us-east-1")

		header := "AWS4-HMAC-SHA1 Credential=VKTEST/20240101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc123"

		_, err = auth.ParseAuthorization(header)
		if err == nil {
			t.Error("ParseAuthorization should reject invalid algorithm")
		}
	})

	t.Run("ParsePresignedURL_parses_valid_query_params", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		store := NewS3CredentialStore(db)
		auth := NewSigV4Auth(store, "us-east-1")

		query := url.Values{}
		query.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
		query.Set("X-Amz-Credential", "VKABCDEF1234567890AB/20240101/us-east-1/s3/aws4_request")
		query.Set("X-Amz-SignedHeaders", "host")
		query.Set("X-Amz-Signature", "deadbeef1234567890")
		query.Set("X-Amz-Date", "20240101T000000Z")
		query.Set("X-Amz-Expires", "3600")

		parsed, err := auth.ParsePresignedURL(query)
		if err != nil {
			t.Fatalf("ParsePresignedURL failed: %v", err)
		}

		if parsed.AccessKeyID != "VKABCDEF1234567890AB" {
			t.Errorf("AccessKeyID = %q, want %q", parsed.AccessKeyID, "VKABCDEF1234567890AB")
		}
		if parsed.Signature != "deadbeef1234567890" {
			t.Errorf("Signature = %q, want %q", parsed.Signature, "deadbeef1234567890")
		}
		if !parsed.IsPresigned {
			t.Error("IsPresigned should be true")
		}
		if parsed.Region != "us-east-1" {
			t.Errorf("Region = %q, want %q", parsed.Region, "us-east-1")
		}
	})

	t.Run("ParsePresignedURL_rejects_missing_signature", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		store := NewS3CredentialStore(db)
		auth := NewSigV4Auth(store, "us-east-1")

		query := url.Values{}
		query.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
		query.Set("X-Amz-Credential", "VKTEST/20240101/us-east-1/s3/aws4_request")
		query.Set("X-Amz-SignedHeaders", "host")
		// No X-Amz-Signature set

		_, err = auth.ParsePresignedURL(query)
		if err == nil {
			t.Error("ParsePresignedURL should reject missing signature")
		}
		if err != nil && !strings.Contains(err.Error(), "missing signature") {
			t.Errorf("error should mention missing signature, got: %v", err)
		}
	})
}

// ============================================================================
// 3. BucketManager tests
// ============================================================================

func TestBucketManager(t *testing.T) {
	t.Run("CreateBucket_with_valid_name", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		bm := NewBucketManager(db)
		if err := bm.CreateBucket("my-test-bucket", "owner1", "us-east-1"); err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}

		info, err := bm.HeadBucket("my-test-bucket")
		if err != nil {
			t.Fatalf("HeadBucket failed: %v", err)
		}
		if info.Name != "my-test-bucket" {
			t.Errorf("Name = %q, want %q", info.Name, "my-test-bucket")
		}
		if info.Owner != "owner1" {
			t.Errorf("Owner = %q, want %q", info.Owner, "owner1")
		}
		if info.Region != "us-east-1" {
			t.Errorf("Region = %q, want %q", info.Region, "us-east-1")
		}
	})

	t.Run("CreateBucket_rejects_invalid_names", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		bm := NewBucketManager(db)

		tests := []struct {
			name   string
			bucket string
			reason string
		}{
			{"too short", "ab", "too short"},
			{"uppercase", "MyBucket", "uppercase"},
			{"IP format", "192.168.1.1", "IP address"},
			{"consecutive dots", "my..bucket", "consecutive dots"},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				err := bm.CreateBucket(tc.bucket, "owner1", "us-east-1")
				if err == nil {
					t.Errorf("CreateBucket(%q) should fail for %s", tc.bucket, tc.reason)
				}
			})
		}
	})

	t.Run("DeleteBucket_non_existent_returns_NoSuchBucket", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		bm := NewBucketManager(db)
		err = bm.DeleteBucket("non-existent-bucket")
		if err == nil {
			t.Error("DeleteBucket should return error for non-existent bucket")
		}
		if err != nil && !strings.Contains(err.Error(), "NoSuchBucket") {
			t.Errorf("error should contain NoSuchBucket, got: %v", err)
		}
	})

	t.Run("DeleteBucket_non_empty_returns_BucketNotEmpty", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		bm := NewBucketManager(db)
		if err := bm.CreateBucket("my-bucket", "owner1", "us-east-1"); err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}

		// Store an object in the bucket
		_, err = db.StoreObject("my-bucket/test.txt", "text/plain", "owner1", []byte("hello"), nil)
		if err != nil {
			t.Fatalf("StoreObject failed: %v", err)
		}

		err = bm.DeleteBucket("my-bucket")
		if err == nil {
			t.Error("DeleteBucket should return error for non-empty bucket")
		}
		if err != nil && !strings.Contains(err.Error(), "BucketNotEmpty") {
			t.Errorf("error should contain BucketNotEmpty, got: %v", err)
		}
	})

	t.Run("HeadBucket_returns_info_for_existing_bucket", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		bm := NewBucketManager(db)
		if err := bm.CreateBucket("head-test", "owner1", "eu-west-1"); err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}

		info, err := bm.HeadBucket("head-test")
		if err != nil {
			t.Fatalf("HeadBucket failed: %v", err)
		}
		if info.Name != "head-test" {
			t.Errorf("Name = %q, want %q", info.Name, "head-test")
		}
		if info.Owner != "owner1" {
			t.Errorf("Owner = %q, want %q", info.Owner, "owner1")
		}

		// Non-existent bucket
		_, err = bm.HeadBucket("no-such-bucket")
		if err == nil {
			t.Error("HeadBucket should return error for non-existent bucket")
		}
	})

	t.Run("ListBuckets_returns_all_and_filtered_by_owner", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		bm := NewBucketManager(db)
		if err := bm.CreateBucket("bucket-alice-1", "alice", "us-east-1"); err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}
		if err := bm.CreateBucket("bucket-alice-2", "alice", "us-east-1"); err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}
		if err := bm.CreateBucket("bucket-bob-1", "bob", "us-east-1"); err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}

		// List all
		all, err := bm.ListBuckets("")
		if err != nil {
			t.Fatalf("ListBuckets failed: %v", err)
		}
		if len(all) != 3 {
			t.Errorf("expected 3 buckets total, got %d", len(all))
		}

		// Filter by alice
		aliceBuckets, err := bm.ListBuckets("alice")
		if err != nil {
			t.Fatalf("ListBuckets(alice) failed: %v", err)
		}
		if len(aliceBuckets) != 2 {
			t.Errorf("expected 2 buckets for alice, got %d", len(aliceBuckets))
		}

		// Filter by bob
		bobBuckets, err := bm.ListBuckets("bob")
		if err != nil {
			t.Fatalf("ListBuckets(bob) failed: %v", err)
		}
		if len(bobBuckets) != 1 {
			t.Errorf("expected 1 bucket for bob, got %d", len(bobBuckets))
		}
	})

	t.Run("SetBucketVersioning_and_GetBucketVersioning", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		bm := NewBucketManager(db)
		if err := bm.CreateBucket("ver-bucket", "owner1", "us-east-1"); err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}

		// Initially empty
		state, err := bm.GetBucketVersioning("ver-bucket")
		if err != nil {
			t.Fatalf("GetBucketVersioning failed: %v", err)
		}
		if state != "" {
			t.Errorf("initial versioning state = %q, want empty string", state)
		}

		// Enable versioning
		if err := bm.SetBucketVersioning("ver-bucket", "Enabled"); err != nil {
			t.Fatalf("SetBucketVersioning(Enabled) failed: %v", err)
		}
		state, err = bm.GetBucketVersioning("ver-bucket")
		if err != nil {
			t.Fatalf("GetBucketVersioning failed: %v", err)
		}
		if state != "Enabled" {
			t.Errorf("versioning state = %q, want %q", state, "Enabled")
		}

		// Suspend versioning
		if err := bm.SetBucketVersioning("ver-bucket", "Suspended"); err != nil {
			t.Fatalf("SetBucketVersioning(Suspended) failed: %v", err)
		}
		state, err = bm.GetBucketVersioning("ver-bucket")
		if err != nil {
			t.Fatalf("GetBucketVersioning failed: %v", err)
		}
		if state != "Suspended" {
			t.Errorf("versioning state = %q, want %q", state, "Suspended")
		}
	})

	t.Run("SetBucketPolicy_GetBucketPolicy_DeleteBucketPolicy", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		bm := NewBucketManager(db)
		if err := bm.CreateBucket("policy-bucket", "owner1", "us-east-1"); err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}

		policy := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-bucket/*"}]}`)

		// Set policy
		if err := bm.SetBucketPolicy("policy-bucket", policy); err != nil {
			t.Fatalf("SetBucketPolicy failed: %v", err)
		}

		// Get policy
		retrieved, err := bm.GetBucketPolicy("policy-bucket")
		if err != nil {
			t.Fatalf("GetBucketPolicy failed: %v", err)
		}
		if !bytes.Equal(retrieved, policy) {
			t.Errorf("policy mismatch: got %s, want %s", retrieved, policy)
		}

		// Delete policy
		if err := bm.DeleteBucketPolicy("policy-bucket"); err != nil {
			t.Fatalf("DeleteBucketPolicy failed: %v", err)
		}

		// Get after delete should fail
		_, err = bm.GetBucketPolicy("policy-bucket")
		if err == nil {
			t.Error("GetBucketPolicy after delete should return error")
		}
	})

	t.Run("SetBucketEncryption_and_GetBucketEncryption", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		bm := NewBucketManager(db)
		if err := bm.CreateBucket("enc-bucket", "owner1", "us-east-1"); err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}

		enc := &BucketEncryption{
			SSEAlgorithm: "AES256",
		}

		if err := bm.SetBucketEncryption("enc-bucket", enc); err != nil {
			t.Fatalf("SetBucketEncryption failed: %v", err)
		}

		retrieved, err := bm.GetBucketEncryption("enc-bucket")
		if err != nil {
			t.Fatalf("GetBucketEncryption failed: %v", err)
		}
		if retrieved == nil {
			t.Fatal("GetBucketEncryption returned nil")
		}
		if retrieved.SSEAlgorithm != "AES256" {
			t.Errorf("SSEAlgorithm = %q, want %q", retrieved.SSEAlgorithm, "AES256")
		}
	})

	t.Run("SetBucketQuota_and_GetBucketQuota", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		bm := NewBucketManager(db)
		if err := bm.CreateBucket("quota-bucket", "owner1", "us-east-1"); err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}

		quota := &BucketQuota{
			MaxSizeBytes: 1024 * 1024 * 100, // 100MB
			MaxObjects:   1000,
		}

		if err := bm.SetBucketQuota("quota-bucket", quota); err != nil {
			t.Fatalf("SetBucketQuota failed: %v", err)
		}

		retrieved, err := bm.GetBucketQuota("quota-bucket")
		if err != nil {
			t.Fatalf("GetBucketQuota failed: %v", err)
		}
		if retrieved == nil {
			t.Fatal("GetBucketQuota returned nil")
		}
		if retrieved.MaxSizeBytes != 1024*1024*100 {
			t.Errorf("MaxSizeBytes = %d, want %d", retrieved.MaxSizeBytes, 1024*1024*100)
		}
		if retrieved.MaxObjects != 1000 {
			t.Errorf("MaxObjects = %d, want %d", retrieved.MaxObjects, 1000)
		}

		// Non-existent bucket quota returns nil
		noQuota, err := bm.GetBucketQuota("no-quota-bucket")
		if err != nil {
			t.Fatalf("GetBucketQuota for non-existent should not error: %v", err)
		}
		if noQuota != nil {
			t.Error("expected nil quota for bucket without quota set")
		}
	})
}

// ============================================================================
// 4. MultipartManager tests
// ============================================================================

func TestMultipartManager(t *testing.T) {
	t.Run("Full_multipart_upload_lifecycle", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		mm := NewMultipartManager(db)

		// Create multipart upload
		upload, err := mm.CreateMultipartUpload("test-bucket", "large-file.bin", "application/octet-stream", "user1", nil)
		if err != nil {
			t.Fatalf("CreateMultipartUpload failed: %v", err)
		}
		if upload.UploadID == "" {
			t.Error("UploadID should not be empty")
		}
		if upload.Bucket != "test-bucket" {
			t.Errorf("Bucket = %q, want %q", upload.Bucket, "test-bucket")
		}
		if upload.Key != "large-file.bin" {
			t.Errorf("Key = %q, want %q", upload.Key, "large-file.bin")
		}

		// Upload 3 parts
		partData := [][]byte{
			bytes.Repeat([]byte("A"), 1024),
			bytes.Repeat([]byte("B"), 1024),
			bytes.Repeat([]byte("C"), 512),
		}

		completeParts := make([]CompletePart, 3)
		for i, data := range partData {
			part, err := mm.UploadPart(upload.UploadID, i+1, bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatalf("UploadPart %d failed: %v", i+1, err)
			}
			if part.PartNumber != i+1 {
				t.Errorf("PartNumber = %d, want %d", part.PartNumber, i+1)
			}
			if part.ETag == "" {
				t.Errorf("Part %d ETag should not be empty", i+1)
			}
			if part.Size != int64(len(data)) {
				t.Errorf("Part %d Size = %d, want %d", i+1, part.Size, len(data))
			}
			completeParts[i] = CompletePart{
				PartNumber: i + 1,
				ETag:       part.ETag,
			}
		}

		// Complete upload
		meta, err := mm.CompleteMultipartUpload(upload.UploadID, completeParts)
		if err != nil {
			t.Fatalf("CompleteMultipartUpload failed: %v", err)
		}
		if meta == nil {
			t.Fatal("CompleteMultipartUpload returned nil metadata")
		}
		expectedSize := int64(1024 + 1024 + 512)
		if meta.Size != expectedSize {
			t.Errorf("Size = %d, want %d", meta.Size, expectedSize)
		}
		if meta.Hash == "" {
			t.Error("Hash should not be empty")
		}
		// Multipart ETag should contain dash
		if !strings.Contains(meta.Hash, "-") {
			t.Errorf("multipart ETag should contain dash, got %q", meta.Hash)
		}
	})

	t.Run("AbortMultipartUpload_cleans_up", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		mm := NewMultipartManager(db)

		upload, err := mm.CreateMultipartUpload("test-bucket", "abort-file.bin", "application/octet-stream", "user1", nil)
		if err != nil {
			t.Fatalf("CreateMultipartUpload failed: %v", err)
		}

		// Upload a part
		_, err = mm.UploadPart(upload.UploadID, 1, bytes.NewReader([]byte("data")), 4)
		if err != nil {
			t.Fatalf("UploadPart failed: %v", err)
		}

		// Abort
		if err := mm.AbortMultipartUpload(upload.UploadID); err != nil {
			t.Fatalf("AbortMultipartUpload failed: %v", err)
		}

		// Trying to upload to the aborted upload should fail
		_, err = mm.UploadPart(upload.UploadID, 2, bytes.NewReader([]byte("more")), 4)
		if err == nil {
			t.Error("UploadPart after abort should fail")
		}

		// Aborting again should fail (already cleaned up)
		err = mm.AbortMultipartUpload(upload.UploadID)
		if err == nil {
			t.Error("AbortMultipartUpload again should fail")
		}
	})

	t.Run("ListMultipartUploads_returns_active_uploads", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		mm := NewMultipartManager(db)

		// Create two uploads in the same bucket
		_, err = mm.CreateMultipartUpload("list-bucket", "file1.bin", "application/octet-stream", "user1", nil)
		if err != nil {
			t.Fatalf("CreateMultipartUpload failed: %v", err)
		}
		_, err = mm.CreateMultipartUpload("list-bucket", "file2.bin", "application/octet-stream", "user1", nil)
		if err != nil {
			t.Fatalf("CreateMultipartUpload failed: %v", err)
		}
		// Create one in a different bucket
		_, err = mm.CreateMultipartUpload("other-bucket", "file3.bin", "application/octet-stream", "user1", nil)
		if err != nil {
			t.Fatalf("CreateMultipartUpload failed: %v", err)
		}

		uploads, err := mm.ListMultipartUploads("list-bucket")
		if err != nil {
			t.Fatalf("ListMultipartUploads failed: %v", err)
		}
		if len(uploads) != 2 {
			t.Errorf("expected 2 uploads in list-bucket, got %d", len(uploads))
		}

		otherUploads, err := mm.ListMultipartUploads("other-bucket")
		if err != nil {
			t.Fatalf("ListMultipartUploads failed: %v", err)
		}
		if len(otherUploads) != 1 {
			t.Errorf("expected 1 upload in other-bucket, got %d", len(otherUploads))
		}
	})

	t.Run("ListParts_returns_uploaded_parts", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		mm := NewMultipartManager(db)

		upload, err := mm.CreateMultipartUpload("parts-bucket", "parts-file.bin", "application/octet-stream", "user1", nil)
		if err != nil {
			t.Fatalf("CreateMultipartUpload failed: %v", err)
		}

		// Upload 3 parts
		for i := 1; i <= 3; i++ {
			data := bytes.Repeat([]byte{byte(i)}, 100)
			_, err := mm.UploadPart(upload.UploadID, i, bytes.NewReader(data), 100)
			if err != nil {
				t.Fatalf("UploadPart %d failed: %v", i, err)
			}
		}

		parts, err := mm.ListParts(upload.UploadID)
		if err != nil {
			t.Fatalf("ListParts failed: %v", err)
		}
		if len(parts) != 3 {
			t.Errorf("expected 3 parts, got %d", len(parts))
		}

		// Verify parts are in order
		for i, part := range parts {
			if part.PartNumber != i+1 {
				t.Errorf("part[%d].PartNumber = %d, want %d", i, part.PartNumber, i+1)
			}
			if part.Size != 100 {
				t.Errorf("part[%d].Size = %d, want 100", i, part.Size)
			}
		}
	})

	t.Run("Invalid_part_numbers_rejected", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		mm := NewMultipartManager(db)

		upload, err := mm.CreateMultipartUpload("part-num-bucket", "file.bin", "application/octet-stream", "user1", nil)
		if err != nil {
			t.Fatalf("CreateMultipartUpload failed: %v", err)
		}

		// Part number 0 should be rejected
		_, err = mm.UploadPart(upload.UploadID, 0, bytes.NewReader([]byte("data")), 4)
		if err == nil {
			t.Error("UploadPart with part number 0 should fail")
		}

		// Negative part number
		_, err = mm.UploadPart(upload.UploadID, -1, bytes.NewReader([]byte("data")), 4)
		if err == nil {
			t.Error("UploadPart with negative part number should fail")
		}

		// Part number exceeding max
		_, err = mm.UploadPart(upload.UploadID, 10001, bytes.NewReader([]byte("data")), 4)
		if err == nil {
			t.Error("UploadPart with part number > 10000 should fail")
		}
	})

	t.Run("UploadPart_with_invalid_upload_ID_returns_NoSuchUpload", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		mm := NewMultipartManager(db)

		_, err = mm.UploadPart("nonexistent-upload-id", 1, bytes.NewReader([]byte("data")), 4)
		if err == nil {
			t.Error("UploadPart with invalid upload ID should fail")
		}
		if err != nil && !strings.Contains(err.Error(), "NoSuchUpload") {
			t.Errorf("error should contain NoSuchUpload, got: %v", err)
		}
	})
}

// ============================================================================
// 5. PresignedURLGenerator tests
// ============================================================================

func TestPresignedURLGenerator(t *testing.T) {
	// helper creates a DB, credential store, a credential, and a presigned URL generator
	setupPresigned := func(t *testing.T) (*DB, *S3CredentialStore, *S3Credential, *PresignedURLGenerator) {
		t.Helper()
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		store := NewS3CredentialStore(db)
		cred, err := store.GenerateCredentials("user1", "presign key")
		if err != nil {
			t.Fatalf("GenerateCredentials failed: %v", err)
		}
		pg := NewPresignedURLGenerator(store, "us-east-1", "http://localhost:8080")
		return db, store, cred, pg
	}

	t.Run("GeneratePresignedGetURL_creates_valid_URL_with_SigV4_params", func(t *testing.T) {
		db, _, cred, pg := setupPresigned(t)
		defer db.Close()

		rawURL, err := pg.GeneratePresignedGetURL(cred.AccessKeyID, "my-bucket", "my-key.txt", 15*time.Minute)
		if err != nil {
			t.Fatalf("GeneratePresignedGetURL failed: %v", err)
		}

		u, err := url.Parse(rawURL)
		if err != nil {
			t.Fatalf("invalid URL: %v", err)
		}

		query := u.Query()

		if query.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
			t.Errorf("X-Amz-Algorithm = %q, want AWS4-HMAC-SHA256", query.Get("X-Amz-Algorithm"))
		}

		credential := query.Get("X-Amz-Credential")
		if !strings.HasPrefix(credential, cred.AccessKeyID+"/") {
			t.Errorf("X-Amz-Credential should start with access key ID, got %q", credential)
		}
		if !strings.Contains(credential, "/us-east-1/s3/") {
			t.Errorf("X-Amz-Credential should contain region and service, got %q", credential)
		}

		if query.Get("X-Amz-Date") == "" {
			t.Error("X-Amz-Date should be present")
		}
		if query.Get("X-Amz-Expires") != "900" {
			t.Errorf("X-Amz-Expires = %q, want 900", query.Get("X-Amz-Expires"))
		}
		if query.Get("X-Amz-Signature") == "" {
			t.Error("X-Amz-Signature should be present")
		}
		if query.Get("X-Amz-SignedHeaders") == "" {
			t.Error("X-Amz-SignedHeaders should be present")
		}

		// Path should include bucket and key
		if !strings.Contains(u.Path, "my-bucket") {
			t.Errorf("path should contain bucket name, got %q", u.Path)
		}
		if !strings.Contains(u.Path, "my-key.txt") {
			t.Errorf("path should contain key, got %q", u.Path)
		}
	})

	t.Run("GeneratePresignedPutURL_with_content_type", func(t *testing.T) {
		db, _, cred, pg := setupPresigned(t)
		defer db.Close()

		rawURL, err := pg.GeneratePresignedPutURL(cred.AccessKeyID, "upload-bucket", "upload.json", "application/json", 1*time.Hour)
		if err != nil {
			t.Fatalf("GeneratePresignedPutURL failed: %v", err)
		}

		u, err := url.Parse(rawURL)
		if err != nil {
			t.Fatalf("invalid URL: %v", err)
		}

		query := u.Query()
		if query.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
			t.Errorf("X-Amz-Algorithm = %q, want AWS4-HMAC-SHA256", query.Get("X-Amz-Algorithm"))
		}
		if query.Get("X-Amz-Expires") != "3600" {
			t.Errorf("X-Amz-Expires = %q, want 3600", query.Get("X-Amz-Expires"))
		}

		// Signed headers should include content-type
		signedHeaders := query.Get("X-Amz-SignedHeaders")
		if !strings.Contains(signedHeaders, "content-type") {
			t.Errorf("SignedHeaders should include content-type, got %q", signedHeaders)
		}
	})

	t.Run("Expiration_exceeding_7_days_rejected", func(t *testing.T) {
		db, _, cred, pg := setupPresigned(t)
		defer db.Close()

		_, err := pg.GeneratePresignedGetURL(cred.AccessKeyID, "bucket", "key", 8*24*time.Hour)
		if err == nil {
			t.Error("expiration > 7 days should be rejected")
		}
		if err != nil && !strings.Contains(err.Error(), "7 days") {
			t.Errorf("error should mention 7 days, got: %v", err)
		}
	})

	t.Run("ValidatePresignedURL_extracts_bucket_and_key", func(t *testing.T) {
		db, _, cred, pg := setupPresigned(t)
		defer db.Close()

		rawURL, err := pg.GeneratePresignedGetURL(cred.AccessKeyID, "val-bucket", "path/to/object.txt", 15*time.Minute)
		if err != nil {
			t.Fatalf("GeneratePresignedGetURL failed: %v", err)
		}

		bucket, key, err := pg.ValidatePresignedURL(rawURL)
		if err != nil {
			t.Fatalf("ValidatePresignedURL failed: %v", err)
		}

		if bucket != "val-bucket" {
			t.Errorf("bucket = %q, want %q", bucket, "val-bucket")
		}
		if key != "path/to/object.txt" {
			t.Errorf("key = %q, want %q", key, "path/to/object.txt")
		}
	})
}

// ============================================================================
// 6. S3ObjectOps tests
// ============================================================================

func TestS3ObjectOps(t *testing.T) {
	t.Run("ParseRangeHeader_various_formats", func(t *testing.T) {
		objectSize := int64(1000)

		tests := []struct {
			name      string
			header    string
			wantStart int64
			wantEnd   int64
		}{
			{"bytes=0-499", "bytes=0-499", 0, 499},
			{"bytes=500-", "bytes=500-", 500, 999},
			{"bytes=-500", "bytes=-500", 500, 999},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				ranges, err := ParseRangeHeader(tc.header, objectSize)
				if err != nil {
					t.Fatalf("ParseRangeHeader(%q) failed: %v", tc.header, err)
				}
				if len(ranges) != 1 {
					t.Fatalf("expected 1 range, got %d", len(ranges))
				}
				if ranges[0].Start != tc.wantStart {
					t.Errorf("Start = %d, want %d", ranges[0].Start, tc.wantStart)
				}
				if ranges[0].End != tc.wantEnd {
					t.Errorf("End = %d, want %d", ranges[0].End, tc.wantEnd)
				}
			})
		}
	})

	t.Run("ParseRangeHeader_rejects_invalid_ranges", func(t *testing.T) {
		objectSize := int64(1000)

		invalidHeaders := []struct {
			name   string
			header string
		}{
			{"no bytes prefix", "items=0-499"},
			{"start > end", "bytes=500-100"},
			{"start beyond size", "bytes=2000-3000"},
		}

		for _, tc := range invalidHeaders {
			t.Run(tc.name, func(t *testing.T) {
				_, err := ParseRangeHeader(tc.header, objectSize)
				if err == nil {
					t.Errorf("ParseRangeHeader(%q) should return error", tc.header)
				}
			})
		}
	})

	t.Run("ParseRangeHeader_empty_returns_nil", func(t *testing.T) {
		ranges, err := ParseRangeHeader("", 1000)
		if err != nil {
			t.Fatalf("ParseRangeHeader(\"\") should not error: %v", err)
		}
		if ranges != nil {
			t.Error("empty range header should return nil")
		}
	})

	t.Run("GetObjectRange_returns_correct_slice", func(t *testing.T) {
		data := []byte("Hello, World! This is test data for range operations.")

		// First 5 bytes
		result := GetObjectRange(data, RangeSpec{Start: 0, End: 4})
		if string(result) != "Hello" {
			t.Errorf("GetObjectRange(0-4) = %q, want %q", result, "Hello")
		}

		// Middle portion
		result = GetObjectRange(data, RangeSpec{Start: 7, End: 11})
		if string(result) != "World" {
			t.Errorf("GetObjectRange(7-11) = %q, want %q", result, "World")
		}

		// Beyond data length is clamped
		result = GetObjectRange(data, RangeSpec{Start: 0, End: int64(len(data) + 100)})
		if string(result) != string(data) {
			t.Errorf("GetObjectRange beyond length should clamp to data length")
		}
	})

	t.Run("ComputeETag_returns_quoted_MD5", func(t *testing.T) {
		data := []byte("Hello, World!")
		etag := ComputeETag(data)

		// Should be quoted
		if !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) {
			t.Errorf("ETag should be quoted, got %q", etag)
		}

		// Verify MD5
		hash := md5.Sum(data)
		expectedMD5 := hex.EncodeToString(hash[:])
		expectedETag := fmt.Sprintf(`"%s"`, expectedMD5)
		if etag != expectedETag {
			t.Errorf("ETag = %q, want %q", etag, expectedETag)
		}
	})

	t.Run("ComputeMultipartETag_with_multiple_parts", func(t *testing.T) {
		// Compute individual part ETags
		part1 := []byte("part1data")
		part2 := []byte("part2data")
		part3 := []byte("part3data")

		etag1 := ComputeETag(part1)
		etag2 := ComputeETag(part2)
		etag3 := ComputeETag(part3)

		multipartETag := ComputeMultipartETag([]string{etag1, etag2, etag3})

		// Should be quoted
		if !strings.HasPrefix(multipartETag, `"`) || !strings.HasSuffix(multipartETag, `"`) {
			t.Errorf("multipart ETag should be quoted, got %q", multipartETag)
		}

		// Should contain -3 suffix (3 parts)
		if !strings.HasSuffix(multipartETag, `-3"`) {
			t.Errorf("multipart ETag should end with -3, got %q", multipartETag)
		}

		// Verify the computed value manually
		h1 := md5.Sum(part1)
		h2 := md5.Sum(part2)
		h3 := md5.Sum(part3)
		combined := append(h1[:], h2[:]...)
		combined = append(combined, h3[:]...)
		finalHash := md5.Sum(combined)
		expected := fmt.Sprintf(`"%s-3"`, hex.EncodeToString(finalHash[:]))
		if multipartETag != expected {
			t.Errorf("multipart ETag = %q, want %q", multipartETag, expected)
		}
	})

	t.Run("EvaluateConditions_IfMatch", func(t *testing.T) {
		etag := `"abc123"`
		lastMod := time.Now().Add(-1 * time.Hour)

		// Matching ETag
		ok, status := EvaluateConditions(ConditionalCheck{IfMatch: `"abc123"`}, etag, lastMod)
		if !ok {
			t.Error("IfMatch with matching ETag should succeed")
		}
		if status != 200 {
			t.Errorf("status = %d, want 200", status)
		}

		// Non-matching ETag
		ok, status = EvaluateConditions(ConditionalCheck{IfMatch: `"xyz789"`}, etag, lastMod)
		if ok {
			t.Error("IfMatch with non-matching ETag should fail")
		}
		if status != 412 {
			t.Errorf("status = %d, want 412", status)
		}

		// Wildcard
		ok, status = EvaluateConditions(ConditionalCheck{IfMatch: "*"}, etag, lastMod)
		if !ok {
			t.Error("IfMatch with * should succeed")
		}
		if status != 200 {
			t.Errorf("status = %d, want 200", status)
		}
	})

	t.Run("EvaluateConditions_IfNoneMatch", func(t *testing.T) {
		etag := `"abc123"`
		lastMod := time.Now().Add(-1 * time.Hour)

		// Matching ETag returns 304
		ok, status := EvaluateConditions(ConditionalCheck{IfNoneMatch: `"abc123"`}, etag, lastMod)
		if ok {
			t.Error("IfNoneMatch with matching ETag should fail")
		}
		if status != 304 {
			t.Errorf("status = %d, want 304", status)
		}

		// Non-matching ETag succeeds
		ok, status = EvaluateConditions(ConditionalCheck{IfNoneMatch: `"different"`}, etag, lastMod)
		if !ok {
			t.Error("IfNoneMatch with non-matching ETag should succeed")
		}
		if status != 200 {
			t.Errorf("status = %d, want 200", status)
		}

		// Wildcard returns 304
		ok, status = EvaluateConditions(ConditionalCheck{IfNoneMatch: "*"}, etag, lastMod)
		if ok {
			t.Error("IfNoneMatch with * should fail")
		}
		if status != 304 {
			t.Errorf("status = %d, want 304", status)
		}
	})

	t.Run("EvaluateConditions_IfModifiedSince", func(t *testing.T) {
		etag := `"abc123"`
		lastMod := time.Now().Add(-1 * time.Hour)

		// Modified after the given time
		twoBefore := time.Now().Add(-2 * time.Hour)
		ok, status := EvaluateConditions(ConditionalCheck{IfModifiedSince: &twoBefore}, etag, lastMod)
		if !ok {
			t.Error("IfModifiedSince with earlier date should succeed")
		}
		if status != 200 {
			t.Errorf("status = %d, want 200", status)
		}

		// Not modified since (object is older)
		future := time.Now().Add(1 * time.Hour)
		ok, status = EvaluateConditions(ConditionalCheck{IfModifiedSince: &future}, etag, lastMod)
		if ok {
			t.Error("IfModifiedSince with future date should fail")
		}
		if status != 304 {
			t.Errorf("status = %d, want 304", status)
		}
	})

	t.Run("EvaluateConditions_IfUnmodifiedSince", func(t *testing.T) {
		etag := `"abc123"`
		lastMod := time.Now().Add(-1 * time.Hour)

		// Object modified before the given time
		future := time.Now().Add(1 * time.Hour)
		ok, status := EvaluateConditions(ConditionalCheck{IfUnmodifiedSince: &future}, etag, lastMod)
		if !ok {
			t.Error("IfUnmodifiedSince with future date should succeed")
		}
		if status != 200 {
			t.Errorf("status = %d, want 200", status)
		}

		// Object modified after the given time
		twoBefore := time.Now().Add(-2 * time.Hour)
		ok, status = EvaluateConditions(ConditionalCheck{IfUnmodifiedSince: &twoBefore}, etag, lastMod)
		if ok {
			t.Error("IfUnmodifiedSince with earlier date should fail")
		}
		if status != 412 {
			t.Errorf("status = %d, want 412", status)
		}
	})

	t.Run("CopyObject_copies_data_and_metadata", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		srcData := []byte("source object data for copy test")
		opts := &ObjectOptions{
			CustomMetadata: map[string]string{"x-amz-meta-author": "test"},
			StorageClass:   "STANDARD",
		}

		_, err = db.StoreObject("src-bucket/src-key.txt", "text/plain", "user1", srcData, opts)
		if err != nil {
			t.Fatalf("StoreObject (source) failed: %v", err)
		}

		// Copy
		dstMeta, err := db.CopyObject("src-bucket", "src-key.txt", "dst-bucket", "dst-key.txt", "user1")
		if err != nil {
			t.Fatalf("CopyObject failed: %v", err)
		}

		if dstMeta.ContentType != "text/plain" {
			t.Errorf("ContentType = %q, want %q", dstMeta.ContentType, "text/plain")
		}
		if dstMeta.Size != int64(len(srcData)) {
			t.Errorf("Size = %d, want %d", dstMeta.Size, len(srcData))
		}

		// Verify destination data
		dstDataRetrieved, _, err := db.GetObject("dst-bucket/dst-key.txt", "user1")
		if err != nil {
			t.Fatalf("GetObject (dst) failed: %v", err)
		}
		if !bytes.Equal(dstDataRetrieved, srcData) {
			t.Errorf("copied data mismatch: got %d bytes, want %d bytes", len(dstDataRetrieved), len(srcData))
		}
	})

	t.Run("PutObjectTagging_GetObjectTagging_DeleteObjectTagging", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		// Store an object first
		_, err = db.StoreObject("tag-bucket/tagged.txt", "text/plain", "user1", []byte("tagged content"), nil)
		if err != nil {
			t.Fatalf("StoreObject failed: %v", err)
		}

		tags := map[string]string{
			"env":     "production",
			"project": "velocity",
			"team":    "backend",
		}

		// Put tags
		if err := db.PutObjectTagging("tag-bucket", "tagged.txt", tags); err != nil {
			t.Fatalf("PutObjectTagging failed: %v", err)
		}

		// Get tags
		retrieved, err := db.GetObjectTagging("tag-bucket", "tagged.txt")
		if err != nil {
			t.Fatalf("GetObjectTagging failed: %v", err)
		}
		if len(retrieved) != 3 {
			t.Errorf("expected 3 tags, got %d", len(retrieved))
		}
		if retrieved["env"] != "production" {
			t.Errorf("tag env = %q, want %q", retrieved["env"], "production")
		}
		if retrieved["project"] != "velocity" {
			t.Errorf("tag project = %q, want %q", retrieved["project"], "velocity")
		}

		// Delete tags
		if err := db.DeleteObjectTagging("tag-bucket", "tagged.txt"); err != nil {
			t.Fatalf("DeleteObjectTagging failed: %v", err)
		}

		// Tags should be empty after delete
		afterDelete, err := db.GetObjectTagging("tag-bucket", "tagged.txt")
		if err != nil {
			t.Fatalf("GetObjectTagging after delete failed: %v", err)
		}
		if len(afterDelete) != 0 {
			t.Errorf("expected 0 tags after delete, got %d", len(afterDelete))
		}
	})

	t.Run("Tag_limit_validation_max_10_tags", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		// 11 tags should fail
		tags := make(map[string]string)
		for i := 0; i < 11; i++ {
			tags[fmt.Sprintf("key%d", i)] = fmt.Sprintf("value%d", i)
		}

		err = db.PutObjectTagging("bucket", "key", tags)
		if err == nil {
			t.Error("PutObjectTagging with 11 tags should fail")
		}
		if err != nil && !strings.Contains(err.Error(), "too many tags") {
			t.Errorf("error should mention too many tags, got: %v", err)
		}
	})

	t.Run("Tag_limit_validation_key_length", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		longKey := strings.Repeat("k", 129) // 129 chars, exceeds 128 limit
		tags := map[string]string{
			longKey: "value",
		}

		err = db.PutObjectTagging("bucket", "key", tags)
		if err == nil {
			t.Error("PutObjectTagging with key > 128 chars should fail")
		}
		if err != nil && !strings.Contains(err.Error(), "tag key too long") {
			t.Errorf("error should mention tag key too long, got: %v", err)
		}
	})

	t.Run("Tag_limit_validation_value_length", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		longValue := strings.Repeat("v", 257) // 257 chars, exceeds 256 limit
		tags := map[string]string{
			"key": longValue,
		}

		err = db.PutObjectTagging("bucket", "key", tags)
		if err == nil {
			t.Error("PutObjectTagging with value > 256 chars should fail")
		}
		if err != nil && !strings.Contains(err.Error(), "tag value too long") {
			t.Errorf("error should mention tag value too long, got: %v", err)
		}
	})
}
