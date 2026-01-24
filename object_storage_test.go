package velocity

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestObjectStorage(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "velocity-object-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create DB with encryption
	db, err := NewWithConfig(Config{
		Path:          tmpDir,
		EncryptionKey: make([]byte, 32), // Use zeros for test
		MaxUploadSize: 10 * 1024 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	t.Run("StoreAndRetrieveObject", func(t *testing.T) {
		testData := []byte("Hello, Object Storage!")
		opts := &ObjectOptions{
			Version: "v1",
			Encrypt: true,
			Tags:    map[string]string{"env": "test"},
		}

		meta, err := db.StoreObject("test/file.txt", "text/plain", "user1", testData, opts)
		if err != nil {
			t.Fatal(err)
		}

		if meta.Path != "test/file.txt" {
			t.Errorf("Expected path 'test/file.txt', got %s", meta.Path)
		}
		if meta.Folder != "test" {
			t.Errorf("Expected folder 'test', got %s", meta.Folder)
		}
		if meta.Name != "file.txt" {
			t.Errorf("Expected name 'file.txt', got %s", meta.Name)
		}
		if !meta.Encrypted {
			t.Error("Expected object to be encrypted")
		}

		// Retrieve object
		data, retrievedMeta, err := db.GetObject("test/file.txt", "user1")
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(data, testData) {
			t.Errorf("Retrieved data doesn't match original")
		}
		if retrievedMeta.ObjectID != meta.ObjectID {
			t.Errorf("Metadata ObjectID mismatch")
		}
	})

	t.Run("FolderOperations", func(t *testing.T) {
		// Create nested folder structure
		err := db.CreateFolder("documents/reports/2025", "user1")
		if err != nil {
			t.Fatal(err)
		}

		// Store file in nested folder
		testData := []byte("Report content")
		_, err = db.StoreObject("documents/reports/2025/Q1.pdf", "application/pdf", "user1", testData, &ObjectOptions{
			Encrypt: true,
		})
		if err != nil {
			t.Fatal(err)
		}

		// List objects in folder
		objects, err := db.ListObjects(ObjectListOptions{
			Folder:    "documents/reports/2025",
			Recursive: false,
		})
		if err != nil {
			t.Fatal(err)
		}

		if len(objects) != 1 {
			t.Errorf("Expected 1 object, got %d", len(objects))
		}
		if objects[0].Name != "Q1.pdf" {
			t.Errorf("Expected Q1.pdf, got %s", objects[0].Name)
		}
	})

	t.Run("AccessControl", func(t *testing.T) {
		testData := []byte("Private document")
		opts := &ObjectOptions{
			Encrypt: true,
			ACL: &ObjectACL{
				Owner: "user1",
				Permissions: map[string][]string{
					"user1": {PermissionFull},
					"user2": {PermissionRead},
				},
				Public: false,
			},
		}

		_, err := db.StoreObject("private/secret.txt", "text/plain", "user1", testData, opts)
		if err != nil {
			t.Fatal(err)
		}

		// user1 (owner) should be able to read
		_, _, err = db.GetObject("private/secret.txt", "user1")
		if err != nil {
			t.Error("Owner should be able to read:", err)
		}

		// user2 has read permission
		_, _, err = db.GetObject("private/secret.txt", "user2")
		if err != nil {
			t.Error("User2 should have read permission:", err)
		}

		// user3 has no permission
		_, _, err = db.GetObject("private/secret.txt", "user3")
		if err != ErrAccessDenied {
			t.Error("User3 should be denied access")
		}

		// user2 cannot delete (no delete permission)
		err = db.DeleteObject("private/secret.txt", "user2")
		if err != ErrAccessDenied {
			t.Error("User2 should not be able to delete")
		}

		// user1 can delete
		err = db.DeleteObject("private/secret.txt", "user1")
		if err != nil {
			t.Error("Owner should be able to delete:", err)
		}
	})

	t.Run("Versioning", func(t *testing.T) {
		// Store version 1
		v1Data := []byte("Version 1")
		meta1, err := db.StoreObject("versioned/doc.txt", "text/plain", "user1", v1Data, &ObjectOptions{
			Version: "v1",
			Encrypt: true,
		})
		if err != nil {
			t.Fatal(err)
		}

		time.Sleep(10 * time.Millisecond) // Ensure different timestamp

		// Store version 2
		v2Data := []byte("Version 2 - Updated")
		meta2, err := db.StoreObject("versioned/doc.txt", "text/plain", "user1", v2Data, &ObjectOptions{
			Version: "v2",
			Encrypt: true,
		})
		if err != nil {
			t.Fatal(err)
		}

		// Latest version should be v2
		data, meta, err := db.GetObject("versioned/doc.txt", "user1")
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(data, v2Data) {
			t.Error("Should retrieve latest version (v2)")
		}
		if meta.Version != "v2" {
			t.Errorf("Expected version v2, got %s", meta.Version)
		}
		if meta.VersionID == meta1.VersionID {
			t.Error("Version IDs should be different")
		}
		if meta2.VersionID != meta.VersionID {
			t.Error("Should match latest version ID")
		}
	})

	t.Run("ListObjectsWithPrefix", func(t *testing.T) {
		// Create multiple objects
		testFiles := []struct {
			path string
			data string
		}{
			{"projects/alpha/readme.md", "Alpha project"},
			{"projects/alpha/src/main.go", "Main code"},
			{"projects/beta/readme.md", "Beta project"},
			{"projects/gamma/readme.md", "Gamma project"},
		}

		for _, tf := range testFiles {
			_, err := db.StoreObject(tf.path, "text/plain", "user1", []byte(tf.data), &ObjectOptions{
				Encrypt: true,
			})
			if err != nil {
				t.Fatal(err)
			}
		}

		// List all projects
		objects, err := db.ListObjects(ObjectListOptions{
			Prefix:    "projects/",
			Recursive: true,
		})
		if err != nil {
			t.Fatal(err)
		}

		if len(objects) != 4 {
			t.Errorf("Expected 4 objects, got %d", len(objects))
		}

		// List only alpha project
		alphaObjects, err := db.ListObjects(ObjectListOptions{
			Prefix:    "projects/alpha/",
			Recursive: true,
		})
		if err != nil {
			t.Fatal(err)
		}

		if len(alphaObjects) != 2 {
			t.Errorf("Expected 2 objects in alpha, got %d", len(alphaObjects))
		}
	})

	t.Run("DeleteAndHardDelete", func(t *testing.T) {
		testData := []byte("To be deleted")
		_, err := db.StoreObject("temp/delete-me.txt", "text/plain", "user1", testData, &ObjectOptions{
			Encrypt: true,
		})
		if err != nil {
			t.Fatal(err)
		}

		// Soft delete
		err = db.DeleteObject("temp/delete-me.txt", "user1")
		if err != nil {
			t.Fatal(err)
		}

		// Object should not be accessible after soft delete
		_, _, err = db.GetObject("temp/delete-me.txt", "user1")
		if err == nil {
			t.Error("Object should not be accessible after soft delete")
		}

		// Hard delete
		err = db.HardDeleteObject("temp/delete-me.txt", "user1")
		if err != nil {
			t.Fatal(err)
		}

		// Metadata should be gone
		_, err = db.GetObjectMetadata("temp/delete-me.txt")
		if err != ErrObjectNotFound {
			t.Error("Object metadata should be gone after hard delete")
		}
	})

	t.Run("PublicAccess", func(t *testing.T) {
		testData := []byte("Public document")
		opts := &ObjectOptions{
			Encrypt: true,
			ACL: &ObjectACL{
				Owner:       "user1",
				Permissions: map[string][]string{"user1": {PermissionFull}},
				Public:      true,
			},
		}

		_, err := db.StoreObject("public/announcement.txt", "text/plain", "user1", testData, opts)
		if err != nil {
			t.Fatal(err)
		}

		// Anyone should be able to read public objects
		_, _, err = db.GetObject("public/announcement.txt", "anonymous")
		if err != nil {
			t.Error("Public object should be readable by anyone:", err)
		}

		// But not delete
		err = db.DeleteObject("public/announcement.txt", "anonymous")
		if err != ErrAccessDenied {
			t.Error("Anonymous user should not be able to delete")
		}
	})

	t.Run("CustomMetadata", func(t *testing.T) {
		testData := []byte("Document with metadata")
		opts := &ObjectOptions{
			Encrypt: true,
			Tags: map[string]string{
				"department": "engineering",
				"priority":   "high",
			},
			CustomMetadata: map[string]string{
				"author":      "John Doe",
				"description": "Important document",
			},
		}

		meta, err := db.StoreObject("docs/important.txt", "text/plain", "user1", testData, opts)
		if err != nil {
			t.Fatal(err)
		}

		if meta.Tags["department"] != "engineering" {
			t.Error("Tag not stored correctly")
		}
		if meta.CustomMetadata["author"] != "John Doe" {
			t.Error("Custom metadata not stored correctly")
		}

		// Retrieve and verify
		retrievedMeta, err := db.GetObjectMetadata("docs/important.txt")
		if err != nil {
			t.Fatal(err)
		}

		if retrievedMeta.Tags["priority"] != "high" {
			t.Error("Tag not retrieved correctly")
		}
		if retrievedMeta.CustomMetadata["description"] != "Important document" {
			t.Error("Custom metadata not retrieved correctly")
		}
	})

	t.Run("LargeObject", func(t *testing.T) {
		// Create a 1MB object
		largeData := make([]byte, 1024*1024)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		meta, err := db.StoreObject("large/bigfile.bin", "application/octet-stream", "user1", largeData, &ObjectOptions{
			Encrypt:         true,
			SystemOperation: true,
		})
		if err != nil {
			t.Fatal(err)
		}

		if meta.Size != int64(len(largeData)) {
			t.Errorf("Size mismatch: expected %d, got %d", len(largeData), meta.Size)
		}

		// Retrieve and verify (use internal API since this is system test)
		retrieved, _, err := db.GetObjectInternal("large/bigfile.bin", "test_service")
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(retrieved, largeData) {
			t.Error("Large object data mismatch")
		}
	})

	t.Run("PathNormalization", func(t *testing.T) {
		testData := []byte("Test")

		// Store with various path formats
		_, err := db.StoreObject("/leading/slash.txt", "text/plain", "user1", testData, &ObjectOptions{
			Encrypt: true,
		})
		if err != nil {
			t.Fatal(err)
		}

		// Should be normalized
		meta, err := db.GetObjectMetadata("leading/slash.txt")
		if err != nil {
			t.Fatal(err)
		}
		if meta.Path != "leading/slash.txt" {
			t.Errorf("Path not normalized: %s", meta.Path)
		}
	})

	t.Run("InvalidPaths", func(t *testing.T) {
		testData := []byte("Test")

		// Path with ..
		_, err := db.StoreObject("../escape/file.txt", "text/plain", "user1", testData, &ObjectOptions{})
		if err != ErrInvalidPath {
			t.Error("Should reject path with ..")
		}

		// Empty path
		_, err = db.StoreObject("", "text/plain", "user1", testData, &ObjectOptions{})
		if err != ErrInvalidPath {
			t.Error("Should reject empty path")
		}
	})

	t.Run("StorageWithoutEncryption", func(t *testing.T) {
		testData := []byte("Unencrypted data")
		opts := &ObjectOptions{
			Version: "v1",
			Encrypt: false, // No encryption
		}

		meta, err := db.StoreObject("plain/file.txt", "text/plain", "user1", testData, opts)
		if err != nil {
			t.Fatal(err)
		}

		if meta.Encrypted {
			t.Error("Object should not be encrypted")
		}

		// Retrieve and verify
		data, _, err := db.GetObject("plain/file.txt", "user1")
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(data, testData) {
			t.Error("Unencrypted data mismatch")
		}
	})
}

func TestFolderManagement(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "velocity-folder-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, err := NewWithConfig(Config{
		Path:          tmpDir,
		EncryptionKey: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	t.Run("CreateNestedFolders", func(t *testing.T) {
		err := db.CreateFolder("a/b/c/d", "user1")
		if err != nil {
			t.Fatal(err)
		}

		// Verify all parent folders were created
		folders := []string{"a", "a/b", "a/b/c", "a/b/c/d"}
		for _, folder := range folders {
			key := []byte(ObjectFolderPrefix + folder)
			if !db.Has(key) {
				t.Errorf("Folder %s was not created", folder)
			}
		}
	})

	t.Run("DeleteEmptyFolder", func(t *testing.T) {
		err := db.CreateFolder("empty/folder", "user1")
		if err != nil {
			t.Fatal(err)
		}

		err = db.DeleteFolder("empty/folder", "user1")
		if err != nil {
			t.Fatal(err)
		}

		key := []byte(ObjectFolderPrefix + "empty/folder")
		if db.Has(key) {
			t.Error("Folder should be deleted")
		}
	})

	t.Run("CannotDeleteNonEmptyFolder", func(t *testing.T) {
		// Create folder and add file
		err := db.CreateFolder("nonempty", "user1")
		if err != nil {
			t.Fatal(err)
		}

		_, err = db.StoreObject("nonempty/file.txt", "text/plain", "user1", []byte("data"), &ObjectOptions{
			Encrypt: true,
		})
		if err != nil {
			t.Fatal(err)
		}

		// Try to delete folder
		err = db.DeleteFolder("nonempty", "user1")
		if err != ErrFolderNotEmpty {
			t.Error("Should not be able to delete non-empty folder")
		}
	})
}

func BenchmarkObjectStorage(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "velocity-bench-*")
	defer os.RemoveAll(tmpDir)

	db, _ := NewWithConfig(Config{
		Path:          tmpDir,
		EncryptionKey: make([]byte, 32),
		MaxUploadSize: 100 * 1024 * 1024,
	})
	defer db.Close()

	testData := make([]byte, 1024) // 1KB
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	b.Run("StoreObject", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			path := filepath.Join("bench", "store", fmt.Sprintf("file-%d.bin", i))
			_, _ = db.StoreObject(path, "application/octet-stream", "user1", testData, &ObjectOptions{
				Encrypt: true,
			})
		}
	})

	// Store some objects for retrieval benchmark
	for i := 0; i < 100; i++ {
		path := filepath.Join("bench", "retrieve", fmt.Sprintf("file-%d.bin", i))
		db.StoreObject(path, "application/octet-stream", "user1", testData, &ObjectOptions{
			Encrypt: true,
		})
	}

	b.Run("GetObject", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			path := filepath.Join("bench", "retrieve", fmt.Sprintf("file-%d.bin", i%100))
			_, _, _ = db.GetObject(path, "user1")
		}
	})

	b.Run("ListObjects", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = db.ListObjects(ObjectListOptions{
				Prefix:  "bench/",
				MaxKeys: 100,
			})
		}
	})
}
