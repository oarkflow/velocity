package main

import (
	"fmt"
	"log"
	"time"

	"github.com/oarkflow/velocity"
)

func main() {
	// Initialize database with encryption
	db, err := velocity.NewWithConfig(velocity.Config{
		Path:          "./velocitydb_data",
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.UserDefined,
		},
		MaxUploadSize: 100 * 1024 * 1024,
	})
	if err != nil {
		log.Fatal(err)
	}
	// defer db.Close() // CRITICAL: Always close the database to flush data to disk

	fmt.Println("=== Velocity DB Object Storage Example ===")

	// Example 1: Store a simple object
	example1_StoreObject(db)
	// Retrieve the object
	retrieved, _, err := db.GetObject("documents/hello.txt", "user1")
	if err != nil {
		log.Printf("Error retrieving object: %v\n", err)
		return
	}
	fmt.Printf("✓ Retrieved: %s\n\n", string(retrieved))
	time.Sleep(10*time.Second)
	return

	// Example 2: Create nested folders and organize files
	example2_FolderStructure(db)

	// Example 3: Access control and permissions
	example3_AccessControl(db)

	// Example 4: Object versioning
	example4_Versioning(db)

	// Example 5: List and search objects
	example5_ListObjects(db)

	// Example 6: Metadata and tags
	example6_MetadataAndTags(db)

	// Example 7: Public vs Private objects
	example7_PublicPrivate(db)
}

func example1_StoreObject(db *velocity.DB) {
	fmt.Println("Example 1: Store a simple object")
	fmt.Println("-----------------------------------")

	data := []byte("Hello, Velocity Object Storage!")
	opts := &velocity.ObjectOptions{
		Version: "v1",
		Encrypt: true,
	}

	meta, err := db.StoreObject("documents/hello.txt", "text/plain", "user1", data, opts)
	if err != nil {
		log.Printf("Error storing object: %v\n", err)
		return
	}

	fmt.Printf("✓ Stored object: %s\n", meta.Path)
	fmt.Printf("  - Object ID: %s\n", meta.ObjectID)
	fmt.Printf("  - Version ID: %s\n", meta.VersionID)
	fmt.Printf("  - Size: %d bytes\n", meta.Size)
	fmt.Printf("  - Encrypted: %v\n", meta.Encrypted)
	fmt.Printf("  - Hash: %s\n", meta.Hash[:16]+"...")

	// Retrieve the object
	retrieved, _, err := db.GetObject("documents/hello.txt", "user1")
	if err != nil {
		log.Printf("Error retrieving object: %v\n", err)
		return
	}
	fmt.Printf("✓ Retrieved: %s\n\n", string(retrieved))
}

func example2_FolderStructure(db *velocity.DB) {
	fmt.Println("Example 2: Create nested folders and organize files")
	fmt.Println("----------------------------------------------------")

	// Create nested folder structure
	folders := []string{
		"projects/alpha/src",
		"projects/alpha/docs",
		"projects/beta/src",
		"projects/beta/docs",
	}

	for _, folder := range folders {
		err := db.CreateFolder(folder, "user1")
		if err != nil && err != velocity.ErrObjectExists {
			log.Printf("Error creating folder %s: %v\n", folder, err)
			continue
		}
		fmt.Printf("✓ Created folder: %s\n", folder)
	}

	// Store files in different folders
	files := map[string]string{
		"projects/alpha/README.md":    "# Alpha Project\n\nThis is the alpha project.",
		"projects/alpha/src/main.go":  "package main\n\nfunc main() {\n\tprintln(\"Alpha\")\n}",
		"projects/beta/README.md":     "# Beta Project\n\nThis is the beta project.",
		"projects/beta/src/main.go":   "package main\n\nfunc main() {\n\tprintln(\"Beta\")\n}",
	}

	for path, content := range files {
		opts := &velocity.ObjectOptions{Encrypt: true}
		_, err := db.StoreObject(path, "text/plain", "user1", []byte(content), opts)
		if err != nil {
			log.Printf("Error storing %s: %v\n", path, err)
			continue
		}
		fmt.Printf("✓ Stored: %s\n", path)
	}
	fmt.Println()
}

func example3_AccessControl(db *velocity.DB) {
	fmt.Println("Example 3: Access control and permissions")
	fmt.Println("------------------------------------------")

	// Create a private document with specific permissions
	secretData := []byte("This is confidential information!")
	opts := &velocity.ObjectOptions{
		Encrypt: true,
		ACL: &velocity.ObjectACL{
			Owner: "user1",
			Permissions: map[string][]string{
				"user1": {velocity.PermissionFull},
				"user2": {velocity.PermissionRead},
			},
			Public: false,
		},
	}

	_, err := db.StoreObject("private/secret.txt", "text/plain", "user1", secretData, opts)
	if err != nil {
		log.Printf("Error storing secret: %v\n", err)
		return
	}
	fmt.Println("✓ Stored private object with ACL")

	// user1 (owner) can read
	_, _, err = db.GetObject("private/secret.txt", "user1")
	if err != nil {
		fmt.Printf("✗ user1 access denied (unexpected): %v\n", err)
	} else {
		fmt.Println("✓ user1 (owner) can read")
	}

	// user2 can read (has permission)
	_, _, err = db.GetObject("private/secret.txt", "user2")
	if err != nil {
		fmt.Printf("✗ user2 access denied (unexpected): %v\n", err)
	} else {
		fmt.Println("✓ user2 can read (granted permission)")
	}

	// user3 cannot read (no permission)
	_, _, err = db.GetObject("private/secret.txt", "user3")
	if err == velocity.ErrAccessDenied {
		fmt.Println("✓ user3 denied access (no permission)")
	} else {
		fmt.Printf("✗ user3 should be denied: %v\n", err)
	}

	// user2 cannot delete (no delete permission)
	err = db.DeleteObject("private/secret.txt", "user2")
	if err == velocity.ErrAccessDenied {
		fmt.Println("✓ user2 cannot delete (lacks permission)")
	} else {
		fmt.Printf("✗ user2 should not be able to delete: %v\n", err)
	}
	fmt.Println()
}

func example4_Versioning(db *velocity.DB) {
	fmt.Println("Example 4: Object versioning")
	fmt.Println("-----------------------------")

	// Store version 1
	v1 := []byte("Version 1 content")
	meta1, err := db.StoreObject("docs/versioned.txt", "text/plain", "user1", v1, &velocity.ObjectOptions{
		Version: "v1",
		Encrypt: true,
	})
	if err != nil {
		log.Printf("Error storing v1: %v\n", err)
		return
	}
	fmt.Printf("✓ Stored version 1 (version ID: %s)\n", meta1.VersionID[:12]+"...")

	// Store version 2 (same path)
	v2 := []byte("Version 2 content - updated!")
	meta2, err := db.StoreObject("docs/versioned.txt", "text/plain", "user1", v2, &velocity.ObjectOptions{
		Version: "v2",
		Encrypt: true,
	})
	if err != nil {
		log.Printf("Error storing v2: %v\n", err)
		return
	}
	fmt.Printf("✓ Stored version 2 (version ID: %s)\n", meta2.VersionID[:12]+"...")

	// Retrieve latest version
	latest, meta, err := db.GetObject("docs/versioned.txt", "user1")
	if err != nil {
		log.Printf("Error retrieving latest: %v\n", err)
		return
	}
	fmt.Printf("✓ Latest version: %s (version %s)\n", string(latest), meta.Version)
	fmt.Printf("  Version ID: %s\n", meta.VersionID[:12]+"...")
	fmt.Println()
}

func example5_ListObjects(db *velocity.DB) {
	fmt.Println("Example 5: List and search objects")
	fmt.Println("-----------------------------------")

	// List all objects in projects/alpha
	opts := velocity.ObjectListOptions{
		Prefix:    "projects/alpha/",
		Recursive: true,
		MaxKeys:   100,
	}
	objects, err := db.ListObjects(opts)
	if err != nil {
		log.Printf("Error listing objects: %v\n", err)
		return
	}

	fmt.Printf("Found %d objects in projects/alpha/:\n", len(objects))
	for _, obj := range objects {
		fmt.Printf("  - %s (%d bytes, %s)\n", obj.Path, obj.Size, obj.ContentType)
	}

	// List objects in a specific folder (non-recursive)
	opts2 := velocity.ObjectListOptions{
		Folder:    "projects",
		Recursive: false,
		MaxKeys:   100,
	}
	objects2, err := db.ListObjects(opts2)
	if err != nil {
		log.Printf("Error listing folder: %v\n", err)
		return
	}

	fmt.Printf("\nDirect children of projects/ folder:\n")
	for _, obj := range objects2 {
		fmt.Printf("  - %s\n", obj.Name)
	}
	fmt.Println()
}

func example6_MetadataAndTags(db *velocity.DB) {
	fmt.Println("Example 6: Metadata and tags")
	fmt.Println("-----------------------------")

	data := []byte("Important document with metadata")
	opts := &velocity.ObjectOptions{
		Encrypt: true,
		Tags: map[string]string{
			"department": "engineering",
			"priority":   "high",
			"status":     "draft",
		},
		CustomMetadata: map[string]string{
			"author":      "John Doe",
			"reviewer":    "Jane Smith",
			"description": "System architecture document",
		},
	}

	meta, err := db.StoreObject("docs/architecture.md", "text/markdown", "user1", data, opts)
	if err != nil {
		log.Printf("Error storing object: %v\n", err)
		return
	}

	fmt.Println("✓ Stored object with metadata:")
	fmt.Println("  Tags:")
	for k, v := range meta.Tags {
		fmt.Printf("    %s: %s\n", k, v)
	}
	fmt.Println("  Custom Metadata:")
	for k, v := range meta.CustomMetadata {
		fmt.Printf("    %s: %s\n", k, v)
	}
	fmt.Println()
}

func example7_PublicPrivate(db *velocity.DB) {
	fmt.Println("Example 7: Public vs Private objects")
	fmt.Println("-------------------------------------")

	// Store a public object
	publicData := []byte("This is public information")
	publicOpts := &velocity.ObjectOptions{
		Encrypt: false, // Public data doesn't need encryption
		ACL: &velocity.ObjectACL{
			Owner:  "user1",
			Public: true,
		},
	}

	_, err := db.StoreObject("public/announcement.txt", "text/plain", "user1", publicData, publicOpts)
	if err != nil {
		log.Printf("Error storing public object: %v\n", err)
		return
	}
	fmt.Println("✓ Stored public object")

	// Anyone can read public objects
	_, _, err = db.GetObject("public/announcement.txt", "anonymous")
	if err != nil {
		fmt.Printf("✗ Anonymous access denied (unexpected): %v\n", err)
	} else {
		fmt.Println("✓ Anonymous user can read public object")
	}

	// Store a private object
	privateData := []byte("This is private information")
	privateOpts := &velocity.ObjectOptions{
		Encrypt: true,
		ACL: &velocity.ObjectACL{
			Owner: "user1",
			Permissions: map[string][]string{
				"user1": {velocity.PermissionFull},
			},
			Public: false,
		},
	}

	_, err = db.StoreObject("private/personal.txt", "text/plain", "user1", privateData, privateOpts)
	if err != nil {
		log.Printf("Error storing private object: %v\n", err)
		return
	}
	fmt.Println("✓ Stored private object")

	// Anonymous cannot read private objects
	_, _, err = db.GetObject("private/personal.txt", "anonymous")
	if err == velocity.ErrAccessDenied {
		fmt.Println("✓ Anonymous user denied access to private object")
	} else {
		fmt.Printf("✗ Anonymous should be denied: %v\n", err)
	}
	fmt.Println()
}
