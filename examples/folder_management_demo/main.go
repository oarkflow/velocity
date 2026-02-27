//go:build velocity_examples
// +build velocity_examples

package main

import (
	"fmt"
	"log"

	"github.com/oarkflow/velocity"
)

func mai1n() {
	// Initialize database
	db, err := velocity.NewWithConfig(velocity.Config{
		Path: "./folder_demo_db",
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.UserDefined,
		},
		MaxUploadSize: 100 * 1024 * 1024,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	fmt.Println("=== Velocity DB Folder Management Demo ===")

	// Example 1: Create folders
	example1_CreateFolders(db)

	// Example 2: Store objects in folders
	example2_StoreObjectsInFolders(db)

	// Example 3: List folders
	example3_ListFolders(db)

	// Example 4: Get folder information
	example4_GetFolderInfo(db)

	// Example 5: Copy folders
	example5_CopyFolder(db)

	// Example 6: Rename/Move folders
	example6_RenameFolder(db)

	// Example 7: Delete folders
	example7_DeleteFolders(db)
}

func example1_CreateFolders(db *velocity.DB) {
	fmt.Println("Example 1: Create folder structures")
	fmt.Println("------------------------------------")

	// Create single folders
	folders := []string{
		"documents",
		"documents/reports",
		"documents/reports/2026",
		"documents/invoices",
		"images",
		"images/photos",
		"images/graphics",
		"projects",
		"projects/alpha",
		"projects/beta",
	}

	for _, folder := range folders {
		err := db.CreateFolder(folder, "admin")
		if err != nil && err != velocity.ErrObjectExists {
			log.Printf("✗ Error creating folder %s: %v\n", folder, err)
			continue
		}
		fmt.Printf("✓ Created folder: %s\n", folder)
	}

	// Create multiple folders at once
	fmt.Println("\nCreating batch folders...")
	batchFolders := []string{
		"data/raw",
		"data/processed",
		"data/archive",
	}
	err := db.CreateFolders(batchFolders, "admin")
	if err != nil {
		log.Printf("✗ Error creating batch folders: %v\n", err)
	} else {
		fmt.Printf("✓ Created %d folders in batch\n", len(batchFolders))
	}

	fmt.Println()
}

func example2_StoreObjectsInFolders(db *velocity.DB) {
	fmt.Println("Example 2: Store objects in folders")
	fmt.Println("------------------------------------")

	// Store objects in different folders
	objects := map[string]struct {
		content     string
		contentType string
	}{
		"documents/reports/2026/q1-report.pdf": {
			content:     "Q1 2026 Financial Report Content",
			contentType: "application/pdf",
		},
		"documents/reports/2026/q2-report.pdf": {
			content:     "Q2 2026 Financial Report Content",
			contentType: "application/pdf",
		},
		"documents/invoices/inv-001.pdf": {
			content:     "Invoice #001 Content",
			contentType: "application/pdf",
		},
		"images/photos/team.jpg": {
			content:     "Team photo data",
			contentType: "image/jpeg",
		},
		"images/graphics/logo.png": {
			content:     "Company logo data",
			contentType: "image/png",
		},
		"projects/alpha/README.md": {
			content:     "# Alpha Project\n\nProject documentation here.",
			contentType: "text/markdown",
		},
		"projects/beta/README.md": {
			content:     "# Beta Project\n\nProject documentation here.",
			contentType: "text/markdown",
		},
		"data/raw/dataset1.csv": {
			content:     "id,name,value\n1,test,100",
			contentType: "text/csv",
		},
	}

	for path, obj := range objects {
		opts := &velocity.ObjectOptions{
			Encrypt: true,
			Tags: map[string]string{
				"demo": "folder-management",
			},
		}

		meta, err := db.StoreObject(path, obj.contentType, "admin", []byte(obj.content), opts)
		if err != nil {
			log.Printf("✗ Error storing %s: %v\n", path, err)
			continue
		}
		fmt.Printf("✓ Stored: %s (%d bytes)\n", meta.Path, meta.Size)
	}

	fmt.Println()
}

func example3_ListFolders(db *velocity.DB) {
	fmt.Println("Example 3: List folders")
	fmt.Println("-----------------------")

	// List all folders
	fmt.Println("All folders:")
	allFolders, err := db.ListFolders("", false)
	if err != nil {
		log.Printf("✗ Error listing folders: %v\n", err)
		return
	}
	for _, folder := range allFolders {
		fmt.Printf("  - %s (created by: %s)\n", folder.Path, folder.CreatedBy)
	}

	// List folders under "documents" (non-recursive)
	fmt.Println("\nDirect children of 'documents' folder:")
	docFolders, err := db.ListFolders("documents", false)
	if err != nil {
		log.Printf("✗ Error listing folders: %v\n", err)
		return
	}
	for _, folder := range docFolders {
		fmt.Printf("  - %s\n", folder.Path)
	}

	// List folders under "documents" (recursive)
	fmt.Println("\nAll folders under 'documents' (recursive):")
	docFoldersRec, err := db.ListFolders("documents", true)
	if err != nil {
		log.Printf("✗ Error listing folders: %v\n", err)
		return
	}
	for _, folder := range docFoldersRec {
		fmt.Printf("  - %s\n", folder.Path)
	}

	fmt.Println()
}

func example4_GetFolderInfo(db *velocity.DB) {
	fmt.Println("Example 4: Get folder information")
	fmt.Println("----------------------------------")

	// Check if folder exists
	exists := db.FolderExists("documents/reports")
	fmt.Printf("Folder 'documents/reports' exists: %v\n", exists)

	// Get folder metadata
	folder, err := db.GetFolder("documents/reports")
	if err != nil {
		log.Printf("✗ Error getting folder: %v\n", err)
	} else {
		fmt.Printf("\nFolder metadata:")
		fmt.Printf("  Path: %s\n", folder.Path)
		fmt.Printf("  Name: %s\n", folder.Name)
		fmt.Printf("  Parent: %s\n", folder.Parent)
		fmt.Printf("  Created by: %s\n", folder.CreatedBy)
		fmt.Printf("  Created at: %s\n", folder.CreatedAt.Format("2006-01-02 15:04:05"))
	}

	// Get folder size
	size, count, err := db.GetFolderSize("documents/reports", true)
	if err != nil {
		log.Printf("✗ Error getting folder size: %v\n", err)
	} else {
		fmt.Printf("\nFolder size:")
		fmt.Printf("  Total size: %d bytes\n", size)
		fmt.Printf("  Object count: %d\n", count)
	}

	// List objects in folder
	fmt.Println("\nObjects in 'documents/reports' (recursive):")
	opts := velocity.ObjectListOptions{
		Folder:    "documents/reports",
		Recursive: true,
		MaxKeys:   100,
	}
	objects, err := db.ListObjects(opts)
	if err != nil {
		log.Printf("✗ Error listing objects: %v\n", err)
	} else {
		for _, obj := range objects {
			fmt.Printf("  - %s (%d bytes)\n", obj.Path, obj.Size)
		}
	}

	fmt.Println()
}

func example5_CopyFolder(db *velocity.DB) {
	fmt.Println("Example 5: Copy folders")
	fmt.Println("-----------------------")

	// Copy folder
	err := db.CopyFolder("projects/alpha", "projects/alpha-backup", "admin")
	if err != nil {
		log.Printf("✗ Error copying folder: %v\n", err)
		return
	}
	fmt.Println("✓ Copied 'projects/alpha' to 'projects/alpha-backup'")

	// Verify the copy
	size, count, err := db.GetFolderSize("projects/alpha-backup", true)
	if err != nil {
		log.Printf("✗ Error getting backup folder size: %v\n", err)
	} else {
		fmt.Printf("  Backup folder contains %d objects (%d bytes)\n", count, size)
	}

	fmt.Println()
}

func example6_RenameFolder(db *velocity.DB) {
	fmt.Println("Example 6: Rename/Move folders")
	fmt.Println("-------------------------------")

	// Rename folder
	err := db.RenameFolder("projects/beta", "projects/beta-v2", "admin")
	if err != nil {
		log.Printf("✗ Error renaming folder: %v\n", err)
		return
	}
	fmt.Println("✓ Renamed 'projects/beta' to 'projects/beta-v2'")

	// Verify old folder is gone
	exists := db.FolderExists("projects/beta")
	fmt.Printf("  Old folder exists: %v\n", exists)

	// Verify new folder exists
	exists = db.FolderExists("projects/beta-v2")
	fmt.Printf("  New folder exists: %v\n", exists)

	// Check objects were moved
	opts := velocity.ObjectListOptions{
		Folder:    "projects/beta-v2",
		Recursive: true,
		MaxKeys:   100,
	}
	objects, err := db.ListObjects(opts)
	if err != nil {
		log.Printf("✗ Error listing objects: %v\n", err)
	} else {
		fmt.Printf("  Objects in new folder: %d\n", len(objects))
	}

	fmt.Println()
}

func example7_DeleteFolders(db *velocity.DB) {
	fmt.Println("Example 7: Delete folders")
	fmt.Println("-------------------------")

	// Try to delete non-empty folder (should fail with regular delete)
	err := db.DeleteFolder("documents/reports", "admin")
	if err == velocity.ErrFolderNotEmpty {
		fmt.Println("✓ Cannot delete non-empty folder with DeleteFolder()")
	} else {
		fmt.Printf("✗ Unexpected result: %v\n", err)
	}

	// Delete folder recursively (deletes all contents)
	err = db.DeleteFolderRecursive("projects/alpha-backup", "admin")
	if err != nil {
		log.Printf("✗ Error deleting folder recursively: %v\n", err)
	} else {
		fmt.Println("✓ Deleted 'projects/alpha-backup' and all its contents")
	}

	// Verify folder is gone
	exists := db.FolderExists("projects/alpha-backup")
	fmt.Printf("  Folder exists after delete: %v\n", exists)

	// Delete empty folder
	err = db.CreateFolder("temp/empty-folder", "admin")
	if err != nil {
		log.Printf("✗ Error creating temp folder: %v\n", err)
	} else {
		err = db.DeleteFolder("temp/empty-folder", "admin")
		if err != nil {
			log.Printf("✗ Error deleting empty folder: %v\n", err)
		} else {
			fmt.Println("✓ Deleted empty folder 'temp/empty-folder'")
		}
	}

	fmt.Println()
}
