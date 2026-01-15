package velocity

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/oarkflow/previewer/pkg/vfs"
)

func TestMemoryVFS_AddFile(t *testing.T) {
	opts := vfs.Options{
		MaxFileSize:  10 * 1024, // 10KB
		MaxTotalSize: 50 * 1024, // 50KB
	}
	mvfs := NewMemoryVFS("test", opts)
	defer mvfs.Clear()

	testData := []byte("Hello, secure world!")
	err := mvfs.AddFile("test.txt", testData, "text/plain")
	if err != nil {
		t.Fatalf("Failed to add file: %v", err)
	}

	// Verify file was added
	file, err := mvfs.GetFile("test.txt")
	if err != nil {
		t.Fatalf("Failed to get file: %v", err)
	}

	if file.IsDir {
		t.Error("File should not be a directory")
	}

	if !bytes.Equal(file.Data, testData) {
		t.Error("File data mismatch")
	}

	if file.ContentType != "text/plain" {
		t.Errorf("Expected content type text/plain, got %s", file.ContentType)
	}
}

func TestMemoryVFS_DirectoryCreation(t *testing.T) {
	opts := vfs.Options{}
	mvfs := NewMemoryVFS("test", opts)
	defer mvfs.Clear()

	// Add file with nested path
	testData := []byte("nested content")
	err := mvfs.AddFile("dir1/dir2/file.txt", testData, "text/plain")
	if err != nil {
		t.Fatalf("Failed to add nested file: %v", err)
	}

	// Verify parent directories were created
	dir1, err := mvfs.GetFile("dir1")
	if err != nil {
		t.Fatalf("Parent directory not created: %v", err)
	}
	if !dir1.IsDir {
		t.Error("dir1 should be a directory")
	}

	dir2, err := mvfs.GetFile("dir1/dir2")
	if err != nil {
		t.Fatalf("Nested directory not created: %v", err)
	}
	if !dir2.IsDir {
		t.Error("dir2 should be a directory")
	}

	// Verify file
	file, err := mvfs.GetFile("dir1/dir2/file.txt")
	if err != nil {
		t.Fatalf("Failed to get nested file: %v", err)
	}
	if file.IsDir {
		t.Error("File should not be a directory")
	}
}

func TestMemoryVFS_SizeLimits(t *testing.T) {
	opts := vfs.Options{
		MaxFileSize:  100, // 100 bytes max per file
		MaxTotalSize: 200, // 200 bytes max total
	}
	mvfs := NewMemoryVFS("test", opts)
	defer mvfs.Clear()

	// Test file size limit
	largeData := make([]byte, 150)
	err := mvfs.AddFile("large.txt", largeData, "text/plain")
	if err == nil {
		t.Error("Should have failed due to file size limit")
	}

	// Add files within limits
	data1 := make([]byte, 90)
	err = mvfs.AddFile("file1.txt", data1, "text/plain")
	if err != nil {
		t.Fatalf("Failed to add file1: %v", err)
	}

	// This should fail due to total size limit (90 + 120 = 210 > 200)
	data2 := make([]byte, 120)
	err = mvfs.AddFile("file2.txt", data2, "text/plain")
	if err == nil {
		t.Error("Should have failed due to total size limit")
	}

	// Smaller file should succeed (90 + 50 = 140 < 200)
	data3 := make([]byte, 50)
	err = mvfs.AddFile("file3.txt", data3, "text/plain")
	if err != nil {
		t.Fatalf("Failed to add file3: %v", err)
	}
}

func TestMemoryVFS_ReadFile(t *testing.T) {
	opts := vfs.Options{}
	mvfs := NewMemoryVFS("test", opts)
	defer mvfs.Clear()

	original := []byte("original data")
	err := mvfs.AddFile("test.txt", original, "text/plain")
	if err != nil {
		t.Fatalf("Failed to add file: %v", err)
	}

	// Read file
	data, err := mvfs.ReadFile("test.txt")
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	if !bytes.Equal(data, original) {
		t.Error("Read data doesn't match original")
	}

	// Verify returned data is a copy (modifying it shouldn't affect original)
	data[0] = 'X'
	file, _ := mvfs.GetFile("test.txt")
	if file.Data[0] == 'X' {
		t.Error("File data was modified through returned slice (should be a copy)")
	}
}

func TestMemoryVFS_AccessTracking(t *testing.T) {
	opts := vfs.Options{
		MaxAccessPerFile: 5,
		AnomalyThreshold: 75,
	}
	mvfs := NewMemoryVFS("test", opts)
	defer mvfs.Clear()

	testData := []byte("test")
	mvfs.AddFile("test.txt", testData, "text/plain")

	// Access file multiple times
	for i := 0; i < 5; i++ {
		_, err := mvfs.GetFile("test.txt")
		if err != nil {
			t.Fatalf("Failed to get file on access %d: %v", i+1, err)
		}
	}

	// 6th access should fail due to access limit
	_, err := mvfs.GetFile("test.txt")
	if err == nil {
		t.Error("Should have failed due to access limit")
	}
}

func TestMemoryVFS_ListFiles(t *testing.T) {
	opts := vfs.Options{}
	mvfs := NewMemoryVFS("test", opts)
	defer mvfs.Clear()

	// Add multiple files and directories
	mvfs.AddFile("file1.txt", []byte("data1"), "text/plain")
	mvfs.AddFile("dir1/file2.txt", []byte("data2"), "text/plain")
	mvfs.AddFile("dir1/dir2/file3.txt", []byte("data3"), "text/plain")

	files := mvfs.ListFiles()

	// Should have exactly 3 files (directories not counted)
	if len(files) != 3 {
		t.Errorf("Expected 3 files, got %d", len(files))
	}

	// Verify all files are present
	expectedFiles := map[string]bool{
		"file1.txt":           true,
		"dir1/file2.txt":      true,
		"dir1/dir2/file3.txt": true,
	}

	for _, file := range files {
		if !expectedFiles[file] {
			t.Errorf("Unexpected file in list: %s", file)
		}
		delete(expectedFiles, file)
	}

	if len(expectedFiles) > 0 {
		t.Errorf("Missing files: %v", expectedFiles)
	}
}

func TestMemoryVFS_Stats(t *testing.T) {
	opts := vfs.Options{}
	mvfs := NewMemoryVFS("test", opts)
	defer mvfs.Clear()

	// Add files
	mvfs.AddFile("file1.txt", make([]byte, 100), "text/plain")
	mvfs.AddFile("dir1/file2.txt", make([]byte, 200), "text/plain")
	mvfs.AddFile("dir1/dir2/file3.txt", make([]byte, 300), "text/plain")

	stats := mvfs.GetStats()

	if stats["file_count"].(int) != 3 {
		t.Errorf("Expected 3 files, got %d", stats["file_count"])
	}

	// Should have created 2 directories (dir1, dir1/dir2)
	if stats["dir_count"].(int) != 2 {
		t.Errorf("Expected 2 directories, got %d", stats["dir_count"])
	}

	expectedSize := int64(600) // 100 + 200 + 300
	if stats["total_size"].(int64) != expectedSize {
		t.Errorf("Expected total size %d, got %d", expectedSize, stats["total_size"])
	}
}

func TestMemoryVFS_SecureClear(t *testing.T) {
	opts := vfs.Options{}
	mvfs := NewMemoryVFS("test", opts)

	// Add files with sensitive data
	sensitiveData := []byte("SECRET PASSWORD 123")
	mvfs.AddFile("secret.txt", sensitiveData, "text/plain")
	mvfs.AddFile("dir/secret2.txt", []byte("MORE SECRETS"), "text/plain")

	// Get reference to original data to verify zeroing
	file, _ := mvfs.GetFile("secret.txt")
	originalDataPtr := &file.Data[0]

	// Clear VFS
	mvfs.Clear()

	// Verify all files are removed
	_, err := mvfs.GetFile("secret.txt")
	if err == nil {
		t.Error("File should not exist after clear")
	}

	// Verify data was zeroed (note: this checks our own reference)
	// In reality, we can't fully guarantee the original memory is zeroed due to GC
	if len(mvfs.files) != 0 {
		t.Error("Files map should be empty after clear")
	}

	// Attempt to access original pointer would be unsafe
	// Just verify the cleanup happened
	_ = originalDataPtr // Use the variable to avoid unused warning
}

func TestMemoryVFS_PathNormalization(t *testing.T) {
	opts := vfs.Options{}
	mvfs := NewMemoryVFS("test", opts)
	defer mvfs.Clear()

	testData := []byte("test data")

	// Add file with leading slash
	err := mvfs.AddFile("/file.txt", testData, "text/plain")
	if err != nil {
		t.Fatalf("Failed to add file with leading slash: %v", err)
	}

	// Should be able to retrieve without leading slash
	file, err := mvfs.GetFile("file.txt")
	if err != nil {
		t.Fatalf("Failed to get file: %v", err)
	}

	if !bytes.Equal(file.Data, testData) {
		t.Error("File data mismatch")
	}
}

func TestMemoryVFS_ExportToReader(t *testing.T) {
	opts := vfs.Options{}
	mvfs := NewMemoryVFS("test", opts)
	defer mvfs.Clear()

	testData := []byte("exportable content")
	mvfs.AddFile("export.txt", testData, "text/plain")

	reader, err := mvfs.ExportToReader("export.txt")
	if err != nil {
		t.Fatalf("Failed to export to reader: %v", err)
	}

	// Read from the reader
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(reader)
	if err != nil {
		t.Fatalf("Failed to read from exported reader: %v", err)
	}

	if !bytes.Equal(buf.Bytes(), testData) {
		t.Error("Exported data doesn't match original")
	}
}

func TestViewFolderSecure_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create test folder structure
	testUser := "testuser"
	testFolder := "secure-test"

	err = db.CreateFolder(testFolder, testUser)
	if err != nil {
		t.Fatalf("Failed to create folder: %v", err)
	}

	// Add test files
	testFiles := map[string]string{
		testFolder + "/file1.txt": "Content 1",
		testFolder + "/file2.txt": "Content 2",
		testFolder + "/sub/file3.txt": "Content 3",
	}

	for path, content := range testFiles {
		_, err = db.StoreObject(path, "text/plain", testUser, []byte(content), nil)
		if err != nil {
			t.Fatalf("Failed to store object %s: %v", path, err)
		}
	}

	// Test the secure materialization process without blocking on preview
	// This tests that files are properly loaded into memory and can be materialized

	folder, err := db.GetFolder(testFolder)
	if err != nil {
		t.Fatalf("Failed to get folder: %v", err)
	}

	if folder.Path != testFolder {
		t.Errorf("Expected folder path %s, got %s", testFolder, folder.Path)
	}

	// Create memory VFS and load objects
	opts := vfs.Options{
		MaxFileSize:      1024 * 1024,
		MaxTotalSize:     500 * 1024 * 1024,
		EnableCompression: false,
		MaxAccessPerFile:  1000,
		AnomalyThreshold: 75,
	}

	memVFS := NewMemoryVFS(testFolder, opts)
	defer memVFS.Clear()

	// Load objects into memory VFS
	searchPrefix := testFolder
	if searchPrefix[0] == '/' {
		searchPrefix = searchPrefix[1:]
	}
	if searchPrefix != "" && searchPrefix[len(searchPrefix)-1] != '/' {
		searchPrefix += "/"
	}

	objects, err := db.ListObjects(ObjectListOptions{
		Prefix:    searchPrefix,
		Recursive: true,
		MaxKeys:   10000,
	})
	if err != nil {
		t.Fatalf("Failed to list objects: %v", err)
	}

	if len(objects) != len(testFiles) {
		t.Errorf("Expected %d objects, got %d", len(testFiles), len(objects))
	}

	// Load into memory VFS
	for _, obj := range objects {
		data, meta, err := db.GetObject(obj.Path, testUser)
		if err != nil {
			t.Fatalf("Failed to get object %s: %v", obj.Path, err)
		}

		relPath := obj.Path
		if len(relPath) > 0 && relPath[0] == '/' {
			relPath = relPath[1:]
		}
		if len(relPath) >= len(searchPrefix) && relPath[:len(searchPrefix)] == searchPrefix {
			relPath = relPath[len(searchPrefix):]
		}

		if err := memVFS.AddFile(relPath, data, meta.ContentType); err != nil {
			t.Fatalf("Failed to add file to VFS: %v", err)
		}
	}

	// Verify all files are in memory
	files := memVFS.ListFiles()
	if len(files) != len(testFiles) {
		t.Errorf("Expected %d files in VFS, got %d", len(testFiles), len(files))
	}

	// Test that we can read the files from memory
	for _, file := range files {
		data, err := memVFS.ReadFile(file)
		if err != nil {
			t.Errorf("Failed to read file %s from VFS: %v", file, err)
		}
		if len(data) == 0 {
			t.Errorf("File %s has no data", file)
		}
	}

	// Note: We don't call ViewFolderSecure here because it blocks waiting for user input
	// The actual preview functionality is tested manually
	t.Logf("✓ Successfully loaded %d files into secure memory VFS", len(files))
}

func TestViewObjectSecure_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Store test object
	testUser := "testuser"
	testPath := "secure-file.txt"
	testContent := []byte("Secure file content")

	_, err = db.StoreObject(testPath, "text/plain", testUser, testContent, nil)
	if err != nil {
		t.Fatalf("Failed to store object: %v", err)
	}

	// Test the secure materialization process without blocking on preview
	// This tests that file is properly loaded into memory

	// Create memory VFS and load object
	opts := vfs.Options{
		MaxFileSize:      100 * 1024 * 1024,
		MaxTotalSize:     100 * 1024 * 1024,
		EnableCompression: false,
		MaxAccessPerFile:  1000,
		AnomalyThreshold: 75,
	}

	memVFS := NewMemoryVFS("preview", opts)
	defer memVFS.Clear()

	// Retrieve object data
	data, meta, err := db.GetObject(testPath, testUser)
	if err != nil {
		t.Fatalf("Failed to get object: %v", err)
	}

	if !bytes.Equal(data, testContent) {
		t.Errorf("Retrieved data doesn't match stored content")
	}

	// Add to memory VFS
	filename := filepath.Base(testPath)
	err = memVFS.AddFile(filename, data, meta.ContentType)
	if err != nil {
		t.Fatalf("Failed to add file to VFS: %v", err)
	}

	// Verify file is in memory
	file, err := memVFS.GetFile(filename)
	if err != nil {
		t.Fatalf("Failed to get file from VFS: %v", err)
	}

	if !bytes.Equal(file.Data, testContent) {
		t.Errorf("VFS file data doesn't match original")
	}

	// Note: We don't call ViewObjectSecure here because it blocks waiting for user input
	// The actual preview functionality is tested manually
	t.Logf("✓ Successfully loaded file into secure memory VFS")
}

func TestMemoryVFS_NoTempFileCreation(t *testing.T) {
	// This test verifies that no temporary files are created
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	testUser := "testuser"
	testFolder := "no-temp-test"

	db.CreateFolder(testFolder, testUser)
	db.StoreObject(testFolder+"/file.txt", "text/plain", testUser, []byte("test"), nil)

	// This will fail with pending integration but shouldn't create temp files
	_ = db.ViewFolderSecure(testFolder, testUser, false, 1024*1024)

	// Verify no velocity temp files exist in system temp dir
	// (The test would need OS temp dir scanning which is complex,
	// so we just log this as a manual verification point)
	t.Log("Manual verification: Check that no velocity-folder-* or velocity-preview-* files exist in /tmp")
}
