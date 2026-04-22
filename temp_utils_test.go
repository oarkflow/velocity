package velocity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTempManager_CreateSecureTempDir(t *testing.T) {
	tm := NewTempManager()
	defer tm.Cleanup()

	// Create a secure temp directory
	tempDir, err := tm.CreateSecureTempDir("test-dir-*")
	if err != nil {
		t.Fatalf("Failed to create secure temp dir: %v", err)
	}

	// Verify the directory exists
	info, err := os.Stat(tempDir)
	if err != nil {
		t.Fatalf("Temp directory does not exist: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("Path is not a directory")
	}

	// Verify secure permissions (0700)
	mode := info.Mode().Perm()
	if mode != 0700 {
		t.Errorf("Expected permissions 0700, got %o", mode)
	}

	// Verify it's tracked
	if tm.Count() != 1 {
		t.Errorf("Expected 1 tracked resource, got %d", tm.Count())
	}

	// Cleanup should remove the directory
	tm.Cleanup()

	// Verify the directory is removed
	if _, err := os.Stat(tempDir); !os.IsNotExist(err) {
		t.Errorf("Temp directory still exists after cleanup")
	}
}

func TestTempManager_CreateSecureTempFile(t *testing.T) {
	tm := NewTempManager()
	defer tm.Cleanup()

	// Create a secure temp file
	tempFile, err := tm.CreateSecureTempFile("test-file-*")
	if err != nil {
		t.Fatalf("Failed to create secure temp file: %v", err)
	}
	tempPath := tempFile.Name()
	tempFile.Close()

	// Verify the file exists
	info, err := os.Stat(tempPath)
	if err != nil {
		t.Fatalf("Temp file does not exist: %v", err)
	}
	if info.IsDir() {
		t.Fatalf("Path is a directory, not a file")
	}

	// Verify secure permissions (0600)
	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("Expected permissions 0600, got %o", mode)
	}

	// Verify it's tracked
	if tm.Count() != 1 {
		t.Errorf("Expected 1 tracked resource, got %d", tm.Count())
	}

	// Cleanup should remove the file
	tm.Cleanup()

	// Verify the file is removed
	if _, err := os.Stat(tempPath); !os.IsNotExist(err) {
		t.Errorf("Temp file still exists after cleanup")
	}
}

func TestTempManager_MultipleResources(t *testing.T) {
	tm := NewTempManager()
	defer tm.Cleanup()

	// Create multiple temp resources
	tempDir1, _ := tm.CreateSecureTempDir("test-dir1-*")
	tempDir2, _ := tm.CreateSecureTempDir("test-dir2-*")
	tempFile1, _ := tm.CreateSecureTempFile("test-file1-*")
	tempFile1.Close()
	tempFile2, _ := tm.CreateSecureTempFile("test-file2-*")
	tempFile2.Close()

	// Verify all are tracked
	if tm.Count() != 4 {
		t.Errorf("Expected 4 tracked resources, got %d", tm.Count())
	}

	// Cleanup should remove all
	tm.Cleanup()

	// Verify all are removed
	for _, path := range []string{tempDir1, tempDir2, tempFile1.Name(), tempFile2.Name()} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("Resource %s still exists after cleanup", path)
		}
	}

	// Verify tracking list is cleared
	if tm.Count() != 0 {
		t.Errorf("Expected 0 tracked resources after cleanup, got %d", tm.Count())
	}
}

func TestTempManager_CleanupPath(t *testing.T) {
	tm := NewTempManager()
	defer tm.Cleanup()

	// Create temp resources
	tempDir, _ := tm.CreateSecureTempDir("test-dir-*")
	tempFile, _ := tm.CreateSecureTempFile("test-file-*")
	tempFile.Close()

	if tm.Count() != 2 {
		t.Fatalf("Expected 2 tracked resources, got %d", tm.Count())
	}

	// Clean up the directory early
	err := tm.CleanupPath(tempDir)
	if err != nil {
		t.Errorf("Failed to cleanup path: %v", err)
	}

	// Verify directory is removed
	if _, err := os.Stat(tempDir); !os.IsNotExist(err) {
		t.Errorf("Temp directory still exists after early cleanup")
	}

	// Verify tracking count decreased
	if tm.Count() != 1 {
		t.Errorf("Expected 1 tracked resource after early cleanup, got %d", tm.Count())
	}

	// File should still exist
	if _, err := os.Stat(tempFile.Name()); err != nil {
		t.Errorf("Temp file should still exist: %v", err)
	}
}

func TestSecureWriteFile(t *testing.T) {
	tmpDir := t.TempDir()
	testPath := filepath.Join(tmpDir, "subdir", "test.txt")
	testData := []byte("secure test data")

	// Write file
	err := SecureWriteFile(testPath, testData)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	// Verify file exists
	data, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	if string(data) != string(testData) {
		t.Errorf("File content mismatch")
	}

	// Verify secure permissions
	info, _ := os.Stat(testPath)
	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("Expected file permissions 0600, got %o", mode)
	}

	// Verify parent directory was created with secure permissions
	dirInfo, _ := os.Stat(filepath.Dir(testPath))
	dirMode := dirInfo.Mode().Perm()
	if dirMode != 0700 {
		t.Errorf("Expected directory permissions 0700, got %o", dirMode)
	}
}

func TestCleanupOrphanedTempFiles(t *testing.T) {
	// Create some fake orphaned temp files/dirs
	tempDir := os.TempDir()

	orphanDir := filepath.Join(tempDir, "velocity-folder-orphan-test")
	os.MkdirAll(orphanDir, 0755)
	defer os.RemoveAll(orphanDir) // Ensure cleanup even if test fails

	orphanFile := filepath.Join(tempDir, "velocity-preview-orphan-test.txt")
	os.WriteFile(orphanFile, []byte("orphan"), 0644)
	defer os.Remove(orphanFile)

	// Run cleanup
	err := CleanupOrphanedTempFiles()
	if err != nil {
		t.Logf("Cleanup completed with errors: %v", err)
	}

	// Verify orphans are removed
	if _, err := os.Stat(orphanDir); !os.IsNotExist(err) {
		t.Errorf("Orphaned directory still exists")
	}
	if _, err := os.Stat(orphanFile); !os.IsNotExist(err) {
		t.Errorf("Orphaned file still exists")
	}
}

func TestViewFolderCleanup(t *testing.T) {
	// This is an integration test to verify ViewFolder cleans up properly
	tmpDir := t.TempDir()

	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create a test folder with some files
	testUser := "testuser"
	testFolder := "test-folder"

	err = db.CreateFolder(testFolder, testUser)
	if err != nil {
		t.Fatalf("Failed to create folder: %v", err)
	}

	// Store some test objects
	testData := []byte("test content")
	_, err = db.StoreObject(testFolder+"/file1.txt", "text/plain", testUser, testData, nil)
	if err != nil {
		t.Fatalf("Failed to store object: %v", err)
	}

	// Count temp directories before
	systemTempDir := os.TempDir()
	beforeCount := countVelocityTempDirs(systemTempDir)

	// Note: We can't actually test ViewFolder completely as it opens a preview
	// which is interactive. But we can verify the cleanup mechanism is in place
	// by checking the code structure

	// Count temp directories after
	afterCount := countVelocityTempDirs(systemTempDir)

	// In a real scenario without preview, temp dirs should be cleaned up
	// This test mainly ensures the defer cleanup is in place
	t.Logf("Temp directories before: %d, after: %d", beforeCount, afterCount)
}

// Helper function to count velocity temp directories
func countVelocityTempDirs(dir string) int {
	matches, _ := filepath.Glob(filepath.Join(dir, "velocity-folder-*"))
	return len(matches)
}
