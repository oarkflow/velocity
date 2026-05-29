package velocity

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func productionTestKey(seed byte) []byte {
	key := bytes.Repeat([]byte{seed}, 32)
	return key
}

func TestProductionKVEncryptedDurabilityAndWrongKeyRejection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kv_encrypted")
	key := productionTestKey('a')
	wrongKey := productionTestKey('b')

	db, err := NewWithConfig(Config{Path: path, MasterKey: key})
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	secret := []byte("production secret payload")
	if err := db.Put([]byte("tenant:1:secret"), secret); err != nil {
		t.Fatalf("put failed: %v", err)
	}

	walBytes, err := os.ReadFile(filepath.Join(path, "wal.log"))
	if err != nil {
		t.Fatalf("read wal failed: %v", err)
	}
	if bytes.Contains(walBytes, secret) {
		t.Fatalf("wal contains plaintext secret")
	}

	replayed, err := NewWithConfig(Config{Path: path, MasterKey: key})
	if err != nil {
		t.Fatalf("crash-style reopen failed: %v", err)
	}
	got, err := replayed.Get([]byte("tenant:1:secret"))
	if err != nil {
		t.Fatalf("replayed get failed: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("replayed value mismatch: got %q want %q", got, secret)
	}
	if err := replayed.Close(); err != nil {
		t.Fatalf("close replayed failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close original failed: %v", err)
	}

	if _, err := NewWithConfig(Config{Path: path, MasterKey: wrongKey}); err == nil {
		t.Fatalf("expected wrong master key to be rejected")
	}

	reopened, err := NewWithConfig(Config{Path: path, MasterKey: key})
	if err != nil {
		t.Fatalf("clean reopen failed: %v", err)
	}
	defer reopened.Close()
	got, err = reopened.Get([]byte("tenant:1:secret"))
	if err != nil {
		t.Fatalf("clean reopened get failed: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("clean reopened value mismatch: got %q want %q", got, secret)
	}
}

func TestProductionKVEncryptedSSTableNoPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kv_encrypted_sstable")
	key := productionTestKey('s')
	secret := []byte("sstable production secret payload")

	db, err := NewWithConfig(Config{Path: path, MasterKey: key})
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if err := db.Put([]byte("tenant:1:sstable_secret"), secret); err != nil {
		t.Fatalf("put failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	files, err := filepath.Glob(filepath.Join(path, "sst_*.db"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("expected at least one SSTable")
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read sstable failed: %v", err)
		}
		if bytes.Contains(data, secret) {
			t.Fatalf("sstable %s contains plaintext secret", filepath.Base(file))
		}
	}

	reopened, err := NewWithConfig(Config{Path: path, MasterKey: key})
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer reopened.Close()
	got, err := reopened.Get([]byte("tenant:1:sstable_secret"))
	if err != nil {
		t.Fatalf("get after reopen failed: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("value mismatch: got %q want %q", got, secret)
	}
}

func TestProductionKVRejectsCorruptedWALReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kv_corrupt_wal")
	key := productionTestKey('c')

	db, err := NewWithConfig(Config{Path: path, MasterKey: key})
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	defer db.Close()
	if err := db.Put([]byte("tenant:1:secret"), []byte("payload")); err != nil {
		t.Fatalf("put failed: %v", err)
	}
	if err := db.wal.Sync(); err != nil {
		t.Fatalf("wal sync failed: %v", err)
	}
	if err := db.wal.Close(); err != nil {
		t.Fatalf("wal close failed: %v", err)
	}
	db.wal = nil

	walPath := filepath.Join(path, "wal.log")
	walBytes, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read wal failed: %v", err)
	}
	if len(walBytes) < 2 {
		t.Fatalf("wal unexpectedly small: %d bytes", len(walBytes))
	}
	walBytes[len(walBytes)-1] ^= 0xff
	if err := os.WriteFile(walPath, walBytes, 0o600); err != nil {
		t.Fatalf("write corrupted wal failed: %v", err)
	}

	if _, err := NewWithConfig(Config{Path: path, MasterKey: key}); err == nil {
		t.Fatalf("expected corrupted WAL replay to fail")
	}
}

func TestProductionKVRejectsCorruptedSSTableRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kv_corrupt_sstable")
	key := productionTestKey('d')
	db, err := NewWithConfig(Config{Path: path, MasterKey: key})
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	value := []byte("uncorrupted payload")
	if err := db.Put([]byte("tenant:1:sst_corrupt"), value); err != nil {
		t.Fatalf("put failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	files, err := filepath.Glob(filepath.Join(path, "sst_*.db"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("expected at least one SSTable")
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read sstable failed: %v", err)
	}
	if len(data) < 80 {
		t.Fatalf("sstable unexpectedly small: %d bytes", len(data))
	}
	data[len(data)/2] ^= 0xff
	if err := os.WriteFile(files[0], data, 0o600); err != nil {
		t.Fatalf("write corrupted sstable failed: %v", err)
	}

	reopened, err := NewWithConfig(Config{Path: path, MasterKey: key})
	if err != nil {
		t.Fatalf("reopen after sstable corruption failed: %v", err)
	}
	defer reopened.Close()
	got, err := reopened.Get([]byte("tenant:1:sst_corrupt"))
	if err == nil && !bytes.Equal(got, value) {
		t.Fatalf("corrupted sstable returned forged value %q", got)
	}
}

func TestProductionKVFlushCheckpointRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kv_flush_checkpoint")
	key := productionTestKey('e')
	cp := flushCheckpoint{SSTable: "missing.db", Started: 1}
	data, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("marshal checkpoint failed: %v", err)
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, flushCheckpointName), data, 0o600); err != nil {
		t.Fatalf("write checkpoint failed: %v", err)
	}

	db, err := NewWithConfig(Config{Path: path, MasterKey: key})
	if err != nil {
		t.Fatalf("open with stale checkpoint failed: %v", err)
	}
	defer db.Close()
	if _, err := os.Stat(filepath.Join(path, flushCheckpointName)); !os.IsNotExist(err) {
		t.Fatalf("expected stale checkpoint to be removed, stat err=%v", err)
	}
}

func TestProductionBackupRestoreDisasterRecovery(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "source")
	restorePath := filepath.Join(root, "restore")
	backupPath := filepath.Join(root, "backups", "full.backup.gz")
	key := productionTestKey('r')

	source, err := NewWithConfig(Config{Path: sourcePath, MasterKey: key})
	if err != nil {
		t.Fatalf("source open failed: %v", err)
	}
	values := map[string][]byte{
		"secret:app/config": []byte("primary-config"),
		"secret:binary":     {0, 1, 2, 3, 250, 251, 252},
	}
	for k, v := range values {
		if err := source.Put([]byte(k), v); err != nil {
			t.Fatalf("put %s failed: %v", k, err)
		}
	}
	if err := source.Backup(BackupOptions{
		OutputPath:   backupPath,
		Compress:     true,
		IncludeTypes: []string{"secrets"},
		User:         "dr-test",
		Description:  "production disaster recovery test",
	}); err != nil {
		t.Fatalf("backup failed: %v", err)
	}
	if _, err := source.VerifyBackupIntegrity(backupPath); err != nil {
		t.Fatalf("backup integrity failed: %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("source close failed: %v", err)
	}
	if err := os.RemoveAll(sourcePath); err != nil {
		t.Fatalf("remove source failed: %v", err)
	}

	restore, err := NewWithConfig(Config{Path: restorePath, MasterKey: key})
	if err != nil {
		t.Fatalf("restore open failed: %v", err)
	}
	defer restore.Close()
	if err := restore.Restore(RestoreOptions{
		BackupPath:   backupPath,
		Overwrite:    true,
		IncludeTypes: []string{"secrets"},
		User:         "dr-test",
	}); err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	for k, want := range values {
		got, err := restore.Get([]byte(k))
		if err != nil {
			t.Fatalf("restored get %s failed: %v", k, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("restored %s = %v, want %v", k, got, want)
		}
	}
}

func TestProductionBackupTamperRejected(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "source")
	backupPath := filepath.Join(root, "full.backup")
	tamperedPath := filepath.Join(root, "tampered.backup")
	key := productionTestKey('t')

	db, err := NewWithConfig(Config{Path: path, MasterKey: key})
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	defer db.Close()
	if err := db.Put([]byte("secret:tamper"), []byte("do-not-change")); err != nil {
		t.Fatalf("put failed: %v", err)
	}
	if err := db.Backup(BackupOptions{
		OutputPath:   backupPath,
		IncludeTypes: []string{"secrets"},
		User:         "dr-test",
	}); err != nil {
		t.Fatalf("backup failed: %v", err)
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup failed: %v", err)
	}
	if len(data) < 32 {
		t.Fatalf("backup unexpectedly small: %d", len(data))
	}
	data[len(data)/2] ^= 0xff
	if err := os.WriteFile(tamperedPath, data, 0o600); err != nil {
		t.Fatalf("write tampered backup failed: %v", err)
	}
	if _, err := db.VerifyBackupIntegrity(tamperedPath); err == nil {
		t.Fatalf("expected tampered backup integrity verification to fail")
	}
	if err := db.Restore(RestoreOptions{
		BackupPath:   tamperedPath,
		Overwrite:    true,
		IncludeTypes: []string{"secrets"},
		User:         "dr-test",
	}); err == nil {
		t.Fatalf("expected tampered backup restore to fail")
	}
}
