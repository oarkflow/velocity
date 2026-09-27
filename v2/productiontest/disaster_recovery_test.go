package productiontest

import (
	"bytes"
	"context"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/backup"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func bootKVBackup(t *testing.T, dir string) (*kernel.Kernel, api.KVService, api.BackupService) {
	t.Helper()
	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir, "always_sync": true}},
		{Name: "kv", Enabled: true},
		{Name: "backup", Enabled: true, Config: map[string]any{"hmac_key": "disaster-recovery-test-hmac-key-32"}},
	}}
	k := kernel.New(manifest)
	plugins := []api.Plugin{storagelsm.New(), kv.New("storage-lsm"), backup.NewPlugin("storage-lsm")}
	ctx := context.Background()
	if err := k.Boot(ctx, plugins, manifest.Enabled()); err != nil {
		t.Fatalf("boot: %v", err)
	}
	kvSvc := k.Registry().MustLookup("kv").(api.KVService)
	backupSvc := k.Registry().MustLookup("backup").(api.BackupService)
	return k, kvSvc, backupSvc
}

// TestDisasterRecovery_FullDataDirLossThenRestore simulates the entire
// data directory being destroyed (disk failure, accidental rm -rf) and
// verifies a completely fresh instance recovers everything from a prior
// backup.
func TestDisasterRecovery_FullDataDirLossThenRestore(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()

	k1, kv1, backup1 := bootKVBackup(t, srcDir)
	want := map[string]string{}
	for i := 0; i < 200; i++ {
		key := "disaster:" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		val := "value-" + key
		if err := kv1.Put(ctx, key, []byte(val)); err != nil {
			t.Fatal(err)
		}
		want[key] = val
	}

	var backupBytes bytes.Buffer
	if err := backup1.Backup(ctx, &backupBytes); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	k1.Shutdown(ctx)

	// "The entire data directory is destroyed" — a fresh instance at a
	// BRAND NEW, never-before-used directory, restored purely from the
	// backup bytes (srcDir is intentionally never touched again).
	freshDir := t.TempDir()
	k2, kv2, backup2 := bootKVBackup(t, freshDir)
	defer k2.Shutdown(ctx)

	if err := backup2.Restore(ctx, bytes.NewReader(backupBytes.Bytes())); err != nil {
		t.Fatalf("Restore into fresh instance: %v", err)
	}

	for key, want := range want {
		got, found, err := kv2.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get(%s): %v", key, err)
		}
		if !found {
			t.Fatalf("key %s missing after disaster-recovery restore", key)
		}
		if string(got) != want {
			t.Fatalf("key %s: got %q, want %q", key, got, want)
		}
	}
	t.Logf("all %d keys recovered correctly into a completely fresh instance", len(want))
}

// TestDisasterRecovery_TamperedBackupRejectedWithoutPartialApply proves a
// corrupted/tampered backup file is rejected outright — the target
// instance ends up with ZERO data, not a partial or corrupted subset.
func TestDisasterRecovery_TamperedBackupRejectedWithoutPartialApply(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()

	k1, kv1, backup1 := bootKVBackup(t, srcDir)
	for i := 0; i < 50; i++ {
		if err := kv1.Put(ctx, "tamper:key"+string(rune('a'+i)), []byte("secret-data")); err != nil {
			t.Fatal(err)
		}
	}
	var backupBytes bytes.Buffer
	if err := backup1.Backup(ctx, &backupBytes); err != nil {
		t.Fatal(err)
	}
	k1.Shutdown(ctx)

	tampered := append([]byte(nil), backupBytes.Bytes()...)
	// Flip a byte roughly in the middle of the payload (past any header,
	// well before the trailing signature) — a real tamper, not a
	// truncation.
	mid := len(tampered) / 2
	tampered[mid] ^= 0xFF

	freshDir := t.TempDir()
	k2, kv2, backup2 := bootKVBackup(t, freshDir)
	defer k2.Shutdown(ctx)

	err := backup2.Restore(ctx, bytes.NewReader(tampered))
	if err == nil {
		t.Fatalf("Restore of a tampered backup succeeded — should have been rejected")
	}
	t.Logf("tampered restore correctly rejected: %v", err)

	// Zero data applied — not partial, not corrupted, none.
	for i := 0; i < 50; i++ {
		_, found, gerr := kv2.Get(ctx, "tamper:key"+string(rune('a'+i)))
		if gerr != nil {
			t.Fatalf("Get after rejected restore: %v", gerr)
		}
		if found {
			t.Fatalf("key tamper:key%c present after a REJECTED restore — partial apply, not clean rejection", 'a'+i)
		}
	}
	t.Logf("confirmed zero data applied after tampered-backup rejection")
}
