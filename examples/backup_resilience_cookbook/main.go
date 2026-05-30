package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/oarkflow/velocity"
)

func main() {
	ctx := context.Background()
	dir := mustTempDir()
	defer os.RemoveAll(dir)

	db, err := velocity.NewWithConfig(velocity.Config{Path: filepath.Join(dir, "db"), MasterKey: []byte("0123456789abcdef0123456789abcdef")})
	check(err)
	defer db.Close()

	check(db.Put([]byte("secret:api-key"), []byte("value")))
	meta, err := db.StoreObject("evidence/report.txt", "text/plain", "alice", []byte("important evidence"), &velocity.ObjectOptions{Encrypt: true})
	check(err)

	wal := db.GetWAL()
	wal.SetBufferSize(64 << 10)
	wal.SetSyncInterval(100 * time.Millisecond)
	wal.SetSyncOnWrite(false)
	wal.SetRotationPolicy(1<<20, filepath.Join(dir, "wal-archive"), 3, 7)
	check(wal.CheckRotation())

	backupPath := filepath.Join(dir, "backup.tar.gz")
	check(db.Backup(velocity.BackupOptions{
		OutputPath:   backupPath,
		Compress:     true,
		IncludeTypes: []string{"secrets", "folders", "objects"},
		User:         "alice",
		Description:  "cookbook backup",
	}))
	verified, err := db.VerifyBackupIntegrity(backupPath)
	check(err)

	exportPath := filepath.Join(dir, "objects.json")
	check(db.Export(velocity.ExportOptions{
		Format: "json", OutputPath: exportPath, Pretty: true,
		User: "alice", ItemType: "object", Paths: []string{"evidence/report.txt"},
	}))
	check(db.Import(velocity.ImportOptions{Format: "json", InputPath: exportPath, User: "alice", DryRun: true}))

	restoreDB, err := velocity.NewWithConfig(velocity.Config{Path: filepath.Join(dir, "restore"), MasterKey: []byte("0123456789abcdef0123456789abcdef")})
	check(err)
	defer restoreDB.Close()
	check(restoreDB.Restore(velocity.RestoreOptions{BackupPath: backupPath, Overwrite: true, User: "alice"}))

	erasure, err := velocity.NewErasureEncoder(velocity.ErasureConfig{DataShards: 3, ParityShards: 2})
	check(err)
	shards, err := erasure.Encode([]byte("resilient payload"))
	check(err)
	ok := erasure.Verify(shards)
	decoded, err := erasure.Decode(shards, len("resilient payload"))
	check(err)

	bitrot := velocity.NewBitRotDetector(db, time.Hour, velocity.HashSHA256)
	check(bitrot.UpdateIntegrityHash("evidence/report.txt", meta.Hash, meta))
	healthy, _, err := bitrot.VerifyObjectIntegrity("evidence/report.txt")
	check(err)
	scan, err := bitrot.ScanAll(ctx)
	check(err)
	healer := velocity.NewHealingManager(db, erasure, bitrot)
	heal, err := healer.HealAll(ctx)
	check(err)
	repair, err := db.RepairObjectStorage(ctx, velocity.RepairOptions{DryRun: true})
	check(err)

	archiveCount, archiveBytes, _, err := wal.ArchiveStats()
	check(err)
	fmt.Printf("backup items=%d signature=%s export=%s\n", verified.ItemCount, verified.Signature.Algorithm, filepath.Base(exportPath))
	fmt.Printf("erasure shards=%d ok=%t decoded=%q\n", len(shards), ok, string(decoded))
	fmt.Printf("bitrot healthy=%t scanned=%d healed=%d repair_missing=%d wal_archives=%d/%d\n", healthy, scan.ObjectsScanned, heal.ObjectsHealed, repair.MissingFiles, archiveCount, archiveBytes)
}

func mustTempDir() string {
	dir, err := os.MkdirTemp("", "velocity_backup_resilience_cookbook_")
	check(err)
	return dir
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
