package api

import (
	"context"
	"io"
)

// BackupService is the durability-export surface plugins/backup exposes,
// ported from v1's backup.go/backup_security.go (HMAC-signed backups with
// tamper rejection on restore). Reference implementation: plugins/backup,
// service name "backup".
//
// Backup/Restore operate over the full keyspace of whatever StorageBackend
// the backup plugin is wired to. Export/Import are the same format scoped
// to keys sharing a prefix, for partial backup/restore workflows.
//
// Restore and Import MUST verify the stream's integrity signature before
// applying any of its contents — a tampered or truncated stream must be
// rejected with an error and must not partially mutate the backend.
type BackupService interface {
	Backup(ctx context.Context, w io.Writer) error
	Restore(ctx context.Context, r io.Reader) error
	Export(ctx context.Context, w io.Writer, prefix string) error
	Import(ctx context.Context, r io.Reader) error
}
