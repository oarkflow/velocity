# backup_restore

Demonstrates Velocity v2's `backup` plugin: a full HMAC-signed backup and
restore into a completely separate instance (proving the format is
portable, not tied to one engine instance), tamper rejection (a corrupted
backup stream is rejected outright, with zero data applied), and
prefix-scoped export/import for partial backups.

## Run

```sh
go run ./examples/backup_restore
```

## Expected output summary

- Data written to a source instance survives, byte-for-byte, a
  Backup-then-Restore round trip into a fresh, separate instance.
- A backup with one flipped bit is rejected with a clear signature-mismatch
  error, and the target instance ends up with no data from it at all.
- `Export`/`Import` scoped to the `user/` prefix only moves matching keys,
  leaving unrelated existing keys in the target untouched.
