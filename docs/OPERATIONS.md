# Operations

## Server Modes

Embedded mode uses `velocity.New` or `velocity.NewWithConfig` inside your Go process.

Minimal CLI mode:

```bash
go build -o velocity ./cmd/velocity
VELOCITY_PATH=./velocity_data ./velocity data put k v
```

HTTP/TCP server mode:

```bash
cd pkg/web
go run ./cmd serve --http 8081 --tcp 8080 --dir ./velocitydb_server --users ./users.db
```

## Environment Variables

- `VELOCITY_PATH`: minimal CLI database path.
- `VELOCITY_BOOTSTRAP_ADMIN_USER`: optional web server admin bootstrap username.
- `VELOCITY_BOOTSTRAP_ADMIN_PASS`: optional web server admin bootstrap password.
- `VELOCITY_BIN`: wrapper script binary path.
- `VELOCITY_SQL_MILLION_ROWS`: million-row SQL test/example row count.
- `VELOCITY_SQL_MILLION_CHUNK`: million-row SQL chunk size.

## Durability

Core durability mechanisms:

- WAL writes and replay.
- Flush checkpoint recovery.
- SSTable atomic writes.
- Compaction.
- WAL rotation and retention.
- SSTable repair endpoint.
- Graceful shutdown on `SIGINT`, `SIGTERM`, and `SIGHUP`.

Avoid disabling WAL, fsync, encryption, or close flush outside controlled benchmarks.

## Disaster-Recovery Test Gate

Before a production release, run the reliability suite from the repository root:

```bash
make reliability-full
```

For deeper pre-release validation:

```bash
VELOCITY_DESTRUCTIVE_SOAK_ITERS=1200 make reliability-soak
make reliability-race
```

The gate exercises normal and negative conditions: crash-style child-process kills, WAL replay, WAL rotation/truncation, flush checkpoint recovery, corrupted WAL/SSTable rejection, backup restore, tampered backup rejection, SQL transaction crash recovery, reactive watch determinism, web API/security regressions, and example smoke tests.

## Backup And Restore

Use the embedded backup APIs:

- `Backup(BackupOptions)`
- `Restore(RestoreOptions)`
- `Export(ExportOptions)`
- `Import(ImportOptions)`
- `VerifyBackupIntegrity`
- `ExportAuditTrail`
- `VerifyAuditChain`

Backup metadata, signatures, HMAC checks, and audit records are part of the backup security model.

## Admin Endpoints

Admin-only HTTP routes expose:

- WAL stats, rotation, and archives.
- SSTable repair.
- Master key config, refresh, cache clear, and cache info.
- Thumbnail regeneration and deletion.

## Monitoring

Metrics support is represented by `MetricsCollector`, histograms, and a `MetricsRenderer` interface used by the enterprise API at `GET /api/v1/metrics`.

For production, wire metrics rendering explicitly and place it behind your chosen authentication/network controls.

## Resilience

Source includes:

- Erasure coding.
- Bit rot detection.
- Healing reports.
- Replication manager.
- Bucket replication.
- Consistent hash ring.
- Cluster manager.
- Load balancer.
- Decommission manager.

Some of these are library building blocks and must be wired by the host application.
