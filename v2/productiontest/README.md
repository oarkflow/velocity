# productiontest

Whole-system production-readiness tests for Velocity v2: boots the real
kernel against a real manifest and abuses it the way production would,
rather than testing one plugin's API in isolation (that's what each
`plugins/*/​*_test.go` suite already does — this package complements those,
it doesn't duplicate them).

Ported from v1's testing methodology (`production_readiness_test.go`,
`destructive_production_test.go`) to v2's plugin architecture.

## What's here

- **`crash_recovery_test.go`** — boots a real child process (`cmd/crashharness`)
  writing continuously, SIGKILLs it at 5 randomized points, reopens the
  same data directory in-process, and verifies every acknowledged write
  survived. Proves crash safety against an actual process death, not an
  in-process simulation.
- **`corruption_rejection_test.go`** — bit-flips the on-disk WAL file at
  several offsets and verifies the engine never returns silently-wrong
  data: it either recovers everything before the corruption (torn-write
  tolerance) or fails to open outright — never a mismatched value.
- **`disaster_recovery_test.go`** — full data-directory loss + restore
  from backup into a brand-new instance, plus tampered-backup rejection
  (verifies zero partial data is applied when a backup fails its HMAC
  check).
- **`soak_test.go`** — 5 seconds of real sustained concurrent load (8
  workers, mixed KV/object Put/Get/Delete) against a real kernel, then an
  exhaustive consistency check against everything the workload tracked
  writing, plus a goroutine-leak check after `kernel.Shutdown`.
- **`fuzz_test.go`** — Go native fuzzing for the two most exposed
  malformed-input surfaces: the WAL file (`FuzzWALRecovery`, fuzzes raw
  bytes as `wal.log` content, requires `storagelsm.Open` to never panic)
  and the SQL parser (`FuzzSQLParser`, fuzzes query strings against a real
  `sql.Engine`, requires it to never panic on garbage SQL).

## Running

```sh
cd v2
go test ./productiontest/...              # everything except fuzzing (fuzz targets run once each as their seed corpus)
go test ./productiontest/... -v -run TestSoak    # soak test alone (respects -short to skip)
go test ./productiontest -fuzz=FuzzWALRecovery -fuzztime=30s -run=^$
go test ./productiontest -fuzz=FuzzSQLParser  -fuzztime=30s -run=^$
```

## What this found

While building this suite, a real bug was found and fixed in the test
harness itself (not v2): using `time.After(d)` as a multi-goroutine "stop"
signal only wakes exactly one goroutine, since a channel receive is
exclusive — the other N-1 spin forever. Fixed by closing a channel
instead (`close()` broadcasts to every receiver). This is a classic Go
concurrency footgun worth documenting here since it looks exactly like a
product deadlock until you check the stop-signal mechanism itself.

No bugs were found in v2 itself during this pass: crash recovery,
corruption handling, disaster recovery, sustained concurrent load, and
4.3M+ fuzzed SQL queries / WAL byte sequences all behaved correctly.
