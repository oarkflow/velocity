#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TIER="${VELOCITY_RELIABILITY_TIER:-${1:-quick}}"
SOAK_ITERS="${VELOCITY_DESTRUCTIVE_SOAK_ITERS:-800}"
RUN_MILLION="${VELOCITY_RELIABILITY_MILLION:-0}"

cd "${ROOT_DIR}"

section() {
  echo
  echo "== $1 =="
}

run() {
  echo
  echo "+ $*"
  "$@"
}

run_in() {
  local dir="$1"
  shift
  echo
  echo "+ (cd ${dir} && $*)"
  (cd "${dir}" && "$@")
}

quick_suite() {
  section "KV durability, WAL, corruption rejection, backup restore, and reactive determinism"
  run go test -run 'TestProductionKV|TestProductionBackup|TestWAL|TestBatchWriter|TestWatch|TestRaceConditionStress|TestRepairSSTable|TestSSTableAtomic' -count=1 .

  section "SQL production readiness and transaction durability"
  run go test ./pkg/sqldriver -run 'TestSQLDriver_Production|TestSQLDriver_Transaction|TestSQLDriver_ProductionSkipCloseFlushReplaysWAL' -count=1

  section "Web security and API regression"
  run_in pkg/web go test ./... -count=1

  section "Reactive example smoke test"
  run_in examples go run ./reactive_watch_hooks
}

full_suite() {
  quick_suite

  section "Root module full test suite"
  run go test ./... -count=1

  section "Examples module compile/test suite"
  run_in examples go test ./... -count=1

  section "Destructive crash/corruption matrix"
  run go test -tags destructive -run 'TestDestructive' -count=1 .
  run go test -tags destructive -run 'TestDestructive' -count=1 ./pkg/sqldriver
}

soak_suite() {
  full_suite

  section "Longer destructive soak matrix"
  run env VELOCITY_DESTRUCTIVE_SOAK_ITERS="${SOAK_ITERS}" go test -tags destructive -run 'TestDestructive' -count=1 -v .
  run env VELOCITY_DESTRUCTIVE_SOAK_ITERS="${SOAK_ITERS}" go test -tags destructive -run 'TestDestructive' -count=1 -v ./pkg/sqldriver

  if [[ "${RUN_MILLION}" == "1" ]]; then
    section "Opt-in million-row SQL workload"
    run go test -tags million ./pkg/sqldriver -run TestSQLDriver_MillionRowComplexWorkload -count=1 -v
  else
    echo
    echo "Skipping million-row workload. Set VELOCITY_RELIABILITY_MILLION=1 to include it."
  fi
}

race_suite() {
  section "Race detector: KV, WAL, reactive, production readiness"
  run go test -race -run 'TestProductionKV|TestProductionBackup|TestWAL|TestBatchWriter|TestWatch|TestRaceConditionStress' -count=1 .

  section "Race detector: SQL production and transactions"
  run go test -race ./pkg/sqldriver -run 'TestSQLDriver_Production|TestSQLDriver_Transaction|TestSQLDriver_ProductionSkipCloseFlushReplaysWAL' -count=1

  section "Race detector: focused packages"
  run go test -race ./pkg/kg ./pkg/s3 ./pkg/object ./pkg/storage -count=1
}

case "${TIER}" in
  quick)
    quick_suite
    ;;
  full)
    full_suite
    ;;
  soak)
    soak_suite
    ;;
  race)
    race_suite
    ;;
  *)
    echo "unknown reliability tier: ${TIER}" >&2
    echo "usage: $0 [quick|full|soak|race]" >&2
    echo "env: VELOCITY_RELIABILITY_TIER, VELOCITY_DESTRUCTIVE_SOAK_ITERS, VELOCITY_RELIABILITY_MILLION=1" >&2
    exit 2
    ;;
esac

echo
echo "Reliability suite '${TIER}' completed successfully."
