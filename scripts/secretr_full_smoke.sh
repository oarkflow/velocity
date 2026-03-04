#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/secretr"
TEST_HOME="${ROOT_DIR}/.tmp_secretr_smoke_home"
WORK_DIR="${ROOT_DIR}/.tmp_secretr_smoke_work"
GO_CACHE_DIR="${ROOT_DIR}/.tmp_secretr_go_cache"

echo "[smoke] building secretr binary"
go build -o "${BIN}" "${ROOT_DIR}/cmd/secretr"

rm -rf "${TEST_HOME}" "${WORK_DIR}" "${GO_CACHE_DIR}"
mkdir -p "${TEST_HOME}" "${WORK_DIR}" "${GO_CACHE_DIR}"

export HOME="${TEST_HOME}"
export GOCACHE="${GO_CACHE_DIR}"
export SECRETR_ALLOW_INSECURE_PASSWORD_ENV=true
export SECRETR_PASSWORD="StrongPass123!"
export SECRETR_PASSWORD_CONFIRM="StrongPass123!"

run() {
  echo "[smoke] $*"
  "$@"
}

run "${BIN}" auth init --name "Admin User" --email "admin@example.com"
run "${BIN}" auth login --email "admin@example.com"
run "${BIN}" auth status

run "${BIN}" secret set --name "test" --value "best"
run "${BIN}" secret get --name "test"
run "${BIN}" secret list
run "${BIN}" secret rotate --name "test"
run "${BIN}" secret delete --name "test" --yes

run "${BIN}" key generate --type encryption --purpose encrypt
run "${BIN}" key list

run "${BIN}" identity create --name "User Two" --email "user2@example.com" --type human --password "StrongPass123!"
run "${BIN}" identity list

echo "hello object" > "${WORK_DIR}/sample.txt"
run "${BIN}" object put --path "smoke/sample.txt" --file "${WORK_DIR}/sample.txt"
run "${BIN}" object list
run "${BIN}" object get --path "smoke/sample.txt" --output "${WORK_DIR}/downloaded.txt"
run "${BIN}" object delete --path "smoke/sample.txt" --yes

run "${BIN}" folder create --path "smoke-folder"
run "${BIN}" folder list

run "${BIN}" backup create --output "${WORK_DIR}/backup.backup"
run "${BIN}" backup list --directory "${WORK_DIR}"
run "${BIN}" backup schedule --cron "0 * * * *" --destination "${WORK_DIR}"

run "${BIN}" audit query --limit 10
run "${BIN}" compliance frameworks
run "${BIN}" monitoring dashboard --period 24h
run "${BIN}" alert list

run "${BIN}" org list
run "${BIN}" session list
run "${BIN}" device list

echo "[smoke] completed successfully"
