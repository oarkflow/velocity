#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-${ROOT_DIR}/secretr}"
TEST_HOME="${TEST_HOME:-${ROOT_DIR}/.tmp_secretr_cli_home}"
WORK_DIR="${WORK_DIR:-${ROOT_DIR}/.tmp_secretr_cli_work}"
LOG_DIR="${LOG_DIR:-${ROOT_DIR}/.tmp_secretr_cli_logs}"
GO_CACHE_DIR="${GO_CACHE_DIR:-${ROOT_DIR}/.tmp_secretr_cli_gocache}"
SERVER_LOG="${LOG_DIR}/server.log"

PASS=0
FAIL=0
SKIP=0

export HOME="${TEST_HOME}"
export GOCACHE="${GO_CACHE_DIR}"
export SECRETR_ALLOW_INSECURE_PASSWORD_ENV="${SECRETR_ALLOW_INSECURE_PASSWORD_ENV:-true}"
export SECRETR_PASSWORD="${SECRETR_PASSWORD:-StrongPass123!}"
export SECRETR_PASSWORD_CONFIRM="${SECRETR_PASSWORD_CONFIRM:-StrongPass123!}"

ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.com}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_NAME="${ADMIN_NAME:-Admin User}"
USER2_EMAIL="${USER2_EMAIL:-user2@example.com}"

color() {
  local c="$1"
  local msg="$2"
  case "$c" in
    green) printf "\033[0;32m%s\033[0m\n" "$msg" ;;
    red) printf "\033[0;31m%s\033[0m\n" "$msg" ;;
    yellow) printf "\033[1;33m%s\033[0m\n" "$msg" ;;
    blue) printf "\033[0;34m%s\033[0m\n" "$msg" ;;
    *) printf "%s\n" "$msg" ;;
  esac
}

pass() { PASS=$((PASS + 1)); color green "[PASS] $*"; }
fail() { FAIL=$((FAIL + 1)); color red "[FAIL] $*"; }
skip() { SKIP=$((SKIP + 1)); color yellow "[SKIP] $*"; }

cleanup() {
  if [ -n "${SERVER_PID:-}" ]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

prepare() {
  rm -rf "${TEST_HOME}" "${WORK_DIR}" "${LOG_DIR}" "${GO_CACHE_DIR}"
  mkdir -p "${TEST_HOME}" "${WORK_DIR}" "${LOG_DIR}" "${GO_CACHE_DIR}"

  if [ ! -x "${BIN}" ]; then
    color blue "[setup] binary not found at ${BIN}; attempting build"
    if ! go build -o "${BIN}" "${ROOT_DIR}/cmd/secretr" >>"${LOG_DIR}/build.log" 2>&1; then
      color red "[fatal] failed to build binary. See ${LOG_DIR}/build.log"
      exit 1
    fi
  fi
}

run_ok() {
  local name="$1"
  shift
  local rc=0
  if "$@" >"${LOG_DIR}/${name}.out" 2>"${LOG_DIR}/${name}.err"; then
    pass "${name}"
    return 0
  fi
  rc=$?
  fail "${name} (exit=${rc})"
  tail -n 30 "${LOG_DIR}/${name}.err" | sed 's/^/  /'
  return 1
}

run_expect_fail() {
  local name="$1"
  local pattern="$2"
  shift 2
  if "$@" >"${LOG_DIR}/${name}.out" 2>"${LOG_DIR}/${name}.err"; then
    fail "${name} expected failure but command succeeded"
    return 1
  fi
  if grep -Eiq "${pattern}" "${LOG_DIR}/${name}.err" "${LOG_DIR}/${name}.out"; then
    pass "${name}"
    return 0
  fi
  fail "${name} failed but did not match expected pattern '${pattern}'"
  tail -n 30 "${LOG_DIR}/${name}.err" | sed 's/^/  /'
  return 1
}

try_cmd() {
  local name="$1"
  shift
  "$@" >"${LOG_DIR}/${name}.out" 2>"${LOG_DIR}/${name}.err"
}

has_top_command() {
  local cmd="$1"
  "${BIN}" --help 2>/dev/null | awk '/^COMMANDS:/{flag=1; next} /^GLOBAL OPTIONS:/{flag=0} flag{print $1}' | sed 's/,//' | grep -qx "${cmd}"
}

has_subcommand() {
  local parent="$1"
  local sub="$2"
  "${BIN}" "${parent}" --help 2>/dev/null | awk '/^COMMANDS:/{flag=1; next} /^OPTIONS:/{flag=0} flag{print $1}' | sed 's/,//' | grep -qx "${sub}"
}

test_help_surface() {
  color blue "[phase] command/help surface"
  run_ok root_help "${BIN}" --help || true
  run_ok root_version "${BIN}" --version || true

  while read -r cmd; do
    [ -z "${cmd}" ] && continue
    if [[ "${cmd}" == *: ]] || [[ "${cmd}" == "help" ]] || [[ "${cmd}" == "h" ]]; then
      continue
    fi
    run_ok "help_${cmd}" "${BIN}" "${cmd}" --help || true
  done < <("${BIN}" --help 2>/dev/null | awk '/^COMMANDS:/{flag=1; next} /^GLOBAL OPTIONS:/{flag=0} flag{print $1}' | sed 's/,//')
}

test_auth_gating() {
  color blue "[phase] auth gating"
  run_expect_fail unauth_secret_list "not logged in|No active session|unauthorized|Please login" "${BIN}" secret list || true
}

test_auth_flow() {
  color blue "[phase] auth flow"
  if has_subcommand auth init; then
    if try_cmd auth_init "${BIN}" auth init --username "${ADMIN_USERNAME}" --full-name "${ADMIN_NAME}" --email "${ADMIN_EMAIL}"; then
      pass "auth_init"
    elif grep -Eiq "already initialized|system already initialized" "${LOG_DIR}/auth_init.err" "${LOG_DIR}/auth_init.out"; then
      pass "auth_init (already initialized)"
    else
      if try_cmd auth_init_compat "${BIN}" auth init --name "${ADMIN_NAME}" --email "${ADMIN_EMAIL}"; then
        pass "auth_init_compat"
      elif grep -Eiq "already initialized|system already initialized" "${LOG_DIR}/auth_init_compat.err" "${LOG_DIR}/auth_init_compat.out"; then
        pass "auth_init_compat (already initialized)"
      else
        fail "auth_init and auth_init_compat both failed"
        tail -n 20 "${LOG_DIR}/auth_init.err" | sed 's/^/  /'
        tail -n 20 "${LOG_DIR}/auth_init_compat.err" | sed 's/^/  /'
      fi
    fi
  else
    skip "auth init missing"
  fi

  if has_subcommand auth login; then
    if try_cmd auth_login "${BIN}" auth login --username "${ADMIN_USERNAME}" --password "${SECRETR_PASSWORD}"; then
      pass "auth_login"
    elif grep -Eiq "already logged in" "${LOG_DIR}/auth_login.err" "${LOG_DIR}/auth_login.out"; then
      pass "auth_login (already logged in)"
    else
      if try_cmd auth_login_email "${BIN}" auth login --email "${ADMIN_EMAIL}" --password "${SECRETR_PASSWORD}"; then
        pass "auth_login_email"
      elif grep -Eiq "already logged in" "${LOG_DIR}/auth_login_email.err" "${LOG_DIR}/auth_login_email.out"; then
        pass "auth_login_email (already logged in)"
      else
        fail "auth_login and auth_login_email both failed"
        tail -n 20 "${LOG_DIR}/auth_login.err" | sed 's/^/  /'
        tail -n 20 "${LOG_DIR}/auth_login_email.err" | sed 's/^/  /'
      fi
    fi
  else
    skip "auth login missing"
  fi

  if has_subcommand auth status; then
    run_ok auth_status "${BIN}" auth status || true
  fi
}

ensure_logged_in() {
  if ! has_subcommand auth status; then
    return 0
  fi
  "${BIN}" auth status >"${LOG_DIR}/_auth_status.out" 2>"${LOG_DIR}/_auth_status.err" || true
  if grep -Eiq "not logged in|no active session" "${LOG_DIR}/_auth_status.out" "${LOG_DIR}/_auth_status.err"; then
    if has_subcommand auth login; then
      "${BIN}" auth login --email "${ADMIN_EMAIL}" --password "${SECRETR_PASSWORD}" >"${LOG_DIR}/_auth_relogin.out" 2>"${LOG_DIR}/_auth_relogin.err" || true
    fi
  fi
}

test_secret_workflow() {
  color blue "[phase] secret workflow"
  ensure_logged_in
  run_ok secret_set "${BIN}" secret set --name "test" --value "best" || true
  run_ok secret_get "${BIN}" secret get --name "test" || true
  run_ok secret_list "${BIN}" secret list || true
  if has_subcommand secret rotate; then
    run_ok secret_rotate "${BIN}" secret rotate --name "test" || true
  fi
  if has_subcommand secret delete; then
    run_ok secret_delete "${BIN}" --yes secret delete --name "test" || true
  fi
}

test_data_workflow() {
  color blue "[phase] data/object/folder workflow"
  ensure_logged_in
  if has_top_command data; then
    run_ok data_put "${BIN}" data put --key "smoke.key" --value "smoke.value" || true
    run_ok data_get "${BIN}" data get --key "smoke.key" || true
    run_ok data_list "${BIN}" data list || true
    run_ok data_delete "${BIN}" data delete --key "smoke.key" || true
  else
    skip "data command missing"
  fi

  if has_top_command object; then
    echo "hello object" > "${WORK_DIR}/sample.txt"
    run_ok object_put "${BIN}" object put --path "smoke/sample.txt" --file "${WORK_DIR}/sample.txt" || true
    run_ok object_list "${BIN}" object list || true
    run_ok object_get "${BIN}" object get --path "smoke/sample.txt" --output "${WORK_DIR}/downloaded.txt" || true
    run_ok object_delete "${BIN}" --yes object delete --path "smoke/sample.txt" || true
  else
    skip "object command missing"
  fi

  if has_top_command folder; then
    run_ok folder_create "${BIN}" folder create --path "smoke-folder" || true
    run_ok folder_list "${BIN}" folder list || true
  else
    skip "folder command missing"
  fi
}

test_core_ops() {
  color blue "[phase] key/identity/session/device/ops workflow"
  ensure_logged_in
  if has_top_command key; then
    run_ok key_generate "${BIN}" key generate --type encryption --purpose encrypt || true
    run_ok key_list "${BIN}" key list || true
  fi
  if has_top_command identity; then
    run_ok identity_create "${BIN}" identity create --name "User Two" --email "${USER2_EMAIL}" --type human --password "${SECRETR_PASSWORD}" || true
    run_ok identity_list "${BIN}" identity list || true
  fi
  if has_top_command session; then
    run_ok session_list "${BIN}" session list || true
  fi
  if has_top_command device; then
    run_ok device_list "${BIN}" device list || true
  fi
  if has_top_command backup; then
    run_ok backup_create "${BIN}" backup create --output "${WORK_DIR}/backup.backup" || true
    run_ok backup_list "${BIN}" backup list --directory "${WORK_DIR}" || true
  fi
  if has_top_command audit && has_subcommand audit query; then
    run_ok audit_query "${BIN}" audit query --limit 10 || true
  fi
  if has_top_command monitoring && has_subcommand monitoring dashboard; then
    if run_ok monitoring_dashboard "${BIN}" monitoring dashboard --period 24h; then
      :
    elif grep -Eiq "organization ID required|org-id" "${LOG_DIR}/monitoring_dashboard.err" "${LOG_DIR}/monitoring_dashboard.out"; then
      skip "monitoring dashboard requires org-id in this environment"
    fi
  fi
  if has_top_command alert && has_subcommand alert list; then
    run_ok alert_list "${BIN}" alert list || true
  fi
  if has_top_command org && has_subcommand org list; then
    run_ok org_list "${BIN}" org list || true
  fi
  if has_top_command compliance && has_subcommand compliance frameworks; then
    run_ok compliance_frameworks "${BIN}" compliance frameworks || true
  fi
}

test_api_health() {
  color blue "[phase] api health endpoints"
  if ! has_top_command admin || ! has_subcommand admin server; then
    skip "admin server command missing"
    return
  fi
  ensure_logged_in
  "${BIN}" admin server --addr "127.0.0.1:19090" >"${SERVER_LOG}" 2>&1 &
  SERVER_PID=$!
  sleep 2
  if ! kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    skip "admin server failed to start (see ${SERVER_LOG})"
    return
  fi
  if command -v curl >/dev/null 2>&1; then
    run_ok api_health curl -fsS "http://127.0.0.1:19090/health" || true
    run_ok api_ready curl -fsS "http://127.0.0.1:19090/ready" || true
  else
    skip "curl not found; skipped /health /ready checks"
  fi
  kill "${SERVER_PID}" >/dev/null 2>&1 || true
  wait "${SERVER_PID}" 2>/dev/null || true
  unset SERVER_PID
}

print_summary() {
  color blue "============================================================"
  color blue "Secretr CLI Comprehensive Test Summary"
  color blue "  Passed : ${PASS}"
  color blue "  Failed : ${FAIL}"
  color blue "  Skipped: ${SKIP}"
  color blue "  Logs   : ${LOG_DIR}"
  color blue "============================================================"
  [ "${FAIL}" -eq 0 ]
}

main() {
  prepare
  test_help_surface
  test_auth_gating
  test_auth_flow
  test_secret_workflow
  test_data_workflow
  test_core_ops
  test_api_health
  print_summary
}

main "$@"
