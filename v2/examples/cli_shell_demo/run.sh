#!/usr/bin/env bash
# run.sh demonstrates every real subcommand of the Velocity v2 embedded CLI
# (v2/cmd/velocity) end to end: kv, secret, object, compliance, search.
#
# Run it from anywhere:
#   bash examples/cli_shell_demo/run.sh        (from the v2 module root)
#   ./run.sh                                    (from this directory)
#
# It resolves the v2 module root itself, builds the CLI once into a temp
# binary, boots it against a throwaway manifest + temp data directory for
# each command (the CLI is embedded: it boots the kernel, runs one command,
# and shuts down again — there is no long-running server here), and cleans
# up everything on exit.
set -euo pipefail

# Resolve the v2 module root regardless of the caller's cwd: this script
# lives at <v2>/examples/cli_shell_demo/run.sh.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
V2_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$V2_ROOT"

TMPDIR="$(mktemp -d)"
BIN="$TMPDIR/velocity-cli-demo"
MANIFEST="$TMPDIR/manifest.json"
DATA_DIR="$TMPDIR/data"

cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "=== Building the CLI ==="
go build -o "$BIN" ./cmd/velocity
echo "OK: built $BIN"

echo "=== Writing a throwaway manifest enabling only what these commands need ==="
mkdir -p "$DATA_DIR"
cat > "$MANIFEST" <<JSON
{
  "plugins": [
    {"name": "storage-lsm", "enabled": true, "config": {"dir": "$DATA_DIR", "always_sync": true}},
    {"name": "storage-mem", "enabled": false, "config": {}},
    {"name": "crypto-xchacha", "enabled": true, "config": {"key": "cli-shell-demo-fixed-32-byte-key"}},
    {"name": "crypto-fips", "enabled": false, "config": {}},
    {"name": "kv", "enabled": true, "config": {}},
    {"name": "object", "enabled": true, "config": {}},
    {"name": "secret", "enabled": true, "config": {}},
    {"name": "compliance", "enabled": true, "config": {}},
    {"name": "search", "enabled": true, "config": {}},
    {"name": "auth-jwt", "enabled": false, "config": {}},
    {"name": "auth-ldap", "enabled": false, "config": {}},
    {"name": "auth-oidc", "enabled": false, "config": {}},
    {"name": "auth-sts", "enabled": false, "config": {}},
    {"name": "auth-mfa", "enabled": false, "config": {}},
    {"name": "metrics", "enabled": false, "config": {}},
    {"name": "replication", "enabled": false, "config": {}},
    {"name": "sql", "enabled": false, "config": {}},
    {"name": "web", "enabled": false, "config": {}},
    {"name": "backup", "enabled": false, "config": {}},
    {"name": "envelope", "enabled": false, "config": {}},
    {"name": "erasure", "enabled": false, "config": {}},
    {"name": "notifications", "enabled": false, "config": {}},
    {"name": "lock", "enabled": false, "config": {}},
    {"name": "extractor", "enabled": false, "config": {}}
  ]
}
JSON
echo "OK: wrote $MANIFEST"

CLI() {
  "$BIN" --manifest "$MANIFEST" "$@"
}

echo "=== kv put ==="
CLI kv put greeting "hello from the CLI"
echo "OK: kv put"

echo "=== kv get ==="
GOT="$(CLI kv get greeting)"
echo "$GOT"
if [ "$GOT" != "hello from the CLI" ]; then
  echo "FAIL: kv get returned unexpected value: $GOT" >&2
  exit 1
fi
echo "OK: kv get round-tripped correctly"

echo "=== kv delete ==="
CLI kv delete greeting
echo "OK: kv delete"

echo "=== secret set ==="
CLI secret set db_password "s3cr3t-demo-value"
echo "OK: secret set"

echo "=== secret get (latest) ==="
GOT_SECRET="$(CLI secret get db_password)"
echo "$GOT_SECRET"
if [ "$GOT_SECRET" != "s3cr3t-demo-value" ]; then
  echo "FAIL: secret get returned unexpected value: $GOT_SECRET" >&2
  exit 1
fi
echo "OK: secret get round-tripped correctly"

echo "=== secret get (explicit version 1) ==="
CLI secret get db_password 1
echo "OK: secret get with explicit version"

echo "=== object put ==="
OBJ_SRC="$TMPDIR/hello.txt"
printf 'hello object storage' > "$OBJ_SRC"
CLI object put demo-bucket greeting.txt "$OBJ_SRC"
echo "OK: object put"

echo "=== object get ==="
OBJ_OUT="$TMPDIR/hello_out.txt"
CLI object get demo-bucket greeting.txt -o "$OBJ_OUT"
cat "$OBJ_OUT"
echo
if ! diff -q "$OBJ_SRC" "$OBJ_OUT" > /dev/null; then
  echo "FAIL: object get output does not match what was put" >&2
  exit 1
fi
echo "OK: object get round-tripped correctly"

echo "=== object list ==="
CLI object list demo-bucket
echo "OK: object list"

echo "=== compliance audit-verify ==="
CLI compliance audit-verify
echo "OK: compliance audit-verify"

echo "=== search index ==="
CLI search index doc1 '{"title":"hello world","body":"the quick brown fox"}'
CLI search index doc2 '{"title":"goodbye","body":"a slow red turtle"}'
echo "OK: search index"

echo "=== search query ==="
CLI search query "quick" 5
echo "OK: search query"

echo
echo "All CLI commands demonstrated successfully."
