#!/bin/bash

VELOCITY_BIN="${VELOCITY_BIN:-./scripts/velocity}"
VELOCITY_PATH="${VELOCITY_PATH:-./velocity_data}"

export VELOCITY_PATH

cmd="$1"
shift

case "$cmd" in
  data)
    subcmd="$1"; shift
    "$VELOCITY_BIN" data "$subcmd" "$@"
    ;;
  secret)
    subcmd="$1"; shift
    "$VELOCITY_BIN" secret "$subcmd" "$@"
    ;;
  object)
    subcmd="$1"; shift
    "$VELOCITY_BIN" object "$subcmd" "$@"
    ;;
  envelope)
    subcmd="$1"; shift
    "$VELOCITY_BIN" envelope "$subcmd" "$@"
    ;;
  help|--help|-h)
    cat <<EOF
Velocity CLI Wrapper

Usage: velocity <command> [arguments]

Commands:
  data put <key> <value>      Store a key-value pair
  data get <key>            Retrieve a value
  secret set <name> <value>  Store a secret
  secret get <name>        Retrieve a secret
  object put <key>          Store an object
  object get <key>          Retrieve an object
  envelope create --label L   Create an envelope
  envelope get --id ID       Get envelope details
  envelope export --id ID --path PATH  Export envelope
  envelope import --path PATH        Import envelope
  envelope bundle create --label L --resource JSON  Create bundle
  envelope bundle list --id ID          List resources
  envelope bundle resolve --id ID        Resolve resources

Environment:
  VELOCITY_PATH   Database path (default: ./velocity_data)
  VELOCITY_BIN   Binary path (default: ./cmd/velocity)

Examples:
  velocity data put mykey myvalue
  velocity data get mykey
  velocity secret set api_key sk_12345
  velocity envelope create --label "Case 001" --type court_evidence
  velocity envelope bundle create --label "Evidence" --resource '[{"type":"file","name":"doc.pdf"}]'
EOF
    ;;
  *)
    echo "Unknown command: $cmd"
    echo "Use 'velocity help' for usage information"
    exit 1
    ;;
esac