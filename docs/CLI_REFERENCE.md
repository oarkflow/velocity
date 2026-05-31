# CLI Reference

Velocity currently has two CLI-related code paths.

## Shipped Minimal CLI

The binary built from `cmd/velocity` is a small manual CLI:

```bash
go build -o velocity ./cmd/velocity
```

Environment:

- `VELOCITY_PATH`: database path, default `./velocity_data`.

Commands:

```text
velocity data put <key> <value>
velocity data get <key>
velocity secret set <name> <value>
velocity secret get <name>
velocity object put <key>
velocity object get <key>
velocity object preview <file> [object-path]
velocity envelope create --label L
velocity envelope get --id ID
velocity envelope export --id ID --path PATH
velocity envelope import --path PATH
velocity envelope bundle create --label L --resource JSON
velocity envelope bundle list --id ID
velocity envelope bundle resolve --id ID
velocity compliance tag --type TYPE [resource flags] --framework GDPR --class restricted
velocity compliance get --type TYPE [resource flags]
velocity compliance check --type TYPE [resource flags] --operation read --actor alice
```

Examples:

```bash
VELOCITY_PATH=./velocity_data ./velocity data put mykey myvalue
VELOCITY_PATH=./velocity_data ./velocity data get mykey
VELOCITY_PATH=./velocity_data ./velocity secret set api_key sk_12345
VELOCITY_PATH=./velocity_data ./velocity object preview ./README.md docs/readme.md
VELOCITY_PATH=./velocity_data ./velocity compliance tag --type secret --name api-key --framework GDPR --class confidential --encrypt
VELOCITY_PATH=./velocity_data ./velocity compliance tag --type sql_column --table patients --column ssn --framework HIPAA --class restricted --encrypt
```

Compliance resource types:

- `kv`: use `--path`.
- `object`: use `--path`.
- `bucket`: use `--bucket`.
- `folder`: use `--path`.
- `secret`: use `--name`.
- `secret_version`: use `--name` and `--version`.
- `sql_schema`: use optional `--schema`, default `main`.
- `sql_table`: use `--table` and optional `--schema`.
- `sql_column`: use `--table`, `--column`, and optional `--schema`.
- `sql_row`: use `--table`, `--row`, and optional `--schema`.

## Wrapper Script

`scripts/velocity.sh` dispatches to the same command families and uses:

- `VELOCITY_BIN`, default `./scripts/velocity`
- `VELOCITY_PATH`, default `./velocity_data`

The default `VELOCITY_BIN` in the script does not match the usual `go build -o velocity ./cmd/velocity` output unless adjusted.

Compliance wrapper example:

```bash
go build -o ./velocity ./cmd/velocity
VELOCITY_BIN=./velocity VELOCITY_PATH=./velocity_data \
  ./scripts/velocity.sh compliance tag --type secret --name api-key --framework GDPR --class confidential --encrypt
```

## Full Compliance Flow Script

`scripts/compliance_full_flow.sh` builds the shipped CLI, tags every supported resource type, checks inherited tags, runs a generated Go API flow for KV/object/secret/SQL enforcement, and executes the focused compliance tests.

Run:

```bash
./scripts/compliance_full_flow.sh
```

Keep the temporary database and generated Go program for inspection:

```bash
KEEP_COMPLIANCE_FLOW=1 ./scripts/compliance_full_flow.sh
```

## Full Feature Flow Script

`scripts/feature_full_flow.sh` is the broad executable walkthrough. It runs shipped CLI commands, wrapper dispatch, generated Go API examples, the compliance flow, and focused validation suites for the major feature families.

Run:

```bash
./scripts/feature_full_flow.sh
```

Or through the wrapper:

```bash
./scripts/velocity.sh demo full
```

Run only the knowledge graph walkthrough:

```bash
./scripts/velocity.sh demo kg
```

The KG walkthrough covers explicit ingestion plus automatic indexing from ordinary KV, object, secret, SQL, envelope, and entity writes.

## Knowledge Graph Commands

The shipped `cmd/velocity` binary includes a compact KG command family:

```bash
velocity kg ingest --source notes.md --file ./notes.md --media-type text/markdown
velocity kg import --connector local_file --path ./docs --format text
velocity kg import --connector structured_file --file ./customers.csv --table customers
velocity kg search "retention policy" --limit 10
velocity kg search "retention policy" --format text
velocity kg graph "CASE-12345" --depth 1 --format text
velocity kg materialize "CASE-12345" --limit 10 --format text
velocity kg relation create --source service:api --target table:customers --type depends_on --evidence "api reads customers"
velocity kg relation list --source service:api --format text
velocity kg query --seed service:api --depth 2 --format text
velocity kg path --source service:api --target table:customers --format text
velocity kg ontology apply --file ./ontology.json
velocity kg entity propose-merge --target person:alice --sources person:alice-old --reason "same employee id"
velocity kg entity approve-merge --id merge-...
velocity kg entity resolve person:alice-old
velocity kg job start --connector local_file --path ./docs
velocity kg job start --connector local_file --path ./docs --async
velocity kg job list --status succeeded
velocity kg job cancel --id job-...
velocity kg mutations --limit 50
velocity kg rebuild
velocity kg sync
velocity kg status
velocity kg analytics
velocity kg ner list
velocity kg ner add --type CUSTOMER_ID --pattern 'CUST-\d+' --confidence 0.9
```

JSON is the default output for automation. Search, graph, and analytics commands also support `--format text`.

Keep its temporary database and generated Go program:

```bash
KEEP_FEATURE_FLOW=1 ./scripts/feature_full_flow.sh
```

## Rich Command Framework

`pkg/cli` contains a richer command framework built on `github.com/urfave/cli/v3`. It includes command builders for:

- `backup`
- `data`
- `envelope`
- `folder`
- `object`
- `secret`

Those command implementations include many more flags and subcommands than `cmd/velocity`, including backup create/restore/export/import/verify/audit, indexed data operations, folder copy/rename/view, object list/info/view, and secret rotation.

The current source does not show this `pkg/cli` registry wired into the shipped `cmd/velocity` binary. Treat it as a reusable/internal CLI framework until an entrypoint connects it.
