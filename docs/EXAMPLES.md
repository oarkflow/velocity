# Examples

Run examples from the repository root unless the example has its own module instructions.

```bash
go run ./examples/<name>
```

For inline Go snippets and matching command examples, see [Code And Command Cookbook](COOKBOOK.md).

For an executable end-to-end flow across the shipped CLI, wrapper, embedded Go APIs, SQL, objects/S3, secrets, envelopes, entities, knowledge graph, compliance, and focused tests, run:

```bash
./scripts/feature_full_flow.sh
```

For a focused knowledge graph walkthrough:

```bash
./scripts/knowledge_graph_demo.sh
```

That script demonstrates explicit KG ingestion, automatic indexing from normal KV, object, secret, SQL, envelope, and entity writes, and query-driven resource graph discovery.

## Storage And Search

- `examples/main/main.go`: basic embedded usage.
- `examples/kv_search_cookbook/main.go`: KV search cookbook.
- `examples/encrypted_search_demo/main.go`: encrypted search flow.
- `examples/fulltext_demo/main.go`: full-text search behavior.
- `examples/search_index_large_demo/main.go`: larger indexed search workload.
- `examples/tag_update_demo/main.go`: tag update behavior.
- `examples/multiple_tags_demo/main.go`: multiple compliance tags.

## SQL

- `examples/sql_demo/main.go`: introductory SQL.
- `examples/sql_crud_demo/main.go`: CRUD through the SQL driver.
- `examples/sql_complete_demo/main.go`: broader SQL walkthrough.
- `examples/sql_advanced_demo/main.go`: advanced SQL queries.
- `examples/sql_driver_cookbook/main.go`: driver cookbook.
- `examples/sql_million_demo/main.go`: large workload, controlled by `VELOCITY_SQL_MILLION_ROWS` and `VELOCITY_SQL_MILLION_CHUNK`.

## Objects, Folders, And S3

- `examples/object_storage_cookbook/main.go`: native object storage.
- `examples/folder_management_demo/main.go`: folder operations.
- `examples/hardened_object_workflow/main.go`: hardened object API.
- `examples/s3_demo/main.go`: S3-style object behavior.
- `examples/s3_bucket_cookbook/main.go`: bucket operations.

## Security, Keys, And Identity

- `examples/master_key_demo/main.go`: master key management.
- `examples/master_key_example/main.go`: master key example.
- `examples/interactive_key_demo/main.go`: interactive key workflow.
- `examples/security_auth/main.go`: authentication/security flow.
- `examples/identity_security_cookbook/main.go`: identity/security cookbook.
- `examples/secretr_exec_env_demo/main.go`: exec/env security demo.

## Compliance And Governance

- `examples/compliance_demo/main.go`: basic compliance features.
- `examples/compliance_full_demo/main.go`: full compliance flow.
- `examples/compliance_governance_cookbook/main.go`: governance cookbook.
- `examples/enterprise_compliance_demo/main.go`: enterprise compliance.
- `examples/production_features/main.go`: production-oriented features.

## Envelopes

- `examples/envelope_workflow/main.go`: envelope workflow.
- `examples/envelope_bundle_demo/main.go`: resource bundles.
- `examples/envelope_audit_chain_demo/main.go`: audit chain demo.

## Knowledge Graph And Entities

- `examples/kg_cookbook/main.go`: KG cookbook.
- `examples/kg_comprehensive_demo/main.go`: comprehensive KG ingestion, connectors, auto-indexing, graph, and cleanup walkthrough.
- `examples/kg_batch_demo/main.go`: batch ingestion.
- `examples/kg_ner_demo/main.go`: NER behavior.
- `examples/kg_search_demo/main.go`: KG search.
- `examples/kg_context_search_demo/main.go`: ontology taxonomy, persistent relations, and relation-aware context search.
- `examples/kg_realworld_scale_demo/main.go`: scalable real-world KG corpus with mixed KV, large object evidence, structured-file, SQL-style, envelope, entity, relation, and context-search workflows; supports 1M-record runs through environment variables.
- `examples/entity_data_demo/main.go`: entity-linked data.
- `examples/entity_relations_demo/main.go`: entity relations.
- `scripts/knowledge_graph_demo.sh`: end-to-end KG shell walkthrough, including automatic resource indexing.

## Backup And Configuration

- `examples/backup_resilience_cookbook/main.go`: backup/resilience workflows.
- `examples/config_cookbook/main.go`: configuration patterns.
- `examples/full_server/main.go`: server-style integration.
