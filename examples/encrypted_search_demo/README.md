# Encrypted Search Demo

This example shows how to combine encrypted-at-rest records with searchable indexes.

It demonstrates:

- full-text search on selected fields
- hash-backed equality filters for sensitive values like email
- reopening the database and running the same query again
- verifying that plaintext names and emails are not written into SSTable files

## Run

```bash
cd examples/encrypted_search_demo
go run .
```

## What it does

The demo creates an encrypted database with a search schema for the `customers` prefix,
stores a few JSON records, closes the database to flush SSTables, checks the on-disk files
for leaked plaintext terms, then reopens the database and runs encrypted search queries.

The main query combines:

- full-text search on `name`
- hash-only equality on `email`
- hash-only equality on `region`
- numeric filtering on `spend`

Expected output includes:

```text
=== Encrypted Search Demo ===
Matching customer records: 1
- customers:1 => {"name":"Alice Johnson","email":"alice@acme.io","region":"emea","status":"active","spend":2400}

Active EMEA customer count: 2
Verified that plaintext names and emails do not appear in SSTable files.
Reopen-safe search confirmed with the same schema and master key.
```
