# search_and_kg

Demonstrates Velocity v2's `search` plugin end to end: full-text search
(term/negative-term/phrase queries), HNSW vector similarity search over
two obviously-separated clusters, a small knowledge graph with BFS
traversal at increasing depth, and the entity-extraction/resolution/
chunking text-mining surface (`api.EntityExtractionService`).

Run:

```sh
go run ./examples/search_and_kg
```

Expected: section 1 shows different result sets per query type; section 2
shows a fruit-like query vector's top-3 nearest neighbors are all fruits,
none vehicles; section 3 shows the reachable node set growing with depth;
section 4 lists extracted entities (email/URL/date/money/person/org
patterns — a regex-based NER, not a machine-learning model, matching v1's
real implementation), merges the two near-duplicate "acme corp" entities
while keeping "widget inc" separate, and splits a 300-word paragraph into
multiple word-bounded chunks.

Note: the pattern-based NER can produce overlapping/noisy matches (e.g. a
URL also matching a DOMAIN or FILE_PATH pattern) — this is real, ported
v1 behavior, not a bug introduced here.
