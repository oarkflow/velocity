# lock_and_extractor

Demonstrates two independent Velocity v2 plugins: the TTL-based `lock`
service (acquire, contention rejection, release, TTL expiry, re-acquire)
and the `extractor` content-extraction service (plain text, JSON, HTML,
CSV).

## Run

```sh
go run ./examples/lock_and_extractor
```

## Expected output

Lock section: a successful acquire, a rejected concurrent acquire on the
same key, release + re-acquire, then a 2-second TTL naturally expiring
(confirmed via `IsLocked`) followed by a fresh acquire with no explicit
release. Extractor section: `SupportedTypes()` followed by four
`Extract()` calls (plain text, JSON, HTML, CSV) each showing the extracted
text and metadata (e.g. CSV row/column counts).
