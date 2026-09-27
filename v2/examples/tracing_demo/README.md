# tracing_demo

Demonstrates `api.TracingService` (`plugins/tracing`), backed by a real
OpenTelemetry `TracerProvider`.

Boots the kernel twice: first with `tracing` enabled but no `otlp_endpoint`
configured — a request through `web` still succeeds, using OpenTelemetry's
real no-op tracer (zero overhead, zero errors, no "is tracing on" branch
anywhere in calling code). Then again with `otlp_endpoint` pointed at a local
`httptest.Server` acting as a fake OTLP/HTTP collector — proves a real,
non-empty `application/x-protobuf` POST actually arrives after a traced
request, i.e. live span export works end to end, not just "the plugin boots".

Run: `go run ./examples/tracing_demo`
