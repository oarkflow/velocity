package api

import "context"

// TracingService provides distributed-tracing spans backed by a real
// OpenTelemetry TracerProvider (see plugins/tracing), so a request that
// flows through multiple plugins (e.g. web -> kv -> compliance ->
// notifications, all via the event bus) can be followed as one trace in
// Jaeger/Tempo/any OTLP collector, instead of only correlated through
// logs. Service name: "tracing".
//
// When no "tracing" plugin is enabled, or when it's enabled with no
// "otlp_endpoint" configured, callers still get a working no-op
// TracingService (StartSpan/SetAttribute/RecordError all succeed and do
// nothing observable) — this mirrors OpenTelemetry's own standard
// no-op-tracer pattern, so calling code never needs an "is tracing
// enabled" check of its own.
type TracingService interface {
	// StartSpan begins a span named name, as a child of any span already
	// present in ctx (or a new root span if none). The caller MUST call
	// the returned end function exactly once, typically via defer,
	// when the traced operation completes.
	StartSpan(ctx context.Context, name string) (context.Context, func())

	// SetAttribute adds a key/value to the span currently in ctx, if any.
	// A ctx with no active span is a safe no-op.
	SetAttribute(ctx context.Context, key string, value any)

	// RecordError marks the span in ctx as failed and attaches err. A ctx
	// with no active span, or a nil err, is a safe no-op.
	RecordError(ctx context.Context, err error)
}
