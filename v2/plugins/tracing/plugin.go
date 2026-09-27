// Package tracing implements the Velocity v2 "tracing" plugin: a real
// OpenTelemetry TracerProvider exposed as api.TracingService, exporting
// spans over OTLP/HTTP to any standard collector (Jaeger, Tempo, an
// OpenTelemetry Collector, ...) when configured, and a genuine no-op
// tracer (OpenTelemetry's own standard pattern) when it isn't — so
// calling code never needs an "is tracing enabled" branch of its own.
//
// Service name: "tracing". No dependencies — every other plugin depends
// on it optionally, never the reverse (same shape as plugins/metrics).
package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/oarkflow/velocity/v2/api"
)

// Plugin wires a *sdktrace.TracerProvider into the kernel under service
// name "tracing". When otlp_endpoint is empty, tracerProvider is left nil
// and every method call falls back to otel's global no-op tracer via
// oteltrace.NewNoopTracerProvider() — this is deliberate: it means a
// caller holding an api.TracingService never has to branch on whether
// tracing is actually configured.
type Plugin struct {
	endpoint    string
	serviceName string
	sampleRatio float64
	insecure    bool
	tp          *sdktrace.TracerProvider // nil when tracing is disabled
	tracer      oteltrace.Tracer
	log         api.Logger
}

// NewPlugin constructs the tracing plugin.
func NewPlugin() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string           { return "tracing" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return nil }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.log = k.Logger()
	cfg := k.Config().Scoped("tracing")
	p.endpoint = cfg.String("otlp_endpoint", "")
	p.serviceName = cfg.String("service_name", "velocity")
	p.sampleRatio = float64(cfg.Int("sample_ratio_percent", 100)) / 100.0
	// Duration/Bool accessors don't give us a clean float; read the raw
	// value if a caller supplied an actual float (e.g. 0.5) instead of
	// the percent-int convenience key above.
	if raw, ok := cfg.Raw()["sample_ratio"]; ok {
		switch v := raw.(type) {
		case float64:
			p.sampleRatio = v
		case int:
			p.sampleRatio = float64(v)
		}
	}
	if p.sampleRatio <= 0 {
		p.sampleRatio = 1.0
	}

	if p.endpoint == "" {
		// Disabled: use the real OpenTelemetry no-op tracer. Nothing is
		// exported, StartSpan/SetAttribute/RecordError all succeed and do
		// nothing observable, exactly OpenTelemetry's own standard
		// pattern for "tracing not configured."
		p.tracer = oteltrace.NewNoopTracerProvider().Tracer("velocity")
		return k.Registry().Provide("tracing", p)
	}

	exporter, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(p.endpoint))
	if err != nil {
		return fmt.Errorf("tracing: creating OTLP HTTP exporter: %w", err)
	}

	res, err := resource.New(ctx, resource.WithAttributes(
		semconv.ServiceNameKey.String(p.serviceName),
	))
	if err != nil {
		return fmt.Errorf("tracing: building resource: %w", err)
	}

	p.tp = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(p.sampleRatio))),
	)
	p.tracer = p.tp.Tracer("velocity")

	return k.Registry().Provide("tracing", p)
}

func (p *Plugin) Start(ctx context.Context) error { return nil }

func (p *Plugin) Stop(ctx context.Context) error {
	if p.tp == nil {
		return nil
	}
	return p.tp.Shutdown(ctx)
}

func (p *Plugin) Health() api.Health {
	if p.endpoint == "" {
		return api.Health{Status: "ok", Detail: "tracing disabled (no otlp_endpoint configured)"}
	}
	return api.Health{Status: "ok", Detail: "exporting to " + p.endpoint}
}

// StartSpan implements api.TracingService.
func (p *Plugin) StartSpan(ctx context.Context, name string) (context.Context, func()) {
	newCtx, span := p.tracer.Start(ctx, name)
	return newCtx, func() { span.End() }
}

// SetAttribute implements api.TracingService.
func (p *Plugin) SetAttribute(ctx context.Context, key string, value any) {
	span := oteltrace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}
	span.SetAttributes(toAttribute(key, value))
}

// RecordError implements api.TracingService.
func (p *Plugin) RecordError(ctx context.Context, err error) {
	if err == nil {
		return
	}
	span := oteltrace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

func toAttribute(key string, value any) attribute.KeyValue {
	switch v := value.(type) {
	case string:
		return attribute.String(key, v)
	case bool:
		return attribute.Bool(key, v)
	case int:
		return attribute.Int(key, v)
	case int64:
		return attribute.Int64(key, v)
	case float64:
		return attribute.Float64(key, v)
	default:
		return attribute.String(key, fmt.Sprintf("%v", v))
	}
}

var (
	_ api.Plugin         = (*Plugin)(nil)
	_ api.TracingService = (*Plugin)(nil)
)

// otel's global propagator/tracer registration is intentionally left
// untouched (no otel.SetTracerProvider call) — this plugin hands out its
// TracerProvider's Tracer directly via the api.TracingService interface
// rather than mutating global state, so multiple Velocity instances (or
// tests) in one process never fight over the global default.
var _ = otel.GetTracerProvider // referenced to document the deliberate non-use above
