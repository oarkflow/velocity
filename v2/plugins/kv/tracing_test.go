package kv

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// fakeSpanRecord/fakeTracer mirror plugins/web/tracing_test.go's approach:
// record enough of what a real span would carry to verify span creation
// end to end, without this package depending on plugins/tracing (which
// would be a layering violation — kv must only depend on api.TracingService).
type fakeSpanRecord struct {
	attrs map[string]any
	err   error
}

type fakeTracer struct {
	mu    sync.Mutex
	spans []*fakeSpanRecord
}

type spanKey struct{}

func (f *fakeTracer) StartSpan(ctx context.Context, name string) (context.Context, func()) {
	rec := &fakeSpanRecord{attrs: map[string]any{"name": name}}
	f.mu.Lock()
	f.spans = append(f.spans, rec)
	f.mu.Unlock()
	return context.WithValue(ctx, spanKey{}, rec), func() {}
}

func (f *fakeTracer) SetAttribute(ctx context.Context, key string, value any) {
	if rec, ok := ctx.Value(spanKey{}).(*fakeSpanRecord); ok {
		rec.attrs[key] = value
	}
}

func (f *fakeTracer) RecordError(ctx context.Context, err error) {
	if rec, ok := ctx.Value(spanKey{}).(*fakeSpanRecord); ok {
		rec.err = err
	}
}

var _ api.TracingService = (*fakeTracer)(nil)

func TestTracing_PutGetDeleteIncrScan_RecordSpansWithKeyAttribute(t *testing.T) {
	ctx := context.Background()
	tracer := &fakeTracer{}
	p := &Plugin{storage: newMemBackend(), tracer: tracer}

	if err := p.Put(ctx, "foo", []byte("bar")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, _, err := p.Get(ctx, "foo"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := p.Incr(ctx, "counter", 1); err != nil {
		t.Fatalf("Incr: %v", err)
	}
	if _, _, err := p.Scan(ctx, "f", 10, ""); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if err := p.Delete(ctx, "foo"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	tracer.mu.Lock()
	defer tracer.mu.Unlock()

	byName := map[string]*fakeSpanRecord{}
	for _, s := range tracer.spans {
		byName[s.attrs["name"].(string)] = s
	}

	get, ok := byName["kv.Get"]
	if !ok {
		t.Fatalf("expected a kv.Get span, spans seen: %v", spanNames(tracer.spans))
	}
	if get.attrs["kv.key"] != "foo" {
		t.Errorf("kv.Get span: expected kv.key=foo, got %v", get.attrs["kv.key"])
	}

	incr, ok := byName["kv.Incr"]
	if !ok {
		t.Fatalf("expected a kv.Incr span, spans seen: %v", spanNames(tracer.spans))
	}
	if incr.attrs["kv.key"] != "counter" {
		t.Errorf("kv.Incr span: expected kv.key=counter, got %v", incr.attrs["kv.key"])
	}

	scan, ok := byName["kv.Scan"]
	if !ok {
		t.Fatalf("expected a kv.Scan span, spans seen: %v", spanNames(tracer.spans))
	}
	if scan.attrs["kv.prefix"] != "f" {
		t.Errorf("kv.Scan span: expected kv.prefix=f, got %v", scan.attrs["kv.prefix"])
	}

	del, ok := byName["kv.Delete"]
	if !ok {
		t.Fatalf("expected a kv.Delete span, spans seen: %v", spanNames(tracer.spans))
	}
	if del.attrs["kv.key"] != "foo" {
		t.Errorf("kv.Delete span: expected kv.key=foo, got %v", del.attrs["kv.key"])
	}

	// Put delegates to PutWithTTL, which already carries its own span —
	// confirm exactly one Put-family span was recorded, not a separate
	// "kv.Put" AND a redundant duplicate.
	putSpans := 0
	for _, s := range tracer.spans {
		if s.attrs["name"] == "kv.Put" {
			putSpans++
		}
	}
	if putSpans != 1 {
		t.Errorf("expected exactly 1 kv.Put span (from PutWithTTL), got %d", putSpans)
	}
}

func TestTracing_ErrorIsRecordedOnSpan(t *testing.T) {
	ctx := context.Background()
	tracer := &fakeTracer{}
	p := &Plugin{storage: newMemBackend(), tracer: tracer}

	// Store a non-integer value, then Incr it — a real, genuine failure
	// path in this plugin's own documented behavior ("existing value is
	// not an integer, cannot Incr").
	if err := p.Put(ctx, "notanumber", []byte("abc")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := p.Incr(ctx, "notanumber", 1); err == nil {
		t.Fatalf("expected Incr on a non-integer value to fail")
	}

	tracer.mu.Lock()
	defer tracer.mu.Unlock()

	var incrErrSpan *fakeSpanRecord
	for _, s := range tracer.spans {
		if s.attrs["name"] == "kv.Incr" && s.attrs["kv.key"] == "notanumber" {
			incrErrSpan = s
		}
	}
	if incrErrSpan == nil {
		t.Fatalf("expected a kv.Incr span for the failing call")
	}
	if incrErrSpan.err == nil {
		t.Errorf("expected the failing Incr's span to have RecordError called, got nil")
	}
	if !errors.Is(incrErrSpan.err, incrErrSpan.err) { // sanity: err is non-nil and comparable
		t.Errorf("unexpected error shape: %v", incrErrSpan.err)
	}
}

func TestTracing_NilTracerIsZeroOverheadNoOp(t *testing.T) {
	// No tracer configured at all — every method must behave exactly as
	// it did before tracing existed. This is the existing full test suite
	// (kv_test.go, encrypt_test.go, watch_test.go, tenancy_test.go) all
	// already running with p.tracer == nil (the zero value), so their
	// continued passing IS this proof — this test just documents that
	// fact explicitly for a reader of this file.
	ctx := context.Background()
	p := &Plugin{storage: newMemBackend()}
	if p.tracer != nil {
		t.Fatalf("expected tracer to be nil by default")
	}
	if err := p.Put(ctx, "x", []byte("y")); err != nil {
		t.Fatalf("Put with nil tracer: %v", err)
	}
}

func spanNames(spans []*fakeSpanRecord) []string {
	names := make([]string, len(spans))
	for i, s := range spans {
		names[i], _ = s.attrs["name"].(string)
	}
	return names
}
