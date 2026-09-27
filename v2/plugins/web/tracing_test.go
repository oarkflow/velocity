package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// fakeSpan/fakeTracer record enough of what traceRequest does to verify
// it end to end, without depending on plugins/tracing (which would be a
// package-boundary layering violation — web must only depend on the
// api.TracingService interface).
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

func TestTraceRequest_RecordsSpanWithAttributesAndStatus(t *testing.T) {
	reg := newFakeRegistry()
	reg.Provide("kv", newFakeKV())
	reg.Provide("object", newFakeObjectStore())
	tracer := &fakeTracer{}
	reg.Provide("tracing", tracer)

	k := &fakeKernel{reg: reg, cfg: &fakeConfig{data: map[string]any{}}, log: noopLogger{t: t}}
	p := NewPlugin("", "", "")
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if p.tracer == nil {
		t.Fatalf("expected p.tracer to be wired from the registered \"tracing\" service")
	}

	rt, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	srv := httptest.NewServer(rt.mux)
	defer srv.Close()

	// A successful request produces a span with no recorded error.
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/kv/foo", strings.NewReader("bar"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	tracer.mu.Lock()
	if len(tracer.spans) != 1 {
		tracer.mu.Unlock()
		t.Fatalf("expected exactly 1 span, got %d", len(tracer.spans))
	}
	successSpan := tracer.spans[0]
	tracer.mu.Unlock()

	if successSpan.attrs["name"] != "PUT /api/kv/{key}" {
		t.Errorf("expected span name %q, got %v", "PUT /api/kv/{key}", successSpan.attrs["name"])
	}
	if successSpan.attrs["http.method"] != "PUT" {
		t.Errorf("expected http.method attribute PUT, got %v", successSpan.attrs["http.method"])
	}
	if successSpan.attrs["http.status_code"] != http.StatusNoContent {
		t.Errorf("expected http.status_code %d, got %v", http.StatusNoContent, successSpan.attrs["http.status_code"])
	}
	if successSpan.err != nil {
		t.Errorf("expected no recorded error on a successful request, got %v", successSpan.err)
	}

	// A request hitting an unconfigured optional route (KG, since no
	// search.graph is registered in this test) returns 501, which must
	// mark its span as errored.
	resp, err = http.Get(srv.URL + "/api/kg/traverse/start-node")
	if err != nil {
		t.Fatalf("GET /api/kg/traverse: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected 501 from the unconfigured KG route, got %d", resp.StatusCode)
	}

	tracer.mu.Lock()
	defer tracer.mu.Unlock()
	if len(tracer.spans) != 2 {
		t.Fatalf("expected exactly 2 spans total, got %d", len(tracer.spans))
	}
	errSpan := tracer.spans[1]
	if errSpan.attrs["http.status_code"] != http.StatusNotImplemented {
		t.Errorf("expected http.status_code %d, got %v", http.StatusNotImplemented, errSpan.attrs["http.status_code"])
	}
	if errSpan.err == nil {
		t.Errorf("expected the 501 response to record an error on its span, got nil")
	}
}
