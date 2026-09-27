package object

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// fakeSpanRecord/fakeTracer mirror plugins/web/tracing_test.go's approach:
// record enough of what a real span would carry to verify span creation
// end to end, without this package depending on plugins/tracing (which
// would be a layering violation — object must only depend on
// api.TracingService).
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

func newTracedTestPlugin(tracer api.TracingService) *Plugin {
	return &Plugin{
		storage:           newMemBackend(),
		stopCh:            make(chan struct{}),
		lifecycleInterval: time.Minute,
		tracer:            tracer,
	}
}

func TestTracing_PutGetDeleteListObject_RecordSpansWithBucketKeyAttributes(t *testing.T) {
	ctx := context.Background()
	tracer := &fakeTracer{}
	p := newTracedTestPlugin(tracer)

	if err := p.CreateBucket(ctx, "docs"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if _, err := p.PutObject(ctx, "docs", "readme.txt", strings.NewReader("hello"), api.ObjectMeta{}); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if _, _, err := p.GetObject(ctx, "docs", "readme.txt", ""); err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	if _, err := p.ListObjects(ctx, "docs", ""); err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if err := p.DeleteObject(ctx, "docs", "readme.txt", "", false); err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}

	tracer.mu.Lock()
	defer tracer.mu.Unlock()

	byName := map[string]*fakeSpanRecord{}
	for _, s := range tracer.spans {
		byName[s.attrs["name"].(string)] = s
	}

	put, ok := byName["object.PutObject"]
	if !ok {
		t.Fatalf("expected an object.PutObject span, spans seen: %v", spanNames(tracer.spans))
	}
	if put.attrs["object.bucket"] != "docs" || put.attrs["object.key"] != "readme.txt" {
		t.Errorf("object.PutObject span: unexpected attrs %v", put.attrs)
	}

	get, ok := byName["object.GetObject"]
	if !ok {
		t.Fatalf("expected an object.GetObject span, spans seen: %v", spanNames(tracer.spans))
	}
	if get.attrs["object.bucket"] != "docs" || get.attrs["object.key"] != "readme.txt" {
		t.Errorf("object.GetObject span: unexpected attrs %v", get.attrs)
	}

	list, ok := byName["object.ListObjects"]
	if !ok {
		t.Fatalf("expected an object.ListObjects span, spans seen: %v", spanNames(tracer.spans))
	}
	if list.attrs["object.bucket"] != "docs" {
		t.Errorf("object.ListObjects span: unexpected attrs %v", list.attrs)
	}

	del, ok := byName["object.DeleteObject"]
	if !ok {
		t.Fatalf("expected an object.DeleteObject span, spans seen: %v", spanNames(tracer.spans))
	}
	if del.attrs["object.bucket"] != "docs" || del.attrs["object.key"] != "readme.txt" {
		t.Errorf("object.DeleteObject span: unexpected attrs %v", del.attrs)
	}
}

func TestTracing_ErrorIsRecordedOnSpan(t *testing.T) {
	ctx := context.Background()
	tracer := &fakeTracer{}
	p := newTracedTestPlugin(tracer)

	if err := p.CreateBucket(ctx, "docs"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	// GetObject on a genuinely missing object is a real, documented error
	// path (ErrObjectNotFound), not a "not found, no error" convention
	// like kv.Get — verified by reading object.go directly.
	if _, _, err := p.GetObject(ctx, "docs", "does-not-exist.txt", ""); err == nil {
		t.Fatalf("expected GetObject on a missing key to return an error")
	}

	tracer.mu.Lock()
	defer tracer.mu.Unlock()

	var errSpan *fakeSpanRecord
	for _, s := range tracer.spans {
		if s.attrs["name"] == "object.GetObject" {
			errSpan = s
		}
	}
	if errSpan == nil {
		t.Fatalf("expected an object.GetObject span for the failing call")
	}
	if errSpan.err == nil {
		t.Errorf("expected the failing GetObject's span to have RecordError called, got nil")
	}
}

func TestTracing_NilTracerIsZeroOverheadNoOp(t *testing.T) {
	// No tracer configured at all — every method must behave exactly as
	// it did before tracing existed. This is the existing full test suite
	// (object_test.go, encrypt_test.go, watch_test.go, tenancy_test.go,
	// range_erasure_test.go, concurrency_test.go) all already running
	// with p.tracer == nil (the zero value), so their continued passing
	// IS this proof — this test just documents that fact explicitly.
	ctx := context.Background()
	p := newTestPlugin()
	if p.tracer != nil {
		t.Fatalf("expected tracer to be nil by default")
	}
	if err := p.CreateBucket(ctx, "b"); err != nil {
		t.Fatalf("CreateBucket with nil tracer: %v", err)
	}
}

func spanNames(spans []*fakeSpanRecord) []string {
	names := make([]string, len(spans))
	for i, s := range spans {
		names[i], _ = s.attrs["name"].(string)
	}
	return names
}
