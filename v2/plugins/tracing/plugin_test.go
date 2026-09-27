package tracing

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
)

func bootTracing(t *testing.T, cfg map[string]any) (*Plugin, *kernel.Kernel) {
	t.Helper()
	m := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "tracing", Enabled: true, Config: cfg},
	}}
	k := kernel.New(m)
	p := NewPlugin()
	if err := k.Boot(context.Background(), []api.Plugin{p}, m.Enabled()); err != nil {
		t.Fatalf("Boot: %v", err)
	}
	t.Cleanup(func() { k.Shutdown(context.Background()) })
	return p, k
}

func TestDisabledByDefaultIsNoop(t *testing.T) {
	p, _ := bootTracing(t, nil)

	ctx, end := p.StartSpan(context.Background(), "op")
	p.SetAttribute(ctx, "key", "value")
	p.RecordError(ctx, nil)
	end() // must not panic, must not block

	if p.Health().Detail == "" {
		t.Fatalf("expected a health detail string")
	}
	if p.tp != nil {
		t.Fatalf("expected no real TracerProvider when otlp_endpoint is unset")
	}
}

func TestRealOTLPExport(t *testing.T) {
	var gotReq int32
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&gotReq, 1)
		gotContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		if len(body) == 0 {
			t.Errorf("expected a non-empty OTLP export body")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "tracing", Enabled: true, Config: map[string]any{
			"otlp_endpoint": srv.URL,
			"service_name":  "test-service",
		}},
	}}
	k := kernel.New(m)
	p := NewPlugin()
	if err := k.Boot(context.Background(), []api.Plugin{p}, m.Enabled()); err != nil {
		t.Fatalf("Boot: %v", err)
	}

	ctx, end := p.StartSpan(context.Background(), "traced-op")
	p.SetAttribute(ctx, "attr", "val")
	end()

	// Force flush by shutting the provider down, which flushes the batcher.
	if err := k.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt32(&gotReq) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if atomic.LoadInt32(&gotReq) == 0 {
		t.Fatalf("expected at least one OTLP export POST to the test receiver, got none")
	}
	if gotContentType == "" {
		t.Errorf("expected a Content-Type header on the OTLP export request")
	}
}

func TestSampleRatioConfig(t *testing.T) {
	p, _ := bootTracing(t, map[string]any{"sample_ratio": 0.5})
	if p.sampleRatio != 0.5 {
		t.Fatalf("expected sampleRatio 0.5, got %v", p.sampleRatio)
	}
}

func TestRecordErrorNilIsNoop(t *testing.T) {
	p, _ := bootTracing(t, nil)
	ctx, end := p.StartSpan(context.Background(), "op")
	defer end()
	p.RecordError(ctx, nil) // must not panic
}
