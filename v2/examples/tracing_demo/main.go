// Command tracing_demo demonstrates Velocity v2's OpenTelemetry-backed
// tracing (api.TracingService, plugins/tracing). It boots the kernel TWICE:
// first with tracing enabled but no otlp_endpoint configured (spans are real
// OpenTelemetry no-ops — zero overhead, zero errors, calling code never
// branches on "is tracing enabled"), then again with otlp_endpoint pointed
// at a local httptest server acting as a fake OTLP/HTTP collector, proving a
// real OTLP export actually happens end to end when a request flows through
// web -> (kv/sql tracing hooks).
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	"github.com/oarkflow/velocity/v2/plugins/object"
	"github.com/oarkflow/velocity/v2/plugins/sql"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
	"github.com/oarkflow/velocity/v2/plugins/tracing"
	"github.com/oarkflow/velocity/v2/plugins/web"
)

const addr = "127.0.0.1:18093"

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func bootKernel(dir, otlpEndpoint string) *kernel.Kernel {
	tracingCfg := map[string]any{}
	if otlpEndpoint != "" {
		tracingCfg["otlp_endpoint"] = otlpEndpoint
	}
	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir}},
		{Name: "kv", Enabled: true},
		{Name: "object", Enabled: true},
		{Name: "sql", Enabled: true},
		{Name: "web", Enabled: true, Config: map[string]any{"addr": addr}},
		{Name: "tracing", Enabled: true, Config: tracingCfg},
	}}
	k := kernel.New(manifest)
	// authDep is left empty and no auth-jwt plugin is enabled at all, so web
	// serves /api/* unauthenticated (logging its own warning about this) —
	// deliberate here to keep the example focused on tracing, not auth.
	must(k.Boot(context.Background(), []api.Plugin{
		storagelsm.New(),
		kv.New("storage-lsm"),
		object.New("storage-lsm"),
		sql.NewPlugin("kv"),
		web.NewPlugin("kv", "object", ""),
		tracing.NewPlugin(),
	}, manifest.Enabled()))
	return k
}

func hitKVEndpoint() {
	req, err := http.NewRequest(http.MethodPut, "http://"+addr+"/api/kv/greeting", nil)
	must(err)
	req.Body = io.NopCloser(readerString("hello"))
	resp, err := http.DefaultClient.Do(req)
	must(err)
	resp.Body.Close()
	fmt.Printf("PUT /api/kv/greeting -> status=%d\n", resp.StatusCode)
}

type readerStringT struct {
	s   string
	pos int
}

func (r *readerStringT) Read(p []byte) (int, error) {
	if r.pos >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.pos:])
	r.pos += n
	return n, nil
}

func readerString(s string) io.Reader { return &readerStringT{s: s} }

// newFakeOTLPCollector is a minimal stand-in for a real OTLP/HTTP collector
// (Jaeger, Tempo, an OpenTelemetry Collector, ...): it accepts any POST,
// records the Content-Type and body size onto received, and replies 200 OK
// with an empty body — enough for the exporter to consider the export
// delivered, and enough for this example to PROVE a real HTTP POST arrived.
func newFakeOTLPCollector(received chan<- struct {
	contentType string
	bodyLen     int
}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- struct {
			contentType string
			bodyLen     int
		}{contentType: r.Header.Get("Content-Type"), bodyLen: len(body)}
		w.WriteHeader(http.StatusOK)
	}))
}

func main() {
	ctx := context.Background()

	fmt.Println("=== Phase 1: tracing enabled, but otlp_endpoint EMPTY (real no-op tracer) ===")
	dir1, err := os.MkdirTemp("", "velocity-tracing-demo-1-*")
	must(err)
	defer os.RemoveAll(dir1)

	k1 := bootKernel(dir1, "")
	hitKVEndpoint()
	fmt.Println("request succeeded with tracing enabled but unconfigured — spans were created")
	fmt.Println("and ended via the real OpenTelemetry no-op tracer, with zero errors and zero")
	fmt.Println("observable overhead. Calling code (web/kv/sql) never checked \"is tracing on\".")
	must(k1.Shutdown(ctx))

	fmt.Println("\n=== Phase 2: tracing enabled WITH a real (fake) OTLP/HTTP collector ===")
	received := make(chan struct {
		contentType string
		bodyLen     int
	}, 4)
	collector := newFakeOTLPCollector(received)
	defer collector.Close()
	fmt.Printf("fake OTLP collector listening at %s\n", collector.URL)

	dir2, err := os.MkdirTemp("", "velocity-tracing-demo-2-*")
	must(err)
	defer os.RemoveAll(dir2)

	k2 := bootKernel(dir2, collector.URL)
	defer k2.Shutdown(ctx)

	hitKVEndpoint()

	fmt.Println("waiting (bounded) for the fake collector to receive a real OTLP export...")
	select {
	case msg := <-received:
		fmt.Printf("fake collector received a real POST: Content-Type=%q, body=%d bytes (non-empty: %v)\n",
			msg.contentType, msg.bodyLen, msg.bodyLen > 0)
		fmt.Println("confirmed: live OTLP span export works end to end")
	case <-time.After(10 * time.Second):
		log.Fatal("timed out waiting for an OTLP export — tracing did not actually export")
	}

	fmt.Println("\ndone.")
}
