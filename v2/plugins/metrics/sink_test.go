package metrics

import (
	"strings"
	"testing"
)

func TestExposeFormat(t *testing.T) {
	s := New()
	s.Counter("http_requests_total", map[string]string{"method": "GET", "route": "/api/kv/{key}", "status": "200"}).Inc()
	s.Counter("http_requests_total", map[string]string{"method": "GET", "route": "/api/kv/{key}", "status": "200"}).Add(2)
	s.Gauge("web_up", nil).Set(1)
	s.Histogram("http_request_duration_seconds", map[string]string{"route": "/api/kv/{key}"}).Observe(0.02)

	body, contentType := s.Expose()
	out := string(body)

	if contentType != "text/plain; version=0.0.4" {
		t.Fatalf("unexpected content type: %q", contentType)
	}

	mustContain := []string{
		"# HELP http_requests_total",
		"# TYPE http_requests_total counter",
		`http_requests_total{method="GET",route="/api/kv/{key}",status="200"} 3`,
		"# TYPE web_up gauge",
		"web_up 1",
		"# TYPE http_request_duration_seconds histogram",
		"http_request_duration_seconds_bucket{",
		`le="+Inf"`,
		"http_request_duration_seconds_sum{",
		"http_request_duration_seconds_count{",
	}
	for _, want := range mustContain {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestCounterAccumulatesAcrossLookups(t *testing.T) {
	s := New()
	labels := map[string]string{"a": "1"}
	s.Counter("x", labels).Inc()
	s.Counter("x", labels).Inc()
	body, _ := s.Expose()
	if !strings.Contains(string(body), `x{a="1"} 2`) {
		t.Fatalf("expected accumulated counter value 2, got:\n%s", body)
	}
}
