package api

// Counter, Gauge, and Histogram are minimal metric-instrument handles.
// Kept deliberately narrow so plugins/metrics can back them with any
// implementation (Prometheus client_golang, or a hand-rolled exposition
// format as v1's metrics.go did) without leaking that choice into every
// other plugin's code.
type Counter interface {
	Inc()
	Add(float64)
}

type Gauge interface {
	Set(float64)
}

type Histogram interface {
	Observe(float64)
}

// MetricsSink is the surface plugins/metrics exposes. Expose returns a
// scrape-ready body and its content type — ported from v1's metrics.go,
// which already emitted genuine Prometheus exposition format
// ("# HELP"/"# TYPE" lines, "text/plain; version=0.0.4").
type MetricsSink interface {
	Counter(name string, labels map[string]string) Counter
	Gauge(name string, labels map[string]string) Gauge
	Histogram(name string, labels map[string]string) Histogram
	Expose() (body []byte, contentType string)
}
