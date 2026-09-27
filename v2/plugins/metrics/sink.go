// Package metrics implements the Velocity v2 "metrics" plugin: a
// dependency-free MetricsSink that emits genuine Prometheus exposition
// format, ported from v1's metrics.go (which already emitted real
// "# HELP"/"# TYPE" lines and "text/plain; version=0.0.4"). Every other
// plugin obtains this via k.Registry().Lookup("metrics") — nothing here
// depends on any other plugin.
package metrics

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/oarkflow/velocity/v2/api"
)

// defaultHistogramBuckets mirrors Prometheus's default client bucket set,
// which is a reasonable general-purpose choice for request-duration-style
// observations (seconds).
var defaultHistogramBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

type metricKind int

const (
	kindCounter metricKind = iota
	kindGauge
	kindHistogram
)

// series is one label-combination's worth of state for a metric name.
type series struct {
	labels map[string]string

	mu sync.Mutex
	// counter/gauge
	value float64
	// histogram
	bucketCounts []uint64 // parallel to buckets
	sum          float64
	count        uint64
}

type metricFamily struct {
	kind    metricKind
	buckets []float64 // histogram only

	mu       sync.Mutex
	seriesBy map[string]*series // keyed by canonical label string
}

// Sink is the default api.MetricsSink implementation.
type Sink struct {
	mu       sync.Mutex
	families map[string]*metricFamily
	histBkts []float64
}

// New constructs an empty Sink. Safe for concurrent use.
func New() *Sink {
	return &Sink{
		families: make(map[string]*metricFamily),
		histBkts: defaultHistogramBuckets,
	}
}

func canonicalLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(labels[k])
	}
	return b.String()
}

func (s *Sink) family(name string, kind metricKind) *metricFamily {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.families[name]
	if !ok {
		f = &metricFamily{kind: kind, buckets: s.histBkts, seriesBy: make(map[string]*series)}
		s.families[name] = f
	}
	return f
}

func (f *metricFamily) get(labels map[string]string) *series {
	key := canonicalLabels(labels)
	f.mu.Lock()
	defer f.mu.Unlock()
	sr, ok := f.seriesBy[key]
	if !ok {
		sr = &series{labels: labels, bucketCounts: make([]uint64, len(f.buckets))}
		f.seriesBy[key] = sr
	}
	return sr
}

// --- Counter ---

type counterHandle struct{ s *series }

func (c counterHandle) Inc() { c.Add(1) }
func (c counterHandle) Add(delta float64) {
	c.s.mu.Lock()
	c.s.value += delta
	c.s.mu.Unlock()
}

func (s *Sink) Counter(name string, labels map[string]string) api.Counter {
	return counterHandle{s: s.family(name, kindCounter).get(labels)}
}

// --- Gauge ---

type gaugeHandle struct{ s *series }

func (g gaugeHandle) Set(v float64) {
	g.s.mu.Lock()
	g.s.value = v
	g.s.mu.Unlock()
}

func (s *Sink) Gauge(name string, labels map[string]string) api.Gauge {
	return gaugeHandle{s: s.family(name, kindGauge).get(labels)}
}

// --- Histogram ---

type histogramHandle struct {
	s       *series
	buckets []float64
}

func (h histogramHandle) Observe(v float64) {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	h.s.sum += v
	h.s.count++
	for i, ub := range h.buckets {
		if v <= ub {
			h.s.bucketCounts[i]++
		}
	}
}

func (s *Sink) Histogram(name string, labels map[string]string) api.Histogram {
	f := s.family(name, kindHistogram)
	return histogramHandle{s: f.get(labels), buckets: f.buckets}
}

var _ api.MetricsSink = (*Sink)(nil)

// Expose renders every tracked metric in Prometheus text exposition
// format (https://prometheus.io/docs/instrumenting/exposition_formats/).
func (s *Sink) Expose() (body []byte, contentType string) {
	s.mu.Lock()
	names := make([]string, 0, len(s.families))
	for name := range s.families {
		names = append(names, name)
	}
	sort.Strings(names)
	fams := make(map[string]*metricFamily, len(s.families))
	for k, v := range s.families {
		fams[k] = v
	}
	s.mu.Unlock()

	var b strings.Builder
	for _, name := range names {
		f := fams[name]
		switch f.kind {
		case kindCounter:
			fmt.Fprintf(&b, "# HELP %s %s total\n", name, name)
			fmt.Fprintf(&b, "# TYPE %s counter\n", name)
		case kindGauge:
			fmt.Fprintf(&b, "# HELP %s %s current value\n", name, name)
			fmt.Fprintf(&b, "# TYPE %s gauge\n", name)
		case kindHistogram:
			fmt.Fprintf(&b, "# HELP %s %s distribution\n", name, name)
			fmt.Fprintf(&b, "# TYPE %s histogram\n", name)
		}

		f.mu.Lock()
		keys := make([]string, 0, len(f.seriesBy))
		for k := range f.seriesBy {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			sr := f.seriesBy[key]
			labelStr := formatLabels(sr.labels)
			sr.mu.Lock()
			switch f.kind {
			case kindCounter, kindGauge:
				fmt.Fprintf(&b, "%s%s %s\n", name, labelStr, formatFloat(sr.value))
			case kindHistogram:
				cumulative := uint64(0)
				for i, ub := range f.buckets {
					cumulative += sr.bucketCounts[i]
					fmt.Fprintf(&b, "%s_bucket%s %d\n", name, mergeLabel(sr.labels, "le", formatFloat(ub)), cumulative)
				}
				fmt.Fprintf(&b, "%s_bucket%s %d\n", name, mergeLabel(sr.labels, "le", "+Inf"), sr.count)
				fmt.Fprintf(&b, "%s_sum%s %s\n", name, labelStr, formatFloat(sr.sum))
				fmt.Fprintf(&b, "%s_count%s %d\n", name, labelStr, sr.count)
			}
			sr.mu.Unlock()
		}
		f.mu.Unlock()
	}
	return []byte(b.String()), "text/plain; version=0.0.4"
}

func formatFloat(v float64) string {
	if math.IsInf(v, 1) {
		return "+Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%q", k, labels[k]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func mergeLabel(labels map[string]string, extraKey, extraVal string) string {
	merged := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		merged[k] = v
	}
	merged[extraKey] = extraVal
	return formatLabels(merged)
}
