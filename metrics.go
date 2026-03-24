package velocity

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Counter: a monotonically increasing value with optional labels.
// ---------------------------------------------------------------------------

// counterKey is the map key for a labeled counter.
type counterKey struct {
	name   string
	labels string // sorted label pairs encoded as "k1=v1,k2=v2"
}

// counterValue holds the atomic value and original label map for rendering.
type counterValue struct {
	value  atomic.Int64
	labels map[string]string
}

// ---------------------------------------------------------------------------
// Gauge: a value that can go up and down.
// ---------------------------------------------------------------------------

type gaugeEntry struct {
	value  atomic.Int64
	labels map[string]string
}

// ---------------------------------------------------------------------------
// Histogram: a simple histogram with predefined buckets.
// ---------------------------------------------------------------------------

// Histogram tracks observations in a set of cumulative buckets plus a sum
// and count. All operations are goroutine-safe via atomic operations and a
// lightweight mutex for bucket writes.
type Histogram struct {
	name    string
	help    string
	buckets []float64 // upper bounds, sorted ascending

	mu     sync.Mutex
	counts []atomic.Int64 // one per bucket (cumulative)
	count  atomic.Int64
	sum    atomic.Int64 // stored as float64 bits
}

// NewHistogram creates a histogram with the given sorted bucket boundaries.
func NewHistogram(name, help string, buckets []float64) *Histogram {
	sorted := make([]float64, len(buckets))
	copy(sorted, buckets)
	sort.Float64s(sorted)
	h := &Histogram{
		name:    name,
		help:    help,
		buckets: sorted,
		counts:  make([]atomic.Int64, len(sorted)),
	}
	return h
}

// Observe records a single observation.
func (h *Histogram) Observe(v float64) {
	h.count.Add(1)

	// Atomically add v to sum (stored as float64 bits).
	for {
		old := h.sum.Load()
		oldF := math.Float64frombits(uint64(old))
		newF := oldF + v
		newBits := int64(math.Float64bits(newF))
		if h.sum.CompareAndSwap(old, newBits) {
			break
		}
	}

	for i, bound := range h.buckets {
		if v <= bound {
			h.counts[i].Add(1)
		}
	}
}

// render writes Prometheus exposition lines into the builder.
func (h *Histogram) render(sb *strings.Builder) {
	fmt.Fprintf(sb, "# HELP %s %s\n", h.name, h.help)
	fmt.Fprintf(sb, "# TYPE %s histogram\n", h.name)

	// Cumulative counts for each bucket.
	var cumulative int64
	for i, bound := range h.buckets {
		cumulative += h.counts[i].Load()
		fmt.Fprintf(sb, "%s_bucket{le=\"%s\"} %d\n", h.name, formatFloat(bound), cumulative)
	}
	// +Inf bucket
	total := h.count.Load()
	fmt.Fprintf(sb, "%s_bucket{le=\"+Inf\"} %d\n", h.name, total)

	sumBits := uint64(h.sum.Load())
	sumF := math.Float64frombits(sumBits)
	fmt.Fprintf(sb, "%s_sum %s\n", h.name, formatFloat(sumF))
	fmt.Fprintf(sb, "%s_count %d\n", h.name, total)
}

// ---------------------------------------------------------------------------
// MetricsCollector: the central registry of all Velocity metrics.
// ---------------------------------------------------------------------------

// MetricsCollector provides Prometheus-compatible metrics without depending
// on an external client library. All counters use sync/atomic for lock-free
// thread safety.
type MetricsCollector struct {
	// Labeled counters keyed by (name, encoded-labels).
	counters   sync.Map // counterKey -> *counterValue
	countersMu sync.Mutex

	// Gauges keyed by name (no labels needed for these system gauges).
	gauges   sync.Map // string -> *gaugeEntry
	gaugesMu sync.Mutex

	// Histograms
	requestDuration *Histogram

	// Metadata for HELP / TYPE lines, populated at creation.
	metricHelp map[string]string
	metricType map[string]string
}

// NewMetricsCollector initialises a MetricsCollector with the standard
// Velocity metric definitions.
func NewMetricsCollector() *MetricsCollector {
	mc := &MetricsCollector{
		requestDuration: NewHistogram(
			"velocity_request_duration_seconds",
			"Histogram of request durations in seconds",
			[]float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		),
		metricHelp: map[string]string{
			"velocity_requests_total":              "Total number of requests processed",
			"velocity_request_duration_seconds":     "Histogram of request durations in seconds",
			"velocity_objects_total":                "Current number of stored objects",
			"velocity_bytes_stored_total":           "Current total bytes stored",
			"velocity_replication_pending":          "Number of pending replication tasks",
			"velocity_replication_replicated":       "Number of successfully replicated objects",
			"velocity_replication_failed":           "Number of failed replication attempts",
			"velocity_replication_bytes_transferred": "Bytes transferred via replication",
			"velocity_cluster_nodes_total":          "Number of active cluster nodes",
			"velocity_bitrot_scans_total":           "Total number of bit-rot scan operations",
			"velocity_healing_operations_total":     "Total number of healing operations",
			"velocity_transport_messages_sent":      "Total transport messages sent",
			"velocity_transport_messages_received":  "Total transport messages received",
		},
		metricType: map[string]string{
			"velocity_requests_total":              "counter",
			"velocity_request_duration_seconds":     "histogram",
			"velocity_objects_total":                "gauge",
			"velocity_bytes_stored_total":           "gauge",
			"velocity_replication_pending":          "gauge",
			"velocity_replication_replicated":       "gauge",
			"velocity_replication_failed":           "gauge",
			"velocity_replication_bytes_transferred": "gauge",
			"velocity_cluster_nodes_total":          "gauge",
			"velocity_bitrot_scans_total":           "counter",
			"velocity_healing_operations_total":     "counter",
			"velocity_transport_messages_sent":      "counter",
			"velocity_transport_messages_received":  "counter",
		},
	}
	return mc
}

// ---------------------------------------------------------------------------
// Counter helpers
// ---------------------------------------------------------------------------

// encodeLabels produces a deterministic string from a label map so it can be
// used as part of a map key.
func encodeLabels(labels map[string]string) string {
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
		parts = append(parts, k+"="+labels[k])
	}
	return strings.Join(parts, ",")
}

// getOrCreateCounter returns the counterValue for a named metric with the
// given labels, creating it on first access.
func (mc *MetricsCollector) getOrCreateCounter(name string, labels map[string]string) *counterValue {
	key := counterKey{name: name, labels: encodeLabels(labels)}
	if v, ok := mc.counters.Load(key); ok {
		return v.(*counterValue)
	}

	mc.countersMu.Lock()
	defer mc.countersMu.Unlock()

	// Double-check after lock.
	if v, ok := mc.counters.Load(key); ok {
		return v.(*counterValue)
	}

	cv := &counterValue{labels: labels}
	mc.counters.Store(key, cv)
	return cv
}

// IncrementCounter atomically increments a labeled counter by 1.
func (mc *MetricsCollector) IncrementCounter(name string, labels map[string]string) {
	mc.getOrCreateCounter(name, labels).value.Add(1)
}

// AddCounter atomically adds delta to a labeled counter.
func (mc *MetricsCollector) AddCounter(name string, labels map[string]string, delta int64) {
	mc.getOrCreateCounter(name, labels).value.Add(delta)
}

// ---------------------------------------------------------------------------
// Gauge helpers
// ---------------------------------------------------------------------------

// getOrCreateGauge returns the gaugeEntry for a named metric, creating it on
// first access.
func (mc *MetricsCollector) getOrCreateGauge(name string, labels map[string]string) *gaugeEntry {
	key := name + "{" + encodeLabels(labels) + "}"
	if v, ok := mc.gauges.Load(key); ok {
		return v.(*gaugeEntry)
	}

	mc.gaugesMu.Lock()
	defer mc.gaugesMu.Unlock()

	if v, ok := mc.gauges.Load(key); ok {
		return v.(*gaugeEntry)
	}

	g := &gaugeEntry{labels: labels}
	mc.gauges.Store(key, g)
	return g
}

// SetGauge atomically sets a gauge to the given value.
func (mc *MetricsCollector) SetGauge(name string, labels map[string]string, value int64) {
	mc.getOrCreateGauge(name, labels).value.Store(value)
}

// ---------------------------------------------------------------------------
// RecordRequest records a single API request.
// ---------------------------------------------------------------------------

// RecordRequest atomically records an API request: it increments the
// velocity_requests_total counter with method/status labels and observes the
// duration in the request-duration histogram.
func (mc *MetricsCollector) RecordRequest(method, status string, duration time.Duration) {
	labels := map[string]string{
		"method": method,
		"status": status,
	}
	mc.IncrementCounter("velocity_requests_total", labels)
	mc.requestDuration.Observe(duration.Seconds())
}

// ---------------------------------------------------------------------------
// UpdateGauges refreshes gauge metrics from live subsystem state.
// ---------------------------------------------------------------------------

// UpdateGauges queries the DB, ClusterManager, ReplicationManager, and
// IntegrityManager to refresh all gauge-style metrics. Any nil parameter is
// silently skipped.
func (mc *MetricsCollector) UpdateGauges(db *DB, cluster *ClusterManager, repl *ReplicationManager, integrity *IntegrityManager) {
	// Object and byte counts from the database.
	if db != nil {
		var objectCount int64
		var bytesStored int64

		_ = db.Scan([]byte(ObjectMetaPrefix), func(key, value []byte) bool {
			var meta ObjectMetadata
			if err := json.Unmarshal(value, &meta); err == nil {
				objectCount++
				bytesStored += meta.Size
			}
			return true // continue scanning
		})

		mc.SetGauge("velocity_objects_total", nil, objectCount)
		mc.SetGauge("velocity_bytes_stored_total", nil, bytesStored)
	}

	// Cluster node count.
	if cluster != nil {
		mc.SetGauge("velocity_cluster_nodes_total", nil, int64(cluster.NodeCount()))
	}

	// Replication statistics.
	if repl != nil {
		stats := repl.GetStats()
		mc.SetGauge("velocity_replication_pending", nil, stats.Pending)
		mc.SetGauge("velocity_replication_replicated", nil, stats.Replicated)
		mc.SetGauge("velocity_replication_failed", nil, stats.Failed)
		mc.SetGauge("velocity_replication_bytes_transferred", nil, stats.BytesTransferred)
	}

	// Integrity / bit-rot / healing statistics.
	if integrity != nil {
		status := integrity.Status()
		if status != nil {
			mc.SetGauge("velocity_bitrot_scans_total", nil, status.BitRot.ObjectsScanned)
			mc.SetGauge("velocity_healing_operations_total", nil, status.Healing.ObjectsHealed)
		}
	}
}

// UpdateTransportMetrics refreshes transport counters from a NodeTransport.
func (mc *MetricsCollector) UpdateTransportMetrics(transport *NodeTransport) {
	if transport == nil {
		return
	}
	stats := transport.Stats()
	mc.SetGauge("velocity_transport_messages_sent", nil, stats.MessagesSent)
	mc.SetGauge("velocity_transport_messages_received", nil, stats.MessagesReceived)
}

// ---------------------------------------------------------------------------
// RenderMetrics produces the full Prometheus text exposition format output.
// ---------------------------------------------------------------------------

// RenderMetrics returns all registered metrics formatted in the Prometheus
// text exposition format (version 0.0.4). The output is suitable for serving
// on a /metrics HTTP endpoint.
func (mc *MetricsCollector) RenderMetrics() string {
	var sb strings.Builder

	// -- Counters (grouped by metric name) --------------------------------

	// Collect all counter entries grouped by name.
	type counterEntry struct {
		name   string
		labels map[string]string
		value  int64
	}
	grouped := make(map[string][]counterEntry)

	mc.counters.Range(func(k, v any) bool {
		ck := k.(counterKey)
		cv := v.(*counterValue)
		grouped[ck.name] = append(grouped[ck.name], counterEntry{
			name:   ck.name,
			labels: cv.labels,
			value:  cv.value.Load(),
		})
		return true
	})

	// Sort metric names for deterministic output.
	counterNames := make([]string, 0, len(grouped))
	for name := range grouped {
		counterNames = append(counterNames, name)
	}
	sort.Strings(counterNames)

	for _, name := range counterNames {
		entries := grouped[name]
		if help, ok := mc.metricHelp[name]; ok {
			fmt.Fprintf(&sb, "# HELP %s %s\n", name, help)
		}
		if typ, ok := mc.metricType[name]; ok {
			fmt.Fprintf(&sb, "# TYPE %s %s\n", name, typ)
		}
		// Sort entries by encoded labels for deterministic output.
		sort.Slice(entries, func(i, j int) bool {
			return encodeLabels(entries[i].labels) < encodeLabels(entries[j].labels)
		})
		for _, e := range entries {
			fmt.Fprintf(&sb, "%s%s %d\n", name, formatLabels(e.labels), e.value)
		}
		sb.WriteString("\n")
	}

	// -- Gauges -----------------------------------------------------------

	type gaugeRenderEntry struct {
		name   string
		labels map[string]string
		value  int64
	}
	gaugeGrouped := make(map[string][]gaugeRenderEntry)

	mc.gauges.Range(func(k, v any) bool {
		key := k.(string)
		g := v.(*gaugeEntry)
		// Recover metric name from the stored key "name{encoded}".
		name := key
		if idx := strings.Index(key, "{"); idx >= 0 {
			name = key[:idx]
		}
		gaugeGrouped[name] = append(gaugeGrouped[name], gaugeRenderEntry{
			name:   name,
			labels: g.labels,
			value:  g.value.Load(),
		})
		return true
	})

	gaugeNames := make([]string, 0, len(gaugeGrouped))
	for name := range gaugeGrouped {
		gaugeNames = append(gaugeNames, name)
	}
	sort.Strings(gaugeNames)

	for _, name := range gaugeNames {
		entries := gaugeGrouped[name]
		if help, ok := mc.metricHelp[name]; ok {
			fmt.Fprintf(&sb, "# HELP %s %s\n", name, help)
		}
		if typ, ok := mc.metricType[name]; ok {
			fmt.Fprintf(&sb, "# TYPE %s %s\n", name, typ)
		}
		sort.Slice(entries, func(i, j int) bool {
			return encodeLabels(entries[i].labels) < encodeLabels(entries[j].labels)
		})
		for _, e := range entries {
			fmt.Fprintf(&sb, "%s%s %d\n", name, formatLabels(e.labels), e.value)
		}
		sb.WriteString("\n")
	}

	// -- Histogram --------------------------------------------------------

	mc.requestDuration.render(&sb)
	sb.WriteString("\n")

	return sb.String()
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

// formatLabels converts a label map to the Prometheus label string
// e.g. {method="GET",status="200"}.
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

// formatFloat renders a float64 in a way that is compatible with the
// Prometheus exposition format (no trailing zeros, no scientific notation
// for reasonable values).
func formatFloat(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%g", f)
	}
	return fmt.Sprintf("%g", f)
}
