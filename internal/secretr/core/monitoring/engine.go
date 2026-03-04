// Package monitoring provides real-time monitoring and event streaming.
package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

// EventType represents the type of monitoring event
type EventType string

const (
	EventTypeAccess     EventType = "access"
	EventTypeAuth       EventType = "auth"
	EventTypePolicy     EventType = "policy"
	EventTypeSecret     EventType = "secret"
	EventTypeFile       EventType = "file"
	EventTypeIncident   EventType = "incident"
	EventTypeCompliance EventType = "compliance"
	EventTypeRisk       EventType = "risk"
	EventTypeAnomaly    EventType = "anomaly"
)

// Event represents a monitoring event
type Event struct {
	ID         types.ID       `json:"id"`
	Type       EventType      `json:"type"`
	Severity   string         `json:"severity"` // info, warning, error, critical
	Source     string         `json:"source"`
	Action     string         `json:"action"`
	ActorID    types.ID       `json:"actor_id,omitempty"`
	ResourceID types.ID       `json:"resource_id,omitempty"`
	Timestamp  time.Time      `json:"timestamp"`
	Details    types.Metadata `json:"details,omitempty"`
	OrgID      types.ID       `json:"org_id,omitempty"`
}

// Engine provides monitoring functionality
type Engine struct {
	mu          sync.RWMutex
	store       *storage.Store
	crypto      *crypto.Engine
	auditEngine *audit.Engine
	eventStore  *storage.TypedStore[Event]
	subscribers map[string]chan *Event
	eventBus    chan *Event
	stopCh      chan struct{}
}

// EngineConfig configures the monitoring engine
type EngineConfig struct {
	Store       *storage.Store
	AuditEngine *audit.Engine
}

// NewEngine creates a new monitoring engine
func NewEngine(cfg EngineConfig) *Engine {
	e := &Engine{
		store:       cfg.Store,
		crypto:      crypto.NewEngine(""),
		auditEngine: cfg.AuditEngine,
		eventStore:  storage.NewTypedStore[Event](cfg.Store, "monitoring_events"),
		subscribers: make(map[string]chan *Event),
		eventBus:    make(chan *Event, 1000),
		stopCh:      make(chan struct{}),
	}

	// Subscribe to audit events
	if e.auditEngine != nil {
		e.auditEngine.Subscribe(func(ae *types.AuditEvent) {
			id := types.ID("")
			if ae.ResourceID != nil {
				id = *ae.ResourceID
			}
			details := ae.Details
			if details == nil {
				details = make(types.Metadata)
			}
			if ae.Success {
				details["success"] = 1.0
			} else {
				details["success"] = 0.0
			}
			// Add risk score if present in metadata or calculate basic
			if _, ok := details["risk_score"]; !ok {
				if !ae.Success {
					details["risk_score"] = 50.0
				} else {
					details["risk_score"] = 0.0
				}
			}

			_ = e.Emit(&Event{
				ID:         ae.ID,
				Type:       EventType(ae.Type),
				Severity:   severityFromAudit(ae),
				Source:     fmt.Sprintf("%s:%s", ae.ResourceType, ae.Action),
				Action:     ae.Action,
				ActorID:    ae.ActorID,
				ResourceID: id,
				Timestamp:  ae.Timestamp.Time(),
				Details:    details,
			})
		})
	}

	// Start event dispatcher
	go e.dispatchEvents()

	return e
}

func severityFromAudit(ae *types.AuditEvent) string {
	if !ae.Success {
		return "warning"
	}
	if ae.Type == "incident" {
		return "critical"
	}
	if ae.Type == "policy" && strings.HasPrefix(ae.Action, "violation") {
		return "error"
	}
	return "info"
}

// dispatchEvents dispatches events to subscribers
func (e *Engine) dispatchEvents() {
	for {
		select {
		case event := <-e.eventBus:
			e.mu.RLock()
			for _, ch := range e.subscribers {
				select {
				case ch <- event:
				default:
					// Channel full, skip
				}
			}
			e.mu.RUnlock()
		case <-e.stopCh:
			return
		}
	}
}

// Subscribe subscribes to events
func (e *Engine) Subscribe(id string, filter EventFilter) <-chan *Event {
	ch := make(chan *Event, 100)

	e.mu.Lock()
	e.subscribers[id] = ch
	e.mu.Unlock()

	return ch
}

// EventFilter defines event filtering criteria
type EventFilter struct {
	Types    []EventType `json:"types,omitempty"`
	Severity []string    `json:"severity,omitempty"`
	ActorIDs []types.ID  `json:"actor_ids,omitempty"`
	OrgID    types.ID    `json:"org_id,omitempty"`
}

// Unsubscribe unsubscribes from events
func (e *Engine) Unsubscribe(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if ch, ok := e.subscribers[id]; ok {
		close(ch)
		delete(e.subscribers, id)
	}
}

// Emit emits a new event
func (e *Engine) Emit(event *Event) error {
	if event.ID == "" {
		id, err := e.crypto.GenerateRandomID()
		if err != nil {
			return err
		}
		event.ID = id
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Store event
	ctx := context.Background()
	if err := e.eventStore.Set(ctx, string(event.ID), event); err != nil {
		return err
	}

	// Publish to subscribers
	select {
	case e.eventBus <- event:
	default:
		// Bus full
	}

	return nil
}

// Query queries events
func (e *Engine) Query(ctx context.Context, opts QueryOptions) ([]*Event, error) {
	events, err := e.eventStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var filtered []*Event
	for _, event := range events {
		// Apply filters
		if len(opts.Types) > 0 {
			match := false
			for _, t := range opts.Types {
				if event.Type == t {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		if opts.OrgID != "" && event.OrgID != opts.OrgID {
			continue
		}

		if opts.ActorID != "" && event.ActorID != opts.ActorID {
			continue
		}

		if !opts.StartTime.IsZero() && event.Timestamp.Before(opts.StartTime) {
			continue
		}

		if !opts.EndTime.IsZero() && event.Timestamp.After(opts.EndTime) {
			continue
		}

		filtered = append(filtered, event)
	}

	// Sort by timestamp descending
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp.After(filtered[j].Timestamp)
	})

	// Apply limit
	if opts.Limit > 0 && len(filtered) > opts.Limit {
		filtered = filtered[:opts.Limit]
	}

	return filtered, nil
}

// QueryOptions holds query options
type QueryOptions struct {
	Types     []EventType
	OrgID     types.ID
	ActorID   types.ID
	StartTime time.Time
	EndTime   time.Time
	Limit     int
}

// GetDashboardData returns dashboard data
func (e *Engine) GetDashboardData(ctx context.Context, orgID types.ID, opts DashboardOptions) (*DashboardData, error) {
	if opts.Period == nil {
		defaultPeriod := 7 * 24 * time.Hour
		opts.Period = &defaultPeriod
	}

	startTime := time.Now().Add(-*opts.Period)

	events, err := e.Query(ctx, QueryOptions{
		OrgID:     orgID,
		StartTime: startTime,
	})
	if err != nil {
		return nil, err
	}

	data := &DashboardData{
		GeneratedAt:    time.Now(),
		Period:         *opts.Period,
		EventCounts:    make(map[EventType]int),
		SeverityCounts: make(map[string]int),
	}

	// Count by type
	for _, event := range events {
		data.TotalEvents++
		data.EventCounts[event.Type]++
		data.SeverityCounts[event.Severity]++
	}

	// Get secret usage heatmap
	data.SecretUsageHeatmap = e.computeSecretHeatmap(ctx, events)

	// Get file access metrics
	data.FileAccessMetrics = e.computeFileMetrics(ctx, events)

	// Get top actors
	data.TopActors = e.computeTopActors(events)

	// Get geo distribution
	data.GeoDistribution = e.computeGeoDistribution(ctx, events)

	// Get hourly distribution
	data.HourlyDistribution = e.computeHourlyDistribution(events)

	// Get risk trends
	data.RiskTrends = e.computeRiskTrends(ctx, events)

	return data, nil
}

// DashboardOptions holds dashboard options
type DashboardOptions struct {
	Period *time.Duration `json:"period,omitempty"`
}

// DashboardData represents dashboard data
type DashboardData struct {
	GeneratedAt        time.Time          `json:"generated_at"`
	Period             time.Duration      `json:"period"`
	TotalEvents        int                `json:"total_events"`
	EventCounts        map[EventType]int  `json:"event_counts"`
	SeverityCounts     map[string]int     `json:"severity_counts"`
	SecretUsageHeatmap *HeatmapData       `json:"secret_usage_heatmap,omitempty"`
	FileAccessMetrics  *FileAccessMetrics `json:"file_access_metrics,omitempty"`
	TopActors          []ActorMetrics     `json:"top_actors,omitempty"`
	GeoDistribution    map[string]int     `json:"geo_distribution,omitempty"`
	HourlyDistribution [24]int            `json:"hourly_distribution"`
	RiskTrends         []RiskTrendPoint   `json:"risk_trends,omitempty"`
}

// HeatmapData represents secret usage heatmap
type HeatmapData struct {
	Data   [][]int  `json:"data"` // [day][hour]
	Labels []string `json:"labels"`
}

// FileAccessMetrics represents file access metrics
type FileAccessMetrics struct {
	TotalAccesses   int   `json:"total_accesses"`
	UniqueFiles     int   `json:"unique_files"`
	TotalDownloads  int   `json:"total_downloads"`
	TotalUploads    int   `json:"total_uploads"`
	AverageFileSize int64 `json:"average_file_size"`
}

// ActorMetrics represents actor activity metrics
type ActorMetrics struct {
	ActorID     types.ID  `json:"actor_id"`
	ActionCount int       `json:"action_count"`
	LastActive  time.Time `json:"last_active"`
}

// RiskTrendPoint represents a point in risk trends
type RiskTrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	RiskScore float64   `json:"risk_score"`
	Events    int       `json:"events"`
}

// computeSecretHeatmap computes secret usage heatmap
func (e *Engine) computeSecretHeatmap(_ context.Context, events []*Event) *HeatmapData {
	heatmap := &HeatmapData{
		Data:   make([][]int, 7),
		Labels: []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"},
	}

	for i := range heatmap.Data {
		heatmap.Data[i] = make([]int, 24)
	}

	for _, event := range events {
		if event.Type == EventTypeSecret {
			day := int(event.Timestamp.Weekday())
			hour := event.Timestamp.Hour()
			heatmap.Data[day][hour]++
		}
	}

	return heatmap
}

// computeFileMetrics computes file access metrics
func (e *Engine) computeFileMetrics(_ context.Context, events []*Event) *FileAccessMetrics {
	metrics := &FileAccessMetrics{}
	fileSet := make(map[types.ID]bool)

	for _, event := range events {
		if event.Type == EventTypeFile {
			metrics.TotalAccesses++
			fileSet[event.ResourceID] = true

			if event.Action == "download" {
				metrics.TotalDownloads++
			} else if event.Action == "upload" {
				metrics.TotalUploads++
			}
		}
	}

	metrics.UniqueFiles = len(fileSet)

	return metrics
}

// computeTopActors computes top actors by activity
func (e *Engine) computeTopActors(events []*Event) []ActorMetrics {
	actorCounts := make(map[types.ID]*ActorMetrics)

	for _, event := range events {
		if event.ActorID == "" {
			continue
		}

		if _, ok := actorCounts[event.ActorID]; !ok {
			actorCounts[event.ActorID] = &ActorMetrics{
				ActorID: event.ActorID,
			}
		}

		actorCounts[event.ActorID].ActionCount++
		if event.Timestamp.After(actorCounts[event.ActorID].LastActive) {
			actorCounts[event.ActorID].LastActive = event.Timestamp
		}
	}

	var actors []ActorMetrics
	for _, a := range actorCounts {
		actors = append(actors, *a)
	}

	sort.Slice(actors, func(i, j int) bool {
		return actors[i].ActionCount > actors[j].ActionCount
	})

	if len(actors) > 10 {
		actors = actors[:10]
	}

	return actors
}

// computeGeoDistribution computes geographic distribution
func (e *Engine) computeGeoDistribution(_ context.Context, events []*Event) map[string]int {
	geo := make(map[string]int)

	for _, event := range events {
		if event.Details != nil {
			if country, ok := event.Details["country"].(string); ok {
				geo[country]++
			}
		}
	}

	return geo
}

// computeHourlyDistribution computes hourly distribution
func (e *Engine) computeHourlyDistribution(events []*Event) [24]int {
	var dist [24]int

	for _, event := range events {
		dist[event.Timestamp.Hour()]++
	}

	return dist
}

// computeRiskTrends computes risk trends
func (e *Engine) computeRiskTrends(_ context.Context, events []*Event) []RiskTrendPoint {
	// Group by day
	dayMap := make(map[string]*RiskTrendPoint)

	for _, event := range events {
		day := event.Timestamp.Format("2006-01-02")
		if _, ok := dayMap[day]; !ok {
			dayMap[day] = &RiskTrendPoint{
				Timestamp: event.Timestamp.Truncate(24 * time.Hour),
			}
		}

		dayMap[day].Events++

		// Aggregate risk scores if present
		if event.Details != nil {
			if risk, ok := event.Details["risk_score"].(float64); ok {
				dayMap[day].RiskScore = (dayMap[day].RiskScore + risk) / 2
			}
		}
	}

	var trends []RiskTrendPoint
	for _, t := range dayMap {
		trends = append(trends, *t)
	}

	sort.Slice(trends, func(i, j int) bool {
		return trends[i].Timestamp.Before(trends[j].Timestamp)
	})

	return trends
}

// GetUserBehaviorAnalysis returns behavior analysis for a user
func (e *Engine) GetUserBehaviorAnalysis(ctx context.Context, identityID types.ID) (*BehaviorAnalysis, error) {
	events, err := e.Query(ctx, QueryOptions{
		ActorID: identityID,
		Limit:   1000,
	})
	if err != nil {
		return nil, err
	}

	analysis := &BehaviorAnalysis{
		IdentityID: identityID,
		AnalyzedAt: time.Now(),
		EventCount: len(events),
	}

	if len(events) == 0 {
		return analysis, nil
	}

	// Compute metrics
	analysis.FirstActivity = events[len(events)-1].Timestamp
	analysis.LastActivity = events[0].Timestamp

	// Action breakdown
	analysis.ActionBreakdown = make(map[string]int)
	for _, event := range events {
		analysis.ActionBreakdown[event.Action]++
	}

	// Resource access patterns
	resourceCounts := make(map[types.ID]int)
	for _, event := range events {
		if event.ResourceID != "" {
			resourceCounts[event.ResourceID]++
		}
	}
	analysis.UniqueResourcesAccessed = len(resourceCounts)

	// Average daily activity
	days := analysis.LastActivity.Sub(analysis.FirstActivity).Hours() / 24
	if days > 0 {
		analysis.AvgDailyActivity = float64(len(events)) / days
	}

	return analysis, nil
}

// BehaviorAnalysis represents user behavior analysis
type BehaviorAnalysis struct {
	IdentityID              types.ID       `json:"identity_id"`
	AnalyzedAt              time.Time      `json:"analyzed_at"`
	EventCount              int            `json:"event_count"`
	FirstActivity           time.Time      `json:"first_activity"`
	LastActivity            time.Time      `json:"last_activity"`
	ActionBreakdown         map[string]int `json:"action_breakdown"`
	UniqueResourcesAccessed int            `json:"unique_resources_accessed"`
	AvgDailyActivity        float64        `json:"avg_daily_activity"`
	RiskScore               float64        `json:"risk_score,omitempty"`
	Anomalies               []string       `json:"anomalies,omitempty"`
}

// ExportEvents exports events as JSON
func (e *Engine) ExportEvents(ctx context.Context, opts QueryOptions) ([]byte, error) {
	events, err := e.Query(ctx, opts)
	if err != nil {
		return nil, err
	}

	return json.Marshal(events)
}

// Close cleans up resources
func (e *Engine) Close() error {
	close(e.stopCh)
	return e.crypto.Close()
}
