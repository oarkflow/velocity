package velocity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// EventType represents the type of notification event.
type EventType string

// Event type constants for object and bucket lifecycle events.
const (
	ObjectCreated  EventType = "s3:ObjectCreated:*"
	ObjectRemoved  EventType = "s3:ObjectRemoved:*"
	ObjectAccessed EventType = "s3:ObjectAccessed:*"
	BucketCreated  EventType = "s3:BucketCreated"
	BucketRemoved  EventType = "s3:BucketRemoved"
)

// DB key prefix for notification configurations.
const notifyConfigPrefix = "notify:config:"

// TargetType identifies the delivery mechanism for a notification target.
type TargetType int

const (
	// TargetWebhook delivers events via HTTP POST.
	TargetWebhook TargetType = iota
	// TargetCallback delivers events via an in-process function call.
	TargetCallback
)

// NotificationEvent is the payload delivered for each qualifying event.
type NotificationEvent struct {
	EventType    EventType `json:"event_type"`
	Bucket       string    `json:"bucket"`
	Key          string    `json:"key,omitempty"`
	Size         int64     `json:"size,omitempty"`
	ETag         string    `json:"etag,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
	UserIdentity string    `json:"user_identity,omitempty"`
	SourceIP     string    `json:"source_ip,omitempty"`
	RequestID    string    `json:"request_id,omitempty"`
}

// NotificationConfig describes which events on a bucket should trigger
// delivery and how to filter them by key prefix/suffix.
type NotificationConfig struct {
	ID           string      `json:"id"`
	Events       []EventType `json:"events"`
	FilterPrefix string      `json:"filter_prefix,omitempty"`
	FilterSuffix string      `json:"filter_suffix,omitempty"`
	Target       NotificationTarget `json:"target"`
}

// NotificationTarget describes where to send the event.
type NotificationTarget struct {
	Type     TargetType                   `json:"type"`
	Endpoint string                       `json:"endpoint,omitempty"` // URL for TargetWebhook
	Callback func(NotificationEvent)      `json:"-"`                 // in-process handler for TargetCallback
}

// NotificationManager manages bucket event notification configurations,
// event dispatch, and background delivery.
type NotificationManager struct {
	db      *DB
	mu      sync.RWMutex
	configs map[string][]NotificationConfig // bucket -> configs

	// Background worker
	eventCh  chan notifyJob
	running  atomic.Bool
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// Webhook delivery settings
	WebhookTimeout time.Duration
	MaxRetries     int

	httpClient *http.Client
}

// notifyJob pairs an event with the target that should receive it.
type notifyJob struct {
	event  NotificationEvent
	config NotificationConfig
}

// NewNotificationManager creates a new notification manager.
// The channel buffer controls how many events can be queued before
// Notify blocks.
func NewNotificationManager(db *DB) *NotificationManager {
	nm := &NotificationManager{
		db:             db,
		configs:        make(map[string][]NotificationConfig),
		eventCh:        make(chan notifyJob, 4096),
		stopCh:         make(chan struct{}),
		WebhookTimeout: 10 * time.Second,
		MaxRetries:     3,
	}
	nm.httpClient = &http.Client{
		Timeout: nm.WebhookTimeout,
	}
	return nm
}

// ---------- Lifecycle ----------

// Start loads persisted configs from the DB and launches the background
// delivery worker. It is safe to call Start only once; subsequent calls
// are no-ops until Stop has been called.
func (nm *NotificationManager) Start(ctx context.Context) {
	if !nm.running.CompareAndSwap(false, true) {
		return
	}

	nm.stopCh = make(chan struct{})
	nm.loadConfigsFromDB()

	nm.wg.Add(1)
	go nm.worker(ctx)
}

// Stop signals the background worker to drain remaining events and exit.
// It blocks until the worker has finished.
func (nm *NotificationManager) Stop() {
	if !nm.running.CompareAndSwap(true, false) {
		return
	}
	close(nm.stopCh)
	nm.wg.Wait()
}

// ---------- Configuration CRUD ----------

// PutBucketNotification adds or replaces a notification configuration for
// a bucket. The config is stored both in memory and persisted to the DB.
func (nm *NotificationManager) PutBucketNotification(bucket string, config NotificationConfig) error {
	if config.ID == "" {
		return fmt.Errorf("notification config ID must not be empty")
	}
	if len(config.Events) == 0 {
		return fmt.Errorf("notification config must specify at least one event type")
	}

	nm.mu.Lock()
	defer nm.mu.Unlock()

	// Replace existing config with the same ID, or append.
	configs := nm.configs[bucket]
	replaced := false
	for i, c := range configs {
		if c.ID == config.ID {
			configs[i] = config
			replaced = true
			break
		}
	}
	if !replaced {
		configs = append(configs, config)
	}
	nm.configs[bucket] = configs

	return nm.persistConfigs(bucket, configs)
}

// GetBucketNotification returns all notification configurations for a bucket.
func (nm *NotificationManager) GetBucketNotification(bucket string) []NotificationConfig {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	out := make([]NotificationConfig, len(nm.configs[bucket]))
	copy(out, nm.configs[bucket])
	return out
}

// DeleteBucketNotification removes a single notification configuration
// identified by configID from a bucket. If configID is empty, all
// configurations for the bucket are removed.
func (nm *NotificationManager) DeleteBucketNotification(bucket, configID string) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if configID == "" {
		delete(nm.configs, bucket)
		nm.db.Delete([]byte(notifyConfigPrefix + bucket))
		return nil
	}

	configs := nm.configs[bucket]
	filtered := configs[:0]
	for _, c := range configs {
		if c.ID != configID {
			filtered = append(filtered, c)
		}
	}

	if len(filtered) == 0 {
		delete(nm.configs, bucket)
		nm.db.Delete([]byte(notifyConfigPrefix + bucket))
		return nil
	}

	nm.configs[bucket] = filtered
	return nm.persistConfigs(bucket, filtered)
}

// ---------- Event dispatch ----------

// Notify enqueues an event for asynchronous delivery to all matching
// targets. If the background worker is not running, events are dispatched
// synchronously in the caller goroutine.
func (nm *NotificationManager) Notify(event NotificationEvent) {
	nm.mu.RLock()
	configs := nm.configs[event.Bucket]
	nm.mu.RUnlock()

	for _, cfg := range configs {
		if !nm.eventMatches(event, cfg) {
			continue
		}

		job := notifyJob{event: event, config: cfg}

		if nm.running.Load() {
			select {
			case nm.eventCh <- job:
			default:
				// Channel full -- deliver synchronously to avoid dropping.
				nm.deliver(job)
			}
		} else {
			nm.deliver(job)
		}
	}
}

// ---------- Internal ----------

// worker is the background goroutine that drains the event channel.
func (nm *NotificationManager) worker(ctx context.Context) {
	defer nm.wg.Done()

	for {
		select {
		case <-ctx.Done():
			nm.drain()
			return
		case <-nm.stopCh:
			nm.drain()
			return
		case job := <-nm.eventCh:
			nm.deliver(job)
		}
	}
}

// drain delivers all remaining queued events before the worker exits.
func (nm *NotificationManager) drain() {
	for {
		select {
		case job := <-nm.eventCh:
			nm.deliver(job)
		default:
			return
		}
	}
}

// deliver dispatches a single event to its target, retrying webhooks
// up to MaxRetries times.
func (nm *NotificationManager) deliver(job notifyJob) {
	switch job.config.Target.Type {
	case TargetCallback:
		nm.deliverCallback(job)
	case TargetWebhook:
		nm.deliverWebhook(job)
	}
}

// deliverCallback invokes the in-process callback. Panics inside the
// callback are recovered and logged.
func (nm *NotificationManager) deliverCallback(job notifyJob) {
	if job.config.Target.Callback == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("notification callback panic for config %s: %v", job.config.ID, r)
		}
	}()
	job.config.Target.Callback(job.event)
}

// deliverWebhook sends an HTTP POST with JSON body, retrying on failure.
func (nm *NotificationManager) deliverWebhook(job notifyJob) {
	if job.config.Target.Endpoint == "" {
		return
	}

	body, err := json.Marshal(job.event)
	if err != nil {
		log.Printf("notification: failed to marshal event for config %s: %v", job.config.ID, err)
		return
	}

	var lastErr error
	for attempt := 0; attempt < nm.MaxRetries; attempt++ {
		if attempt > 0 {
			// Exponential back-off: 100ms, 200ms, 400ms ...
			time.Sleep(time.Duration(100<<uint(attempt)) * time.Millisecond)
		}

		req, err := http.NewRequest(http.MethodPost, job.config.Target.Endpoint, bytes.NewReader(body))
		if err != nil {
			log.Printf("notification: bad request for config %s: %v", job.config.ID, err)
			return // not retryable
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := nm.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return // success
		}
		lastErr = fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}

	log.Printf("notification: webhook delivery failed for config %s after %d attempts: %v",
		job.config.ID, nm.MaxRetries, lastErr)
}

// eventMatches returns true when an event satisfies a configuration's
// event type list and key prefix/suffix filters.
func (nm *NotificationManager) eventMatches(event NotificationEvent, cfg NotificationConfig) bool {
	typeMatch := false
	for _, et := range cfg.Events {
		if et == event.EventType {
			typeMatch = true
			break
		}
	}
	if !typeMatch {
		return false
	}

	if cfg.FilterPrefix != "" && !strings.HasPrefix(event.Key, cfg.FilterPrefix) {
		return false
	}
	if cfg.FilterSuffix != "" && !strings.HasSuffix(event.Key, cfg.FilterSuffix) {
		return false
	}

	return true
}

// ---------- Persistence ----------

// persistableConfig is the JSON-safe subset of NotificationConfig stored
// in the DB. Callback targets are not persisted.
type persistableConfig struct {
	ID           string      `json:"id"`
	Events       []EventType `json:"events"`
	FilterPrefix string      `json:"filter_prefix,omitempty"`
	FilterSuffix string      `json:"filter_suffix,omitempty"`
	TargetType   TargetType  `json:"target_type"`
	Endpoint     string      `json:"endpoint,omitempty"`
}

func toPersistable(c NotificationConfig) persistableConfig {
	return persistableConfig{
		ID:           c.ID,
		Events:       c.Events,
		FilterPrefix: c.FilterPrefix,
		FilterSuffix: c.FilterSuffix,
		TargetType:   c.Target.Type,
		Endpoint:     c.Target.Endpoint,
	}
}

func fromPersistable(p persistableConfig) NotificationConfig {
	return NotificationConfig{
		ID:           p.ID,
		Events:       p.Events,
		FilterPrefix: p.FilterPrefix,
		FilterSuffix: p.FilterSuffix,
		Target: NotificationTarget{
			Type:     p.TargetType,
			Endpoint: p.Endpoint,
		},
	}
}

func (nm *NotificationManager) persistConfigs(bucket string, configs []NotificationConfig) error {
	pcs := make([]persistableConfig, len(configs))
	for i, c := range configs {
		pcs[i] = toPersistable(c)
	}

	data, err := json.Marshal(pcs)
	if err != nil {
		return fmt.Errorf("notification: marshal configs: %w", err)
	}

	return nm.db.PutWithTTL([]byte(notifyConfigPrefix+bucket), data, 0)
}

func (nm *NotificationManager) loadConfigsFromDB() {
	keys, err := nm.db.Keys(notifyConfigPrefix + "*")
	if err != nil {
		log.Printf("notification: failed to list configs: %v", err)
		return
	}

	nm.mu.Lock()
	defer nm.mu.Unlock()

	for _, key := range keys {
		bucket := strings.TrimPrefix(key, notifyConfigPrefix)

		data, err := nm.db.Get([]byte(key))
		if err != nil {
			continue
		}

		var pcs []persistableConfig
		if err := json.Unmarshal(data, &pcs); err != nil {
			log.Printf("notification: failed to unmarshal configs for bucket %s: %v", bucket, err)
			continue
		}

		configs := make([]NotificationConfig, len(pcs))
		for i, p := range pcs {
			configs[i] = fromPersistable(p)
		}
		nm.configs[bucket] = configs
	}
}
