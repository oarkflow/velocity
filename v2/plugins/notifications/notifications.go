// Package notifications implements the Velocity v2 "notifications"
// plugin: api.NotificationService (rule management) plus a background
// webhook-delivery worker pool, ported from v1's notifications.go
// (bucket-event notification manager with a worker pool and retry).
//
// Unlike a synchronous call from kv/object into this plugin, delivery is
// driven entirely by subscribing to the kernel event bus in Init — kv and
// object never know this plugin exists, matching the microkernel's
// decoupled-observer pattern used by plugins/compliance and
// plugins/replication.
package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// ServiceName is the fixed Registry name this plugin provides its
// api.NotificationService under.
const ServiceName = "notifications"

const rulesKey = "notifications/rules"

// delivery is one queued webhook send.
type delivery struct {
	url string
	ev  api.Event
}

// Plugin implements api.Plugin and api.NotificationService.
type Plugin struct {
	storageDep string

	storage api.StorageBackend
	events  api.EventBus
	log     api.Logger
	client  *http.Client

	rulesMu sync.RWMutex
	rules   map[string]api.NotificationRule

	subs []api.Subscription

	queue    chan delivery
	workers  int
	maxRetry int

	stopOnce sync.Once
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// delivered/failed count successful/permanently-failed webhook
	// attempts, exported for tests only.
	statsMu   sync.Mutex
	delivered int
	failed    int
}

// NewPlugin constructs the notifications plugin. storageDep names the
// storage plugin this one depends on for boot ordering (rules are
// persisted so they survive restarts); it defaults to "storage-lsm".
func NewPlugin(storageDep string) *Plugin {
	if storageDep == "" {
		storageDep = "storage-lsm"
	}
	return &Plugin{
		storageDep: storageDep,
		rules:      make(map[string]api.NotificationRule),
		workers:    8,
		maxRetry:   3,
		stopCh:     make(chan struct{}),
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *Plugin) Name() string           { return "notifications" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return []string{p.storageDep} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.storage = k.Registry().MustLookup("storage").(api.StorageBackend)
	p.events = k.Events()
	p.log = k.Logger()

	p.workers = k.Config().Scoped(p.Name()).Int("workers", p.workers)
	p.maxRetry = k.Config().Scoped(p.Name()).Int("max_retry", p.maxRetry)
	p.queue = make(chan delivery, 1024)

	if err := p.loadRules(ctx); err != nil {
		return fmt.Errorf("notifications: loading persisted rules: %w", err)
	}

	for _, topic := range []string{
		api.TopicKVPut, api.TopicKVDelete,
		api.TopicObjectPut, api.TopicObjectDelete,
	} {
		p.subs = append(p.subs, p.events.Subscribe(topic, p.onEvent))
	}

	return k.Registry().Provide(ServiceName, api.NotificationService(p))
}

func (p *Plugin) Start(ctx context.Context) error {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
	return nil
}

func (p *Plugin) Stop(ctx context.Context) error {
	p.stopOnce.Do(func() { close(p.stopCh) })
	for _, s := range p.subs {
		s.Unsubscribe()
	}
	close(p.queue)
	p.wg.Wait()
	return nil
}

func (p *Plugin) Health() api.Health { return api.Health{Status: "ok"} }

// onEvent is the single handler subscribed to every topic this plugin
// observes. It must not block the publisher — matching rules are
// enqueued for the worker pool, never delivered synchronously here.
func (p *Plugin) onEvent(ctx context.Context, ev api.Event) {
	p.rulesMu.RLock()
	var targets []string
	for _, r := range p.rules {
		if r.Enabled && r.Topic == ev.Topic {
			targets = append(targets, r.WebhookURL)
		}
	}
	p.rulesMu.RUnlock()

	for _, url := range targets {
		select {
		case p.queue <- delivery{url: url, ev: ev}:
		default:
			p.log.Warn("notifications: delivery queue full, dropping event", "topic", ev.Topic, "url", url)
		}
	}
}

func (p *Plugin) worker() {
	defer p.wg.Done()
	for d := range p.queue {
		p.deliverWithRetry(d)
	}
}

func (p *Plugin) deliverWithRetry(d delivery) {
	body, err := json.Marshal(d.ev)
	if err != nil {
		return
	}

	backoff := 100 * time.Millisecond
	for attempt := 1; attempt <= p.maxRetry; attempt++ {
		req, err := http.NewRequest(http.MethodPost, d.url, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			resp, err := p.client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					p.statsMu.Lock()
					p.delivered++
					p.statsMu.Unlock()
					return
				}
			}
		}
		if attempt < p.maxRetry {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
	p.statsMu.Lock()
	p.failed++
	p.statsMu.Unlock()
	if p.log != nil {
		p.log.Warn("notifications: webhook delivery failed permanently", "url", d.url, "topic", d.ev.Topic, "attempts", p.maxRetry)
	}
}

// --- api.NotificationService ---

func (p *Plugin) AddRule(ctx context.Context, r api.NotificationRule) error {
	if r.ID == "" {
		return errors.New("notifications: rule ID must not be empty")
	}
	p.rulesMu.Lock()
	p.rules[r.ID] = r
	p.rulesMu.Unlock()
	return p.saveRules(ctx)
}

func (p *Plugin) RemoveRule(ctx context.Context, id string) error {
	p.rulesMu.Lock()
	delete(p.rules, id)
	p.rulesMu.Unlock()
	return p.saveRules(ctx)
}

func (p *Plugin) ListRules(ctx context.Context) ([]api.NotificationRule, error) {
	p.rulesMu.RLock()
	defer p.rulesMu.RUnlock()
	out := make([]api.NotificationRule, 0, len(p.rules))
	for _, r := range p.rules {
		out = append(out, r)
	}
	return out, nil
}

func (p *Plugin) loadRules(ctx context.Context) error {
	v, ok, err := p.storage.Get(ctx, []byte(rulesKey))
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	var rules []api.NotificationRule
	if err := json.Unmarshal(v, &rules); err != nil {
		return err
	}
	p.rulesMu.Lock()
	for _, r := range rules {
		p.rules[r.ID] = r
	}
	p.rulesMu.Unlock()
	return nil
}

func (p *Plugin) saveRules(ctx context.Context) error {
	p.rulesMu.RLock()
	rules := make([]api.NotificationRule, 0, len(p.rules))
	for _, r := range p.rules {
		rules = append(rules, r)
	}
	p.rulesMu.RUnlock()

	data, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	return p.storage.Put(ctx, api.Entry{Key: []byte(rulesKey), Value: data})
}

// Stats returns (delivered, failed) webhook attempt counts. Exported for
// tests only.
func (p *Plugin) Stats() (delivered, failed int) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	return p.delivered, p.failed
}

var (
	_ api.Plugin              = (*Plugin)(nil)
	_ api.NotificationService = (*Plugin)(nil)
)
