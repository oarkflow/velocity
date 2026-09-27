// Package compliance implements Velocity v2's compliance plugin: a
// tamper-evident audit trail, a classification-based policy engine, and
// GDPR-style retention/consent/anonymization, ported from v1's
// audit_immutable.go, policy_engine.go, violations.go, retention_manager.go,
// gdpr_consent.go, gdpr_retention.go, and data_masking.go.
//
// Architecturally, this plugin never imports or calls into kv/object/secret
// directly. It observes them purely by subscribing to kernel events
// (api.TopicKVPut, api.TopicObjectPut, ...) — the point of the microkernel
// design is that kv/object/secret never need to know this plugin exists,
// and this plugin can be removed from a manifest with zero code changes
// elsewhere.
//
// This plugin also fixes a real bug found in v1 during the audit that
// motivated the v2 rework: v1's GDPRController
// (gdpr_consent.go/gdpr_retention.go) silently returned nil (success) from
// RecordConsent/ApplyRetention when its underlying manager was nil —
// meaning a caller could believe consent was recorded or retention was
// applied when neither happened. ApplyRetention, RecordConsent, and
// Anonymize here all return a descriptive error instead whenever the
// storage backend isn't wired.
package compliance

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// observedTopics is the set of kernel events this plugin subscribes to in
// order to build its audit trail without any producer plugin calling it
// directly.
var observedTopics = []string{
	api.TopicKVPut,
	api.TopicKVDelete,
	api.TopicObjectPut,
	api.TopicObjectDelete,
	api.TopicSecretSet,
	api.TopicSecretRotate,
	api.TopicSecretAccess,
	api.TopicAuthDenied,
}

// Plugin is Velocity v2's compliance plugin. It registers itself under the
// service name "compliance" as an api.ComplianceService.
type Plugin struct {
	storageDep string
	storage    api.StorageBackend
	log        api.Logger
	bus        api.EventBus

	mu       sync.Mutex // guards headSeq/headHash for the audit chain
	headSeq  int        // -1 means the chain is empty
	headHash string

	rulesMu sync.RWMutex // guards rules — ImportRulePack mutates it at runtime
	rules   []Rule

	// Violation webhook alerting (v1 violations.go), config-driven —
	// empty violationWebhookURL disables delivery entirely (violations
	// are still recorded/queryable, just not pushed anywhere).
	violationWebhookURL string
	violationRateLimit  int // max webhook deliveries per rolling minute; <=0 means unlimited
	httpClient          *http.Client

	rateMu     sync.Mutex
	rateWindow []time.Time // delivery timestamps within the last minute, oldest first

	subs []api.Subscription
}

// NewPlugin constructs the compliance plugin. storageDep is the Plugin
// Name() of the storage plugin this one depends on for boot ordering
// (e.g. "storage-lsm" or "storage-mem"); it does not affect the fixed
// "storage" service-name lookup used at Init time. An empty string
// defaults to "storage-lsm".
func NewPlugin(storageDep string) *Plugin {
	if storageDep == "" {
		storageDep = "storage-lsm"
	}
	return &Plugin{storageDep: storageDep, headSeq: -1}
}

func (p *Plugin) Name() string    { return "compliance" }
func (p *Plugin) Version() string { return "0.1.0" }

func (p *Plugin) Dependencies() []string { return []string{p.storageDep} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.log = k.Logger()
	p.bus = k.Events()

	storeAny := k.Registry().MustLookup("storage")
	store, ok := storeAny.(api.StorageBackend)
	if !ok {
		return fmt.Errorf("compliance: service %q does not implement api.StorageBackend", "storage")
	}
	p.storage = store

	if err := p.loadHead(ctx); err != nil {
		return fmt.Errorf("compliance: loading audit chain head: %w", err)
	}

	cfg := k.Config().Scoped("compliance")
	p.rules = loadRules(cfg)
	p.violationWebhookURL = cfg.String("violation_webhook_url", "")
	p.violationRateLimit = cfg.Int("violation_webhook_rate_limit", 60)
	p.httpClient = &http.Client{Timeout: 5 * time.Second}

	if err := k.Registry().Provide("compliance", p); err != nil {
		return err
	}

	for _, topic := range observedTopics {
		t := topic // capture
		sub := p.bus.Subscribe(t, func(ctx context.Context, ev api.Event) {
			p.observeEvent(ctx, t, ev)
		})
		p.subs = append(p.subs, sub)
	}

	return nil
}

func (p *Plugin) Start(ctx context.Context) error { return nil }

func (p *Plugin) Stop(ctx context.Context) error {
	for _, sub := range p.subs {
		sub.Unsubscribe()
	}
	p.subs = nil
	return nil
}

func (p *Plugin) Health() api.Health {
	if p.storage == nil {
		return api.Health{Status: "down", Detail: "storage backend not initialized"}
	}
	return api.Health{Status: "ok"}
}

// observeEvent turns one kernel Event from an observed topic into an
// AuditEvent and records it. Handlers cannot return an error (the
// api.Handler signature has none), so a recording failure is logged
// rather than propagated — this is the one place in the plugin where an
// error is intentionally swallowed, because there is no caller to return
// it to.
func (p *Plugin) observeEvent(ctx context.Context, topic string, ev api.Event) {
	auditEv := api.AuditEvent{
		Actor:    ev.Source,
		Action:   topic,
		Resource: fmt.Sprintf("%v", ev.Payload),
		Detail:   map[string]any{"payload": ev.Payload},
	}
	if err := p.Record(ctx, auditEv); err != nil && p.log != nil {
		p.log.Error("compliance: failed to record observed event", "topic", topic, "source", ev.Source, "err", err)
	}
}

var (
	_ api.Plugin            = (*Plugin)(nil)
	_ api.ComplianceService = (*Plugin)(nil)
)
