// Package alerts provides alerting and notification functionality.
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/smtp"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/core/monitoring"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrRuleNotFound     = errors.New("alerts: rule not found")
	ErrNotifierNotFound = errors.New("alerts: notifier not found")
	ErrAlertNotFound    = errors.New("alerts: alert not found")
)

// AlertSeverity represents alert severity
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityError    AlertSeverity = "error"
	AlertSeverityCritical AlertSeverity = "critical"
)

// AlertStatus represents alert status
type AlertStatus string

const (
	AlertStatusActive       AlertStatus = "active"
	AlertStatusAcknowledged AlertStatus = "acknowledged"
	AlertStatusResolved     AlertStatus = "resolved"
	AlertStatusSuppressed   AlertStatus = "suppressed"
)

// ConditionType represents the type of alert condition
type ConditionType string

const (
	ConditionTypeThreshold ConditionType = "threshold"
	ConditionTypePattern   ConditionType = "pattern"
	ConditionTypeAnomaly   ConditionType = "anomaly"
	ConditionTypeRate      ConditionType = "rate"
)

// Rule represents an alert rule
type Rule struct {
	ID            types.ID           `json:"id"`
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	Enabled       bool               `json:"enabled"`
	Condition     Condition          `json:"condition"`
	Severity      AlertSeverity      `json:"severity"`
	Actions       []Action           `json:"actions"`
	Cooldown      time.Duration      `json:"cooldown,omitempty"`
	Tags          []string           `json:"tags,omitempty"`
	CreatedAt     types.Timestamp    `json:"created_at"`
	UpdatedAt     types.Timestamp    `json:"updated_at"`
	LastTriggered *types.Timestamp   `json:"last_triggered,omitempty"`
	Status        types.EntityStatus `json:"status"`
}

// Condition represents an alert condition
type Condition struct {
	Type           ConditionType `json:"type"`
	EventTypes     []string      `json:"event_types,omitempty"`
	Threshold      float64       `json:"threshold,omitempty"`
	Operator       string        `json:"operator,omitempty"` // >, <, >=, <=, ==, !=
	Field          string        `json:"field,omitempty"`
	Pattern        string        `json:"pattern,omitempty"`
	Window         time.Duration `json:"window,omitempty"`
	MinOccurrences int           `json:"min_occurrences,omitempty"`
}

// Action represents an alert action
type Action struct {
	Type       string         `json:"type"` // webhook, email, slack, pagerduty
	NotifierID types.ID       `json:"notifier_id,omitempty"`
	Config     types.Metadata `json:"config,omitempty"`
}

// Alert represents an active alert
type Alert struct {
	ID             types.ID       `json:"id"`
	RuleID         types.ID       `json:"rule_id"`
	RuleName       string         `json:"rule_name"`
	Severity       AlertSeverity  `json:"severity"`
	Status         AlertStatus    `json:"status"`
	Title          string         `json:"title"`
	Description    string         `json:"description"`
	Source         string         `json:"source"`
	TriggeredAt    time.Time      `json:"triggered_at"`
	AcknowledgedAt *time.Time     `json:"acknowledged_at,omitempty"`
	AcknowledgedBy types.ID       `json:"acknowledged_by,omitempty"`
	ResolvedAt     *time.Time     `json:"resolved_at,omitempty"`
	ResolvedBy     types.ID       `json:"resolved_by,omitempty"`
	OrgID          types.ID       `json:"org_id,omitempty"`
	Details        types.Metadata `json:"details,omitempty"`
	RelatedEvents  []types.ID     `json:"related_events,omitempty"`
}

// Notifier represents a notification channel
type Notifier struct {
	ID        types.ID           `json:"id"`
	Name      string             `json:"name"`
	Type      string             `json:"type"` // webhook, slack, email, pagerduty, opsgenie
	Config    NotifierConfig     `json:"config"`
	Enabled   bool               `json:"enabled"`
	CreatedAt types.Timestamp    `json:"created_at"`
	Status    types.EntityStatus `json:"status"`
}

// NotifierConfig holds notifier configuration
type NotifierConfig struct {
	// Webhook
	WebhookURL     string            `json:"webhook_url,omitempty"`
	WebhookMethod  string            `json:"webhook_method,omitempty"`
	WebhookHeaders map[string]string `json:"webhook_headers,omitempty"`

	// Email
	EmailTo      []string `json:"email_to,omitempty"`
	EmailFrom    string   `json:"email_from,omitempty"`
	SMTPHost     string   `json:"smtp_host,omitempty"`
	SMTPPort     int      `json:"smtp_port,omitempty"`
	SMTPUser     string   `json:"smtp_user,omitempty"`
	SMTPPassword string   `json:"smtp_password,omitempty"`

	// Slack
	SlackWebhookURL string `json:"slack_webhook_url,omitempty"`
	SlackChannel    string `json:"slack_channel,omitempty"`

	// PagerDuty
	PagerDutyKey     string `json:"pagerduty_key,omitempty"`
	PagerDutyService string `json:"pagerduty_service,omitempty"`

	// OpsGenie
	OpsGenieKey string `json:"opsgenie_key,omitempty"`
}

// Engine provides alerting functionality
type Engine struct {
	mu            sync.RWMutex
	store         *storage.Store
	crypto        *crypto.Engine
	monitoring    *monitoring.Engine
	ruleStore     *storage.TypedStore[Rule]
	alertStore    *storage.TypedStore[Alert]
	notifierStore *storage.TypedStore[Notifier]
	rules         map[types.ID]*Rule
	notifiers     map[types.ID]*Notifier
	ruleWindows   map[types.ID][]time.Time // For rate-based rules
	stopCh        chan struct{}
}

// EngineConfig configures the alert engine
type EngineConfig struct {
	Store      *storage.Store
	Monitoring *monitoring.Engine
}

// NewEngine creates a new alert engine
func NewEngine(cfg EngineConfig) *Engine {
	e := &Engine{
		store:         cfg.Store,
		crypto:        crypto.NewEngine(""),
		monitoring:    cfg.Monitoring,
		ruleStore:     storage.NewTypedStore[Rule](cfg.Store, "alert_rules"),
		alertStore:    storage.NewTypedStore[Alert](cfg.Store, "alerts"),
		notifierStore: storage.NewTypedStore[Notifier](cfg.Store, "alert_notifiers"),
		rules:         make(map[types.ID]*Rule),
		notifiers:     make(map[types.ID]*Notifier),
		ruleWindows:   make(map[types.ID][]time.Time),
		stopCh:        make(chan struct{}),
	}

	// Load existing rules
	ctx := context.Background()
	rules, _ := e.ruleStore.List(ctx, "")
	for _, r := range rules {
		e.rules[r.ID] = r
	}

	notifiers, _ := e.notifierStore.List(ctx, "")
	for _, n := range notifiers {
		e.notifiers[n.ID] = n
	}

	return e
}

// StartEventProcessor starts processing monitoring events
func (e *Engine) StartEventProcessor(ctx context.Context) {
	subID := "alert-engine"
	eventCh := e.monitoring.Subscribe(subID, monitoring.EventFilter{})

	go func() {
		for {
			select {
			case event := <-eventCh:
				if event != nil {
					_ = e.ProcessEvent(ctx, event)
				}
			case <-e.stopCh:
				e.monitoring.Unsubscribe(subID)
				return
			case <-ctx.Done():
				e.monitoring.Unsubscribe(subID)
				return
			}
		}
	}()
}

// ProcessEvent processes a monitoring event against rules
func (e *Engine) ProcessEvent(ctx context.Context, event *monitoring.Event) error {
	e.mu.RLock()
	rules := make([]*Rule, 0, len(e.rules))
	for _, r := range e.rules {
		if r.Enabled && r.Status == types.StatusActive {
			rules = append(rules, r)
		}
	}
	e.mu.RUnlock()

	for _, rule := range rules {
		// Check cooldown
		if rule.LastTriggered != nil {
			lastTriggered := rule.LastTriggered.Time()
			if time.Since(lastTriggered) < rule.Cooldown {
				continue
			}
		}

		if e.matchesCondition(event, rule) {
			if err := e.triggerAlert(ctx, rule, event); err != nil {
				continue
			}
		}
	}

	return nil
}

// matchesCondition checks if an event matches a rule condition
func (e *Engine) matchesCondition(event *monitoring.Event, rule *Rule) bool {
	cond := rule.Condition

	// Check event types
	if len(cond.EventTypes) > 0 {
		matched := false
		for _, et := range cond.EventTypes {
			if string(event.Type) == et {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	switch cond.Type {
	case ConditionTypeThreshold:
		return e.checkThreshold(event, cond)
	case ConditionTypePattern:
		return e.checkPattern(event, cond)
	case ConditionTypeRate:
		return e.checkRate(rule.ID, cond)
	case ConditionTypeAnomaly:
		return e.checkAnomaly(event, cond)
	}

	return false
}

// checkThreshold checks threshold-based condition
func (e *Engine) checkThreshold(event *monitoring.Event, cond Condition) bool {
	if event.Details == nil || cond.Field == "" {
		return false
	}

	value, ok := event.Details[cond.Field].(float64)
	if !ok {
		return false
	}

	switch cond.Operator {
	case ">":
		return value > cond.Threshold
	case "<":
		return value < cond.Threshold
	case ">=":
		return value >= cond.Threshold
	case "<=":
		return value <= cond.Threshold
	case "==":
		return value == cond.Threshold
	case "!=":
		return value != cond.Threshold
	}

	return false
}

// checkPattern checks pattern-based condition
func (e *Engine) checkPattern(event *monitoring.Event, cond Condition) bool {
	// Simple pattern matching
	if cond.Pattern == "" {
		return false
	}

	// Check action
	if event.Action == cond.Pattern {
		return true
	}

	// Check severity
	if event.Severity == cond.Pattern {
		return true
	}

	return false
}

// checkRate checks rate-based condition
func (e *Engine) checkRate(ruleID types.ID, cond Condition) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-cond.Window)

	// Clean old entries
	var validTimes []time.Time
	for _, t := range e.ruleWindows[ruleID] {
		if t.After(windowStart) {
			validTimes = append(validTimes, t)
		}
	}

	// Add current event
	validTimes = append(validTimes, now)
	e.ruleWindows[ruleID] = validTimes

	return len(validTimes) >= cond.MinOccurrences
}

// checkAnomaly checks anomaly-based condition
func (e *Engine) checkAnomaly(event *monitoring.Event, cond Condition) bool {
	// Check for anomaly indicators
	if event.Details != nil {
		if isAnomaly, ok := event.Details["is_anomaly"].(bool); ok && isAnomaly {
			return true
		}
		if riskScore, ok := event.Details["risk_score"].(float64); ok && riskScore > cond.Threshold {
			return true
		}
	}

	return false
}

// triggerAlert creates and sends an alert
func (e *Engine) triggerAlert(ctx context.Context, rule *Rule, event *monitoring.Event) error {
	id, err := e.crypto.GenerateRandomID()
	if err != nil {
		return err
	}

	alert := &Alert{
		ID:            id,
		RuleID:        rule.ID,
		RuleName:      rule.Name,
		Severity:      rule.Severity,
		Status:        AlertStatusActive,
		Title:         e.formatAlertTitle(rule, event),
		Description:   e.formatAlertDescription(rule, event),
		Source:        event.Source,
		TriggeredAt:   time.Now(),
		OrgID:         event.OrgID,
		Details:       event.Details,
		RelatedEvents: []types.ID{event.ID},
	}

	// Store alert
	if err := e.alertStore.Set(ctx, string(alert.ID), alert); err != nil {
		return err
	}

	// Update rule last triggered
	now := types.Now()
	rule.LastTriggered = &now
	e.mu.Lock()
	e.rules[rule.ID] = rule
	e.mu.Unlock()
	_ = e.ruleStore.Set(ctx, string(rule.ID), rule)

	// Execute actions
	for _, action := range rule.Actions {
		_ = e.executeAction(ctx, action, alert)
	}

	return nil
}

// formatAlertTitle formats the alert title
func (e *Engine) formatAlertTitle(rule *Rule, event *monitoring.Event) string {
	return "[" + string(rule.Severity) + "] " + rule.Name
}

// formatAlertDescription formats the alert description
func (e *Engine) formatAlertDescription(rule *Rule, event *monitoring.Event) string {
	desc := rule.Description
	if desc == "" {
		desc = "Alert triggered by rule: " + rule.Name
	}
	return desc + "\nSource: " + event.Source + "\nAction: " + event.Action
}

// executeAction executes an alert action
func (e *Engine) executeAction(ctx context.Context, action Action, alert *Alert) error {
	switch action.Type {
	case "webhook":
		return e.sendWebhook(ctx, action, alert)
	case "slack":
		return e.sendSlack(ctx, action, alert)
	case "email":
		return e.sendEmail(ctx, action, alert)
	case "pagerduty":
		return e.sendPagerDuty(ctx, action, alert)
	}

	// Check if notifier is specified
	if action.NotifierID != "" {
		e.mu.RLock()
		notifier, ok := e.notifiers[action.NotifierID]
		e.mu.RUnlock()

		if ok && notifier.Enabled {
			return e.sendToNotifier(ctx, notifier, alert)
		}
	}

	return nil
}

// sendWebhook sends a webhook notification
func (e *Engine) sendWebhook(ctx context.Context, action Action, alert *Alert) error {
	url, _ := action.Config["url"].(string)
	if url == "" {
		return nil
	}

	payload, _ := json.Marshal(alert)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// sendSlack sends a Slack notification
func (e *Engine) sendSlack(ctx context.Context, action Action, alert *Alert) error {
	webhookURL, _ := action.Config["webhook_url"].(string)
	if webhookURL == "" {
		return nil
	}

	// Format Slack message
	message := map[string]any{
		"text": alert.Title,
		"attachments": []map[string]any{
			{
				"color": e.severityColor(alert.Severity),
				"title": alert.RuleName,
				"text":  alert.Description,
				"fields": []map[string]any{
					{"title": "Severity", "value": string(alert.Severity), "short": true},
					{"title": "Source", "value": alert.Source, "short": true},
				},
				"ts": alert.TriggeredAt.Unix(),
			},
		},
	}

	payload, _ := json.Marshal(message)
	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// sendEmail sends an email notification via SMTP.
func (e *Engine) sendEmail(ctx context.Context, action Action, alert *Alert) error {
	_ = ctx

	to := normalizeStringSlice(action.Config["to"])
	from := normalizeString(action.Config["from"])
	smtpHost := normalizeString(action.Config["smtp_host"])
	smtpPort := normalizeInt(action.Config["smtp_port"], 25)
	smtpUser := normalizeString(action.Config["smtp_user"])
	smtpPassword := normalizeString(action.Config["smtp_password"])

	if len(to) == 0 || from == "" || smtpHost == "" {
		return errors.New("alerts: email action requires to/from/smtp_host")
	}

	subject := alert.Title
	body := fmt.Sprintf("%s\n\nSeverity: %s\nRule: %s\nSource: %s\nTime: %s\n",
		alert.Description,
		alert.Severity,
		alert.RuleName,
		alert.Source,
		alert.TriggeredAt.UTC().Format(time.RFC3339),
	)

	return sendSMTPMail(smtpHost, smtpPort, smtpUser, smtpPassword, from, to, subject, body)
}

// sendPagerDuty sends a PagerDuty notification
func (e *Engine) sendPagerDuty(ctx context.Context, action Action, alert *Alert) error {
	routingKey, _ := action.Config["routing_key"].(string)
	if routingKey == "" {
		return nil
	}

	event := map[string]any{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"payload": map[string]any{
			"summary":        alert.Title,
			"severity":       string(alert.Severity),
			"source":         alert.Source,
			"custom_details": alert.Details,
		},
	}

	payload, _ := json.Marshal(event)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://events.pagerduty.com/v2/enqueue", bytes.NewReader(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// sendToNotifier sends to a configured notifier
func (e *Engine) sendToNotifier(ctx context.Context, notifier *Notifier, alert *Alert) error {
	switch notifier.Type {
	case "webhook":
		return e.sendWebhookViaNotifier(ctx, notifier, alert)
	case "slack":
		return e.sendSlackViaNotifier(ctx, notifier, alert)
	case "email":
		return e.sendEmailViaNotifier(ctx, notifier, alert)
	case "pagerduty":
		return e.sendPagerDutyViaNotifier(ctx, notifier, alert)
	}
	return nil
}

func (e *Engine) sendWebhookViaNotifier(ctx context.Context, notifier *Notifier, alert *Alert) error {
	if notifier.Config.WebhookURL == "" {
		return nil
	}

	payload, _ := json.Marshal(alert)
	method := notifier.Config.WebhookMethod
	if method == "" {
		method = "POST"
	}

	req, err := http.NewRequestWithContext(ctx, method, notifier.Config.WebhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range notifier.Config.WebhookHeaders {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (e *Engine) sendSlackViaNotifier(ctx context.Context, notifier *Notifier, alert *Alert) error {
	if notifier.Config.SlackWebhookURL == "" {
		return nil
	}

	message := map[string]any{
		"channel": notifier.Config.SlackChannel,
		"text":    alert.Title,
		"attachments": []map[string]any{
			{
				"color": e.severityColor(alert.Severity),
				"title": alert.RuleName,
				"text":  alert.Description,
			},
		},
	}

	payload, _ := json.Marshal(message)
	req, err := http.NewRequestWithContext(ctx, "POST", notifier.Config.SlackWebhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (e *Engine) sendPagerDutyViaNotifier(ctx context.Context, notifier *Notifier, alert *Alert) error {
	if notifier.Config.PagerDutyKey == "" {
		return nil
	}

	event := map[string]any{
		"routing_key":  notifier.Config.PagerDutyKey,
		"event_action": "trigger",
		"payload": map[string]any{
			"summary":  alert.Title,
			"severity": string(alert.Severity),
			"source":   alert.Source,
		},
	}

	payload, _ := json.Marshal(event)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://events.pagerduty.com/v2/enqueue", bytes.NewReader(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (e *Engine) sendEmailViaNotifier(ctx context.Context, notifier *Notifier, alert *Alert) error {
	_ = ctx
	cfg := notifier.Config
	if len(cfg.EmailTo) == 0 || cfg.EmailFrom == "" || cfg.SMTPHost == "" {
		return errors.New("alerts: email notifier requires email_to/email_from/smtp_host")
	}

	subject := alert.Title
	body := fmt.Sprintf("%s\n\nSeverity: %s\nRule: %s\nSource: %s\nTime: %s\n",
		alert.Description,
		alert.Severity,
		alert.RuleName,
		alert.Source,
		alert.TriggeredAt.UTC().Format(time.RFC3339),
	)

	port := cfg.SMTPPort
	if port <= 0 {
		port = 25
	}
	return sendSMTPMail(cfg.SMTPHost, port, cfg.SMTPUser, cfg.SMTPPassword, cfg.EmailFrom, cfg.EmailTo, subject, body)
}

func sendSMTPMail(host string, port int, username, password, from string, to []string, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	msg := strings.Join([]string{
		fmt.Sprintf("From: %s", from),
		fmt.Sprintf("To: %s", strings.Join(to, ", ")),
		fmt.Sprintf("Subject: %s", subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")

	var auth smtp.Auth
	if username != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}

	return smtp.SendMail(addr, auth, from, to, []byte(msg))
}

func normalizeString(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func normalizeStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	if arr, ok := v.([]string); ok {
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	}
	if arr, ok := v.([]any); ok {
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	}
	if s, ok := v.(string); ok {
		parts := strings.Split(s, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
		return out
	}
	return nil
}

func normalizeInt(v any, fallback int) int {
	switch t := v.(type) {
	case int:
		return t
	case int32:
		return int(t)
	case int64:
		return int(t)
	case float64:
		return int(t)
	default:
		return fallback
	}
}

// severityColor returns color for severity
func (e *Engine) severityColor(severity AlertSeverity) string {
	switch severity {
	case AlertSeverityCritical:
		return "#FF0000"
	case AlertSeverityError:
		return "#FF6600"
	case AlertSeverityWarning:
		return "#FFCC00"
	default:
		return "#36A64F"
	}
}

// CreateRule creates a new alert rule
func (e *Engine) CreateRule(ctx context.Context, rule *Rule) error {
	id, err := e.crypto.GenerateRandomID()
	if err != nil {
		return err
	}

	rule.ID = id
	rule.CreatedAt = types.Now()
	rule.UpdatedAt = types.Now()
	rule.Status = types.StatusActive
	rule.Enabled = true

	if err := e.ruleStore.Set(ctx, string(rule.ID), rule); err != nil {
		return err
	}

	e.mu.Lock()
	e.rules[rule.ID] = rule
	e.mu.Unlock()

	return nil
}

// GetRule retrieves a rule by ID
func (e *Engine) GetRule(ctx context.Context, id types.ID) (*Rule, error) {
	e.mu.RLock()
	if rule, ok := e.rules[id]; ok {
		e.mu.RUnlock()
		return rule, nil
	}
	e.mu.RUnlock()
	return e.ruleStore.Get(ctx, string(id))
}

// ListRules lists all rules
func (e *Engine) ListRules(ctx context.Context) ([]*Rule, error) {
	return e.ruleStore.List(ctx, "")
}

// UpdateRule updates a rule
func (e *Engine) UpdateRule(ctx context.Context, id types.ID, rule *Rule) error {
	rule.ID = id
	rule.UpdatedAt = types.Now()

	if err := e.ruleStore.Set(ctx, string(id), rule); err != nil {
		return err
	}

	e.mu.Lock()
	e.rules[id] = rule
	e.mu.Unlock()

	return nil
}

// DeleteRule deletes a rule
func (e *Engine) DeleteRule(ctx context.Context, id types.ID) error {
	e.mu.Lock()
	delete(e.rules, id)
	e.mu.Unlock()
	return e.ruleStore.Delete(ctx, string(id))
}

// GetAlert retrieves an alert by ID
func (e *Engine) GetAlert(ctx context.Context, id types.ID) (*Alert, error) {
	return e.alertStore.Get(ctx, string(id))
}

// ListAlerts lists alerts
func (e *Engine) ListAlerts(ctx context.Context, opts ListAlertsOptions) ([]*Alert, error) {
	all, err := e.alertStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var alerts []*Alert
	for _, a := range all {
		if opts.Status != "" && a.Status != opts.Status {
			continue
		}
		if opts.Severity != "" && a.Severity != opts.Severity {
			continue
		}
		if opts.OrgID != "" && a.OrgID != opts.OrgID {
			continue
		}
		alerts = append(alerts, a)
	}

	// Sort by triggered time descending
	sort.Slice(alerts, func(i, j int) bool {
		return alerts[i].TriggeredAt.After(alerts[j].TriggeredAt)
	})

	return alerts, nil
}

// ListAlertsOptions holds list options
type ListAlertsOptions struct {
	Status   AlertStatus
	Severity AlertSeverity
	OrgID    types.ID
}

// AcknowledgeAlert acknowledges an alert
func (e *Engine) AcknowledgeAlert(ctx context.Context, id types.ID, actorID types.ID) error {
	alert, err := e.GetAlert(ctx, id)
	if err != nil {
		return err
	}

	now := time.Now()
	alert.Status = AlertStatusAcknowledged
	alert.AcknowledgedAt = &now
	alert.AcknowledgedBy = actorID

	return e.alertStore.Set(ctx, string(id), alert)
}

// ResolveAlert resolves an alert
func (e *Engine) ResolveAlert(ctx context.Context, id types.ID, actorID types.ID) error {
	alert, err := e.GetAlert(ctx, id)
	if err != nil {
		return err
	}

	now := time.Now()
	alert.Status = AlertStatusResolved
	alert.ResolvedAt = &now
	alert.ResolvedBy = actorID

	return e.alertStore.Set(ctx, string(id), alert)
}

// CreateNotifier creates a new notifier
func (e *Engine) CreateNotifier(ctx context.Context, notifier *Notifier) error {
	id, err := e.crypto.GenerateRandomID()
	if err != nil {
		return err
	}

	notifier.ID = id
	notifier.CreatedAt = types.Now()
	notifier.Status = types.StatusActive
	notifier.Enabled = true

	if err := e.notifierStore.Set(ctx, string(notifier.ID), notifier); err != nil {
		return err
	}

	e.mu.Lock()
	e.notifiers[notifier.ID] = notifier
	e.mu.Unlock()

	return nil
}

// GetNotifier retrieves a notifier by ID
func (e *Engine) GetNotifier(ctx context.Context, id types.ID) (*Notifier, error) {
	e.mu.RLock()
	if n, ok := e.notifiers[id]; ok {
		e.mu.RUnlock()
		return n, nil
	}
	e.mu.RUnlock()
	return e.notifierStore.Get(ctx, string(id))
}

// ListNotifiers lists all notifiers
func (e *Engine) ListNotifiers(ctx context.Context) ([]*Notifier, error) {
	return e.notifierStore.List(ctx, "")
}

// DeleteNotifier deletes a notifier
func (e *Engine) DeleteNotifier(ctx context.Context, id types.ID) error {
	e.mu.Lock()
	delete(e.notifiers, id)
	e.mu.Unlock()
	return e.notifierStore.Delete(ctx, string(id))
}

// GetActiveAlertCount returns count of active alerts
func (e *Engine) GetActiveAlertCount(ctx context.Context, orgID types.ID) (int, error) {
	alerts, err := e.ListAlerts(ctx, ListAlertsOptions{
		Status: AlertStatusActive,
		OrgID:  orgID,
	})
	if err != nil {
		return 0, err
	}
	return len(alerts), nil
}

// TestNotifier tests a notifier by sending a test message
func (e *Engine) TestNotifier(ctx context.Context, id types.ID) error {
	notifier, err := e.GetNotifier(ctx, id)
	if err != nil {
		return err
	}

	testAlert := &Alert{
		ID:          types.ID("test"),
		RuleName:    "Test Alert",
		Severity:    AlertSeverityInfo,
		Status:      AlertStatusActive,
		Title:       "[TEST] Alert Notification Test",
		Description: "This is a test notification to verify notifier configuration.",
		Source:      "secretr-alert-engine",
		TriggeredAt: time.Now(),
	}

	return e.sendToNotifier(ctx, notifier, testAlert)
}

// Close cleans up resources
func (e *Engine) Close() error {
	close(e.stopCh)
	return e.crypto.Close()
}

// Unused import fix
var _ = template.Must
