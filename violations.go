package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ComplianceViolation represents a compliance rule violation
type ComplianceViolation struct {
	ViolationID    string    `json:"violation_id"`
	Timestamp      time.Time `json:"timestamp"`
	Actor          string    `json:"actor"`
	ActorRole      string    `json:"actor_role"`
	Path           string    `json:"path"`
	Operation      string    `json:"operation"`
	Rules          []string  `json:"rules"`           // Violated rules
	Frameworks     []string  `json:"frameworks"`      // Affected frameworks
	Severity       string    `json:"severity"`        // critical, high, medium, low
	DataClass      string    `json:"data_class"`      // Data classification
	IPAddress      string    `json:"ip_address"`
	MFAStatus      string    `json:"mfa_status"`      // verified, not_verified, not_required
	EncryptionUsed bool      `json:"encryption_used"`
	Resolved       bool      `json:"resolved"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	ResolvedBy     string    `json:"resolved_by,omitempty"`
	ResolutionNote string    `json:"resolution_note,omitempty"`
	Impact         string    `json:"impact"`          // Description of impact
	Remediation    string    `json:"remediation"`     // Recommended remediation
	ReportedToSOC  bool      `json:"reported_to_soc"` // Escalated to security team
	TicketID       string    `json:"ticket_id,omitempty"` // External ticket reference
}

// ViolationsManager manages compliance violations
type ViolationsManager struct {
	db           *DB
	violations   map[string]*ComplianceViolation // violationID -> violation
	mu           sync.RWMutex
	alertManager *AlertManager
	breachSystem *BreachNotificationSystem
}

// NewViolationsManager creates a new violations manager
func NewViolationsManager(db *DB) *ViolationsManager {
	vm := &ViolationsManager{
		db:         db,
		violations: make(map[string]*ComplianceViolation),
	}
	vm.loadViolations()
	return vm
}

// SetAlertManager sets the alert manager for critical violations
func (vm *ViolationsManager) SetAlertManager(am *AlertManager) {
	vm.alertManager = am
}

// SetBreachNotificationSystem sets the breach notification system for critical violations.
func (vm *ViolationsManager) SetBreachNotificationSystem(bns *BreachNotificationSystem) {
	vm.breachSystem = bns
}

// RecordViolation records a compliance violation
func (vm *ViolationsManager) RecordViolation(ctx context.Context, violation *ComplianceViolation) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Set defaults
	if violation.ViolationID == "" {
		violation.ViolationID = fmt.Sprintf("violation:%d", time.Now().UnixNano())
	}
	if violation.Timestamp.IsZero() {
		violation.Timestamp = time.Now()
	}
	if violation.Severity == "" {
		violation.Severity = vm.calculateSeverity(violation)
	}

	violation.Resolved = false

	// Store in memory
	vm.violations[violation.ViolationID] = violation

	// Persist to database
	data, err := json.Marshal(violation)
	if err != nil {
		return fmt.Errorf("failed to marshal violation: %w", err)
	}

	key := []byte("compliance:violation:" + violation.ViolationID)
	if err := vm.db.Put(key, data); err != nil {
		return fmt.Errorf("failed to persist violation: %w", err)
	}

	// Send alert for critical/high severity violations
	if (violation.Severity == "critical" || violation.Severity == "high") && vm.alertManager != nil {
		go vm.alertManager.SendAlert(&Alert{
			Severity: violation.Severity,
			Type:     "compliance_violation",
			Message:  fmt.Sprintf("Compliance violation by %s on %s", violation.Actor, violation.Path),
			Details: map[string]interface{}{
				"violation_id": violation.ViolationID,
				"actor":        violation.Actor,
				"path":         violation.Path,
				"rules":        violation.Rules,
				"frameworks":   violation.Frameworks,
			},
		})
	}

	// Create breach incident for critical violations
	if violation.Severity == "critical" && vm.breachSystem != nil {
		incident := &BreachIncident{
			Severity:      violation.Severity,
			Description:   fmt.Sprintf("Critical compliance violation on %s", violation.Path),
			Frameworks:    frameworksToCompliance(violation.Frameworks),
			AffectedCount: 1,
		}
		go vm.breachSystem.ReportIncident(context.Background(), incident)
	}

	return nil
}

// RecordFromValidation creates a violation from a validation result
func (vm *ViolationsManager) RecordFromValidation(
	ctx context.Context,
	req *ComplianceOperationRequest,
	result *ComplianceValidationResult,
) error {
	if result.Allowed {
		return nil // No violation
	}

	frameworks := make([]string, 0)
	dataClass := ""
	if result.AppliedTag != nil {
		for _, fw := range result.AppliedTag.Frameworks {
			frameworks = append(frameworks, string(fw))
		}
		dataClass = string(result.AppliedTag.DataClass)
	}

	mfaStatus := "not_verified"
	if req.MFAVerified {
		mfaStatus = "verified"
	}

	violation := &ComplianceViolation{
		Actor:          req.Actor,
		Path:           req.Path,
		Operation:      req.Operation,
		Rules:          result.ViolatedRules,
		Frameworks:     frameworks,
		DataClass:      dataClass,
		IPAddress:      req.IPAddress,
		MFAStatus:      mfaStatus,
		EncryptionUsed: req.Encrypted,
		Impact:         fmt.Sprintf("Attempted %s on %s classification data", req.Operation, dataClass),
		Remediation:    vm.generateRemediation(result.ViolatedRules),
	}

	return vm.RecordViolation(ctx, violation)
}

// ResolveViolation marks a violation as resolved
func (vm *ViolationsManager) ResolveViolation(
	ctx context.Context,
	violationID, resolvedBy, note string,
) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	violation, exists := vm.violations[violationID]
	if !exists {
		return fmt.Errorf("violation not found: %s", violationID)
	}

	now := time.Now()
	violation.Resolved = true
	violation.ResolvedAt = &now
	violation.ResolvedBy = resolvedBy
	violation.ResolutionNote = note

	// Update in database
	data, err := json.Marshal(violation)
	if err != nil {
		return fmt.Errorf("failed to marshal violation: %w", err)
	}

	key := []byte("compliance:violation:" + violation.ViolationID)
	return vm.db.Put(key, data)
}

// GetViolations retrieves violations with filtering
func (vm *ViolationsManager) GetViolations(filter *ViolationFilter) ([]*ComplianceViolation, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	violations := make([]*ComplianceViolation, 0)

	for _, v := range vm.violations {
		// Apply filters
		if filter != nil {
			if filter.Actor != "" && v.Actor != filter.Actor {
				continue
			}
			if filter.Severity != "" && v.Severity != filter.Severity {
				continue
			}
			if filter.Resolved != nil && v.Resolved != *filter.Resolved {
				continue
			}
			if !filter.StartTime.IsZero() && v.Timestamp.Before(filter.StartTime) {
				continue
			}
			if !filter.EndTime.IsZero() && v.Timestamp.After(filter.EndTime) {
				continue
			}
			if filter.Framework != "" {
				hasFramework := false
				for _, fw := range v.Frameworks {
					if fw == filter.Framework {
						hasFramework = true
						break
					}
				}
				if !hasFramework {
					continue
				}
			}
		}

		violations = append(violations, v)
	}

	return violations, nil
}

// GetViolationStats generates statistics about violations
func (vm *ViolationsManager) GetViolationStats(ctx context.Context, filter *ViolationFilter) (*ViolationStats, error) {
	violations, err := vm.GetViolations(filter)
	if err != nil {
		return nil, err
	}

	stats := &ViolationStats{
		Total:          len(violations),
		BySeverity:     make(map[string]int),
		ByActor:        make(map[string]int),
		ByFramework:    make(map[string]int),
		ByDataClass:    make(map[string]int),
		TopViolators:   make([]ActorViolation, 0),
		UnresolvedCount: 0,
	}

	actorViolations := make(map[string]*ActorViolation)

	for _, v := range violations {
		// Severity breakdown
		stats.BySeverity[v.Severity]++

		// Actor breakdown
		stats.ByActor[v.Actor]++
		if actorViolations[v.Actor] == nil {
			actorViolations[v.Actor] = &ActorViolation{
				Actor: v.Actor,
				Count: 0,
				Rules: make([]string, 0),
			}
		}
		actorViolations[v.Actor].Count++
		actorViolations[v.Actor].Rules = append(actorViolations[v.Actor].Rules, v.Rules...)

		// Framework breakdown
		for _, fw := range v.Frameworks {
			stats.ByFramework[fw]++
		}

		// Data class breakdown
		if v.DataClass != "" {
			stats.ByDataClass[v.DataClass]++
		}

		// Unresolved count
		if !v.Resolved {
			stats.UnresolvedCount++
		}
	}

	// Sort top violators
	for _, av := range actorViolations {
		stats.TopViolators = append(stats.TopViolators, *av)
	}
	// Sort by count
	for i := 0; i < len(stats.TopViolators)-1; i++ {
		for j := i + 1; j < len(stats.TopViolators); j++ {
			if stats.TopViolators[i].Count < stats.TopViolators[j].Count {
				stats.TopViolators[i], stats.TopViolators[j] =
					stats.TopViolators[j], stats.TopViolators[i]
			}
		}
	}
	if len(stats.TopViolators) > 10 {
		stats.TopViolators = stats.TopViolators[:10]
	}

	return stats, nil
}

// calculateSeverity determines violation severity based on rules
func (vm *ViolationsManager) calculateSeverity(v *ComplianceViolation) string {
	// Critical if:
	// - Restricted data without encryption
	// - Multiple framework violations
	// - No MFA on restricted data
	if v.DataClass == "restricted" && !v.EncryptionUsed {
		return "critical"
	}
	if len(v.Frameworks) > 2 {
		return "critical"
	}
	if v.DataClass == "restricted" && v.MFAStatus != "verified" {
		return "critical"
	}

	// High if:
	// - Confidential data violations
	// - Multiple rule violations
	if v.DataClass == "confidential" && !v.EncryptionUsed {
		return "high"
	}
	if len(v.Rules) >= 3 {
		return "high"
	}

	// Medium if:
	// - Single framework violation
	// - Internal data
	if len(v.Rules) >= 2 {
		return "medium"
	}

	return "low"
}

// generateRemediation suggests remediation steps
func (vm *ViolationsManager) generateRemediation(rules []string) string {
	remediations := []string{}

	for _, rule := range rules {
		if strings.Contains(rule, "encryption") {
			remediations = append(remediations, "Enable encryption for this data")
		}
		if strings.Contains(rule, "MFA") {
			remediations = append(remediations, "Require MFA authentication")
		}
		if strings.Contains(rule, "retention") {
			remediations = append(remediations, "Review and enforce retention policy")
		}
		if strings.Contains(rule, "consent") {
			remediations = append(remediations, "Obtain user consent")
		}
	}

	if len(remediations) == 0 {
		return "Review compliance requirements and update access controls"
	}

	result := ""
	for i, r := range remediations {
		result += fmt.Sprintf("%d. %s\n", i+1, r)
	}
	return result
}

// loadViolations loads violations from database
func (vm *ViolationsManager) loadViolations() error {
	keys, err := vm.db.Keys("compliance:violation:*")
	if err != nil {
		return err
	}

	for _, key := range keys {
		data, err := vm.db.Get([]byte(key))
		if err != nil {
			continue
		}

		var violation ComplianceViolation
		if err := json.Unmarshal(data, &violation); err != nil {
			continue
		}

		vm.violations[violation.ViolationID] = &violation
	}

	return nil
}

// ExportViolations exports violations to JSON
func (vm *ViolationsManager) ExportViolations(filter *ViolationFilter) ([]byte, error) {
	violations, err := vm.GetViolations(filter)
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(violations, "", "  ")
}

func frameworksToCompliance(frameworks []string) []ComplianceFramework {
	result := make([]ComplianceFramework, 0, len(frameworks))
	for _, fw := range frameworks {
		result = append(result, ComplianceFramework(fw))
	}
	return result
}

// ViolationFilter defines criteria for filtering violations
type ViolationFilter struct {
	Actor      string
	Severity   string
	Framework  string
	Resolved   *bool
	StartTime  time.Time
	EndTime    time.Time
	DataClass  string
}

// ViolationStats provides statistics about violations
type ViolationStats struct {
	Total           int
	UnresolvedCount int
	BySeverity      map[string]int
	ByActor         map[string]int
	ByFramework     map[string]int
	ByDataClass     map[string]int
	TopViolators    []ActorViolation
}

// ActorViolation represents violation stats for an actor
type ActorViolation struct {
	Actor string
	Count int
	Rules []string
}

// Alert represents a compliance alert
type Alert struct {
	AlertID   string
	Timestamp time.Time
	Severity  string
	Type      string
	Message   string
	Details   map[string]interface{}
}

// AlertManager manages compliance alerts with webhook support
type AlertManager struct {
	db         *DB
	webhooks   []WebhookConfig
	mu         sync.RWMutex
	rateLimits map[string]*RateLimiter
}

// WebhookConfig defines a webhook endpoint
type WebhookConfig struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"` // POST, PUT
	Headers     map[string]string `json:"headers"`
	Secret      string            `json:"secret"`       // For HMAC signing
	MinSeverity string            `json:"min_severity"` // minimum severity to trigger
	Events      []string          `json:"events"`       // event types to send
	Enabled     bool              `json:"enabled"`
	RetryCount  int               `json:"retry_count"`
	Timeout     int               `json:"timeout_seconds"`
}

// RateLimiter prevents alert flooding
type RateLimiter struct {
	lastSent  time.Time
	count     int
	window    time.Duration
	maxAlerts int
}

// NewAlertManager creates a new alert manager
func NewAlertManager(db *DB) *AlertManager {
	return &AlertManager{
		db:         db,
		webhooks:   make([]WebhookConfig, 0),
		rateLimits: make(map[string]*RateLimiter),
	}
}

// AddWebhook adds a webhook URL for alerts
func (am *AlertManager) AddWebhook(webhook WebhookConfig) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if webhook.Method == "" {
		webhook.Method = "POST"
	}
	if webhook.Timeout == 0 {
		webhook.Timeout = 10
	}
	if webhook.RetryCount == 0 {
		webhook.RetryCount = 3
	}

	am.webhooks = append(am.webhooks, webhook)
}

// SendAlert sends a compliance alert with rate limiting
func (am *AlertManager) SendAlert(alert *Alert) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if alert.AlertID == "" {
		alert.AlertID = fmt.Sprintf("alert:%d", time.Now().UnixNano())
	}
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now()
	}

	// Check rate limiting
	if !am.checkRateLimit(alert) {
		return fmt.Errorf("rate limit exceeded for alert type: %s", alert.Type)
	}

	// Store alert
	data, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	key := []byte("compliance:alert:" + alert.AlertID)
	if err := am.db.Put(key, data); err != nil {
		return fmt.Errorf("failed to persist alert: %w", err)
	}

	// Send to webhooks asynchronously
	for _, webhook := range am.webhooks {
		if !webhook.Enabled {
			continue
		}

		// Check severity threshold
		if !am.meetsMinSeverity(alert.Severity, webhook.MinSeverity) {
			continue
		}

		// Check event type filter
		if len(webhook.Events) > 0 && !am.matchesEventType(alert.Type, webhook.Events) {
			continue
		}

		go am.sendWebhook(alert, webhook)
	}

	// Console log for visibility
	fmt.Printf("[ALERT] %s: %s - %s\n", alert.Severity, alert.Type, alert.Message)

	return nil
}

// checkRateLimit checks if alert should be sent based on rate limiting
func (am *AlertManager) checkRateLimit(alert *Alert) bool {
	limiter, exists := am.rateLimits[alert.Type]
	if !exists {
		// Create new rate limiter: max 10 alerts per minute
		limiter = &RateLimiter{
			window:    time.Minute,
			maxAlerts: 10,
		}
		am.rateLimits[alert.Type] = limiter
	}

	now := time.Now()

	// Reset counter if window expired
	if now.Sub(limiter.lastSent) > limiter.window {
		limiter.count = 0
		limiter.lastSent = now
	}

	// Check limit
	if limiter.count >= limiter.maxAlerts {
		return false
	}

	limiter.count++
	return true
}

// meetsMinSeverity checks if alert severity meets webhook minimum
func (am *AlertManager) meetsMinSeverity(alertSeverity, minSeverity string) bool {
	if minSeverity == "" {
		return true
	}

	severityLevels := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	alertLevel := severityLevels[alertSeverity]
	minLevel := severityLevels[minSeverity]

	return alertLevel >= minLevel
}

// matchesEventType checks if alert type matches webhook event filter
func (am *AlertManager) matchesEventType(alertType string, events []string) bool {
	for _, event := range events {
		if event == "*" || event == alertType {
			return true
		}
	}
	return false
}

// sendWebhook sends alert to webhook endpoint
func (am *AlertManager) sendWebhook(alert *Alert, webhook WebhookConfig) {
	// This is a simplified implementation
	// In production, you would:
	// 1. Use http.Client with timeout
	// 2. Add HMAC signing with webhook.Secret
	// 3. Implement retry logic with exponential backoff
	// 4. Handle different response codes appropriately

	fmt.Printf("[WEBHOOK] Sending %s alert to %s\n", alert.Severity, webhook.URL)

	// Simulate webhook call
	// In production: use net/http to make actual HTTP request
}
