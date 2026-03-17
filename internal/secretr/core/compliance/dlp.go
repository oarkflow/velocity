// Package compliance provides DLP (Data Loss Prevention) functionality.
package compliance

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrDLPRuleNotFound = errors.New("dlp: rule not found")
	ErrDLPViolation    = errors.New("dlp: policy violation detected")
	ErrInvalidPattern  = errors.New("dlp: invalid pattern")
)

// DLPAction represents the action to take when a rule matches
type DLPAction string

const (
	DLPActionAlert      DLPAction = "alert"
	DLPActionBlock      DLPAction = "block"
	DLPActionRedact     DLPAction = "redact"
	DLPActionQuarantine DLPAction = "quarantine"
	DLPActionLog        DLPAction = "log"
)

// DLPSeverity represents the severity of a DLP violation
type DLPSeverity string

const (
	DLPSeverityCritical DLPSeverity = "critical"
	DLPSeverityHigh     DLPSeverity = "high"
	DLPSeverityMedium   DLPSeverity = "medium"
	DLPSeverityLow      DLPSeverity = "low"
)

// DLPRule represents a data loss prevention rule
type DLPRule struct {
	ID                types.ID           `json:"id"`
	Name              string             `json:"name"`
	Description       string             `json:"description"`
	Enabled           bool               `json:"enabled"`
	PatternType       PatternType        `json:"pattern_type"`
	Patterns          []string           `json:"patterns"`
	CompiledPatterns  []*regexp.Regexp   `json:"-"`
	Keywords          []string           `json:"keywords,omitempty"`
	Classification    DataClassification `json:"classification"`
	Severity          DLPSeverity        `json:"severity"`
	Actions           []DLPAction        `json:"actions"`
	ExceptionPatterns []string           `json:"exception_patterns,omitempty"`
	AppliesTo         []string           `json:"applies_to"` // "secrets", "files", "all"
	CreatedAt         types.Timestamp    `json:"created_at"`
	UpdatedAt         types.Timestamp    `json:"updated_at"`
	CreatedBy         types.ID           `json:"created_by"`
	Status            types.EntityStatus `json:"status"`
}

// PatternType represents the type of pattern matching
type PatternType string

const (
	PatternTypeRegex   PatternType = "regex"
	PatternTypeKeyword PatternType = "keyword"
	PatternTypeBuiltIn PatternType = "builtin"
)

// DLPViolation represents a detected DLP violation
type DLPViolation struct {
	ID           types.ID        `json:"id"`
	RuleID       types.ID        `json:"rule_id"`
	RuleName     string          `json:"rule_name"`
	ResourceID   types.ID        `json:"resource_id"`
	ResourceType string          `json:"resource_type"`
	Severity     DLPSeverity     `json:"severity"`
	Actions      []DLPAction     `json:"actions"`
	MatchedData  []MatchedData   `json:"matched_data"`
	DetectedAt   types.Timestamp `json:"detected_at"`
	ActorID      types.ID        `json:"actor_id"`
	Status       string          `json:"status"` // pending, reviewed, dismissed, remediated
	Metadata     types.Metadata  `json:"metadata,omitempty"`
}

// MatchedData represents data that matched a DLP rule
type MatchedData struct {
	Pattern  string `json:"pattern"`
	Match    string `json:"match"`
	Location string `json:"location"` // field name or byte range
	Redacted string `json:"redacted,omitempty"`
}

// DLPEngine provides data loss prevention functionality
type DLPEngine struct {
	mu              sync.RWMutex
	store           *storage.Store
	crypto          *crypto.Engine
	ruleStore       *storage.TypedStore[DLPRule]
	violationStore  *storage.TypedStore[DLPViolation]
	rules           map[types.ID]*DLPRule
	builtinPatterns map[string]*regexp.Regexp
}

// DLPEngineConfig configures the DLP engine
type DLPEngineConfig struct {
	Store *storage.Store
}

// NewDLPEngine creates a new DLP engine
func NewDLPEngine(cfg DLPEngineConfig) *DLPEngine {
	e := &DLPEngine{
		store:           cfg.Store,
		crypto:          crypto.NewEngine(""),
		ruleStore:       storage.NewTypedStore[DLPRule](cfg.Store, "dlp_rules"),
		violationStore:  storage.NewTypedStore[DLPViolation](cfg.Store, "dlp_violations"),
		rules:           make(map[types.ID]*DLPRule),
		builtinPatterns: make(map[string]*regexp.Regexp),
	}
	e.initializeBuiltinPatterns()
	return e
}

// initializeBuiltinPatterns sets up common sensitive data patterns
func (e *DLPEngine) initializeBuiltinPatterns() {
	patterns := map[string]string{
		// Credit Cards
		"credit_card_visa":       `\b4[0-9]{12}(?:[0-9]{3})?\b`,
		"credit_card_mastercard": `\b5[1-5][0-9]{14}\b`,
		"credit_card_amex":       `\b3[47][0-9]{13}\b`,
		"credit_card_discover":   `\b6(?:011|5[0-9]{2})[0-9]{12}\b`,
		"credit_card_generic":    `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`,

		// Social Security Numbers
		"ssn_us":         `\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b`,
		"ssn_us_no_dash": `\b(?!000|666|9\d{2})\d{3}(?!00)\d{2}(?!0000)\d{4}\b`,

		// Identification Numbers
		"passport_us":             `\b[A-Z][0-9]{8}\b`,
		"drivers_license_generic": `\b[A-Z]{1,2}[0-9]{4,14}\b`,

		// Financial
		"iban":           `\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b`,
		"swift_bic":      `\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b`,
		"routing_number": `\b[0-9]{9}\b`,

		// Healthcare
		"npi": `\b[0-9]{10}\b`,          // National Provider Identifier
		"dea": `\b[A-Z]{2}[0-9]{6,7}\b`, // DEA Number

		// API Keys & Secrets
		"aws_access_key":  `\bAKIA[0-9A-Z]{16}\b`,
		"aws_secret_key":  `\b[A-Za-z0-9/+=]{40}\b`,
		"github_token":    `\b(gh[ps]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b`,
		"generic_api_key": `\b[a-zA-Z0-9]{32,64}\b`,
		"private_key":     `-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----`,
		"jwt_token":       `\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b`,

		// Personal Information
		"email":               `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
		"phone_us":            `\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`,
		"phone_international": `\b\+[1-9]\d{1,14}\b`,
		"ip_address_v4":       `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,

		// Date of Birth patterns
		"dob_format1": `\b(0[1-9]|1[0-2])/(0[1-9]|[12][0-9]|3[01])/(19|20)\d{2}\b`,
		"dob_format2": `\b(19|20)\d{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])\b`,
	}

	for name, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err == nil {
			e.builtinPatterns[name] = compiled
		}
	}
}

// CreateRule creates a new DLP rule
func (e *DLPEngine) CreateRule(ctx context.Context, opts CreateDLPRuleOptions) (*DLPRule, error) {
	id, err := e.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	rule := &DLPRule{
		ID:                id,
		Name:              opts.Name,
		Description:       opts.Description,
		Enabled:           true,
		PatternType:       opts.PatternType,
		Patterns:          opts.Patterns,
		Keywords:          opts.Keywords,
		Classification:    opts.Classification,
		Severity:          opts.Severity,
		Actions:           opts.Actions,
		ExceptionPatterns: opts.ExceptionPatterns,
		AppliesTo:         opts.AppliesTo,
		CreatedAt:         types.Now(),
		UpdatedAt:         types.Now(),
		CreatedBy:         opts.CreatedBy,
		Status:            types.StatusActive,
	}

	// Compile regex patterns
	if rule.PatternType == PatternTypeRegex {
		for _, p := range rule.Patterns {
			compiled, err := regexp.Compile(p)
			if err != nil {
				return nil, ErrInvalidPattern
			}
			rule.CompiledPatterns = append(rule.CompiledPatterns, compiled)
		}
	}

	if err := e.ruleStore.Set(ctx, string(rule.ID), rule); err != nil {
		return nil, err
	}

	e.mu.Lock()
	e.rules[rule.ID] = rule
	e.mu.Unlock()

	return rule, nil
}

// CreateDLPRuleOptions holds options for creating a DLP rule
type CreateDLPRuleOptions struct {
	Name              string
	Description       string
	PatternType       PatternType
	Patterns          []string
	Keywords          []string
	Classification    DataClassification
	Severity          DLPSeverity
	Actions           []DLPAction
	ExceptionPatterns []string
	AppliesTo         []string
	CreatedBy         types.ID
}

// GetRule retrieves a rule by ID
func (e *DLPEngine) GetRule(ctx context.Context, id types.ID) (*DLPRule, error) {
	e.mu.RLock()
	if rule, ok := e.rules[id]; ok {
		e.mu.RUnlock()
		return rule, nil
	}
	e.mu.RUnlock()
	return e.ruleStore.Get(ctx, string(id))
}

// ListRules lists all DLP rules
func (e *DLPEngine) ListRules(ctx context.Context) ([]*DLPRule, error) {
	return e.ruleStore.List(ctx, "")
}

// UpdateRule updates a DLP rule
func (e *DLPEngine) UpdateRule(ctx context.Context, id types.ID, opts UpdateDLPRuleOptions) (*DLPRule, error) {
	rule, err := e.GetRule(ctx, id)
	if err != nil {
		return nil, err
	}

	if opts.Name != "" {
		rule.Name = opts.Name
	}
	if opts.Description != "" {
		rule.Description = opts.Description
	}
	if opts.Severity != "" {
		rule.Severity = opts.Severity
	}
	if len(opts.Actions) > 0 {
		rule.Actions = opts.Actions
	}
	if opts.Enabled != nil {
		rule.Enabled = *opts.Enabled
	}

	rule.UpdatedAt = types.Now()

	if err := e.ruleStore.Set(ctx, string(rule.ID), rule); err != nil {
		return nil, err
	}

	e.mu.Lock()
	e.rules[rule.ID] = rule
	e.mu.Unlock()

	return rule, nil
}

// UpdateDLPRuleOptions holds options for updating a DLP rule
type UpdateDLPRuleOptions struct {
	Name        string
	Description string
	Severity    DLPSeverity
	Actions     []DLPAction
	Enabled     *bool
}

// DeleteRule deletes a DLP rule
func (e *DLPEngine) DeleteRule(ctx context.Context, id types.ID) error {
	e.mu.Lock()
	delete(e.rules, id)
	e.mu.Unlock()
	return e.ruleStore.Delete(ctx, string(id))
}

// ScanContent scans content for DLP violations
func (e *DLPEngine) ScanContent(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
	result := &ScanResult{
		Violations:      []DLPViolation{},
		HighestSeverity: DLPSeverityLow,
		BlockRequired:   false,
		ScannedAt:       time.Now(),
	}

	// Load all enabled rules
	rules, err := e.ListRules(ctx)
	if err != nil {
		return nil, err
	}

	content := string(opts.Content)

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// Check if rule applies to this resource type
		if !e.ruleApplies(rule, opts.ResourceType) {
			continue
		}

		matches := e.findMatches(content, rule)
		if len(matches) > 0 {
			id, _ := e.crypto.GenerateRandomID()
			violation := DLPViolation{
				ID:           id,
				RuleID:       rule.ID,
				RuleName:     rule.Name,
				ResourceID:   opts.ResourceID,
				ResourceType: opts.ResourceType,
				Severity:     rule.Severity,
				Actions:      rule.Actions,
				MatchedData:  matches,
				DetectedAt:   types.Now(),
				ActorID:      opts.ActorID,
				Status:       "pending",
			}

			result.Violations = append(result.Violations, violation)

			// Update highest severity
			if e.severityRank(rule.Severity) > e.severityRank(result.HighestSeverity) {
				result.HighestSeverity = rule.Severity
			}

			// Check if blocking is required
			for _, action := range rule.Actions {
				if action == DLPActionBlock {
					result.BlockRequired = true
				}
			}

			// Store violation
			_ = e.violationStore.Set(ctx, string(violation.ID), &violation)
		}
	}

	return result, nil
}

// ScanOptions holds options for scanning content
type ScanOptions struct {
	Content      []byte
	ResourceID   types.ID
	ResourceType string
	ActorID      types.ID
}

// ScanResult represents the result of a DLP scan
type ScanResult struct {
	Violations      []DLPViolation `json:"violations"`
	HighestSeverity DLPSeverity    `json:"highest_severity"`
	BlockRequired   bool           `json:"block_required"`
	ScannedAt       time.Time      `json:"scanned_at"`
}

// ruleApplies checks if a rule applies to a resource type
func (e *DLPEngine) ruleApplies(rule *DLPRule, resourceType string) bool {
	for _, applies := range rule.AppliesTo {
		if applies == "all" || applies == resourceType {
			return true
		}
	}
	return false
}

// findMatches finds matches in content for a rule
func (e *DLPEngine) findMatches(content string, rule *DLPRule) []MatchedData {
	var matches []MatchedData

	switch rule.PatternType {
	case PatternTypeRegex:
		for i, pattern := range rule.Patterns {
			if i < len(rule.CompiledPatterns) && rule.CompiledPatterns[i] != nil {
				found := rule.CompiledPatterns[i].FindAllString(content, -1)
				for _, match := range found {
					matches = append(matches, MatchedData{
						Pattern:  pattern,
						Match:    match,
						Redacted: e.redactMatch(match),
					})
				}
			}
		}

	case PatternTypeKeyword:
		lowerContent := strings.ToLower(content)
		for _, keyword := range rule.Keywords {
			if strings.Contains(lowerContent, strings.ToLower(keyword)) {
				matches = append(matches, MatchedData{
					Pattern: keyword,
					Match:   keyword,
				})
			}
		}

	case PatternTypeBuiltIn:
		for _, patternName := range rule.Patterns {
			if compiled, ok := e.builtinPatterns[patternName]; ok {
				found := compiled.FindAllString(content, -1)
				for _, match := range found {
					matches = append(matches, MatchedData{
						Pattern:  patternName,
						Match:    match,
						Redacted: e.redactMatch(match),
					})
				}
			}
		}
	}

	return matches
}

// redactMatch redacts sensitive data
func (e *DLPEngine) redactMatch(match string) string {
	if len(match) <= 4 {
		return strings.Repeat("*", len(match))
	}
	return match[:2] + strings.Repeat("*", len(match)-4) + match[len(match)-2:]
}

// severityRank returns numeric rank for severity comparison
func (e *DLPEngine) severityRank(severity DLPSeverity) int {
	switch severity {
	case DLPSeverityCritical:
		return 4
	case DLPSeverityHigh:
		return 3
	case DLPSeverityMedium:
		return 2
	case DLPSeverityLow:
		return 1
	default:
		return 0
	}
}

// GetViolation retrieves a violation by ID
func (e *DLPEngine) GetViolation(ctx context.Context, id types.ID) (*DLPViolation, error) {
	return e.violationStore.Get(ctx, string(id))
}

// ListViolations lists violations with optional filters
func (e *DLPEngine) ListViolations(ctx context.Context, opts ListViolationsOptions) ([]*DLPViolation, error) {
	all, err := e.violationStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var violations []*DLPViolation
	for _, v := range all {
		// Apply filters
		if opts.Status != "" && v.Status != opts.Status {
			continue
		}
		if opts.Severity != "" && v.Severity != opts.Severity {
			continue
		}
		if opts.RuleID != "" && v.RuleID != opts.RuleID {
			continue
		}
		violations = append(violations, v)
	}

	return violations, nil
}

// ListViolationsOptions holds options for listing violations
type ListViolationsOptions struct {
	Status   string
	Severity DLPSeverity
	RuleID   types.ID
}

// UpdateViolationStatus updates the status of a violation
func (e *DLPEngine) UpdateViolationStatus(ctx context.Context, id types.ID, status string) error {
	violation, err := e.GetViolation(ctx, id)
	if err != nil {
		return err
	}

	violation.Status = status
	return e.violationStore.Set(ctx, string(id), violation)
}

// GetBuiltinPatterns returns available builtin pattern names
func (e *DLPEngine) GetBuiltinPatterns() []string {
	patterns := make([]string, 0, len(e.builtinPatterns))
	for name := range e.builtinPatterns {
		patterns = append(patterns, name)
	}
	return patterns
}

// Close cleans up resources
func (e *DLPEngine) Close() error {
	return e.crypto.Close()
}
