// Package context provides context-aware access evaluation and risk scoring.
package context

import (
	"context"
	"errors"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrHighRiskDetected        = errors.New("context: high risk detected")
	ErrGeoLocationBlocked      = errors.New("context: geo-location not allowed")
	ErrDeviceNotTrusted        = errors.New("context: device not trusted")
	ErrNetworkNotTrusted       = errors.New("context: network not trusted")
	ErrOutsideTimeWindow       = errors.New("context: access outside allowed time window")
	ErrBehaviorAnomalyDetected = errors.New("context: behavioral anomaly detected")
)

// NetworkTrust represents network trust levels
type NetworkTrust string

const (
	NetworkTrustCorporate  NetworkTrust = "corporate"
	NetworkTrustVPN        NetworkTrust = "vpn"
	NetworkTrustKnown      NetworkTrust = "known"
	NetworkTrustPublicWifi NetworkTrust = "public_wifi"
	NetworkTrustUnknown    NetworkTrust = "unknown"
	NetworkTrustHostile    NetworkTrust = "hostile"
)

// RiskLevel represents risk levels
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// AccessDecision represents the access control decision
type AccessDecision string

const (
	AccessDecisionAllow           AccessDecision = "allow"
	AccessDecisionAllowWithMFA    AccessDecision = "allow_with_mfa"
	AccessDecisionAllowRedacted   AccessDecision = "allow_redacted"
	AccessDecisionAllowReadOnly   AccessDecision = "allow_readonly"
	AccessDecisionRequireApproval AccessDecision = "require_approval"
	AccessDecisionDeny            AccessDecision = "deny"
	AccessDecisionQuarantine      AccessDecision = "quarantine"
)

// GeoLocation represents geographic location
type GeoLocation struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	IsProxy     bool    `json:"is_proxy"`
	IsVPN       bool    `json:"is_vpn"`
	IsTor       bool    `json:"is_tor"`
}

// BrowserInfo represents browser/client information
type BrowserInfo struct {
	UserAgent  string `json:"user_agent"`
	Browser    string `json:"browser"`
	BrowserVer string `json:"browser_version"`
	OS         string `json:"os"`
	OSVersion  string `json:"os_version"`
	DeviceType string `json:"device_type"` // desktop, mobile, tablet
	IsBot      bool   `json:"is_bot"`
	IsHeadless bool   `json:"is_headless"`
}

// AccessContext represents the full context of an access request
type AccessContext struct {
	DeviceID          types.ID      `json:"device_id,omitempty"`
	DeviceFingerprint string        `json:"device_fingerprint"`
	DeviceTrustScore  float64       `json:"device_trust_score"`
	NetworkTrustLevel NetworkTrust  `json:"network_trust_level"`
	WiFiSSID          string        `json:"wifi_ssid,omitempty"`
	IPAddress         string        `json:"ip_address"`
	GeoLocation       *GeoLocation  `json:"geo_location,omitempty"`
	TimeOfAccess      time.Time     `json:"time_of_access"`
	LocalTime         time.Time     `json:"local_time,omitempty"`
	Timezone          string        `json:"timezone,omitempty"`
	UserRiskScore     float64       `json:"user_risk_score"`
	DeviceRiskScore   float64       `json:"device_risk_score"`
	NetworkRiskScore  float64       `json:"network_risk_score"`
	OverallRiskScore  float64       `json:"overall_risk_score"`
	RiskLevel         RiskLevel     `json:"risk_level"`
	IsRooted          bool          `json:"is_rooted"`
	IsJailbroken      bool          `json:"is_jailbroken"`
	BrowserInfo       *BrowserInfo  `json:"browser_info,omitempty"`
	SessionAge        time.Duration `json:"session_age"`
	RecentFailures    int           `json:"recent_failures"`
	AccessPattern     string        `json:"access_pattern,omitempty"` // normal, unusual, anomalous
}

// ContextPolicy defines context-based access rules
type ContextPolicy struct {
	ID                  types.ID           `json:"id"`
	Name                string             `json:"name"`
	Description         string             `json:"description"`
	AllowedCountries    []string           `json:"allowed_countries,omitempty"`
	BlockedCountries    []string           `json:"blocked_countries,omitempty"`
	AllowedIPRanges     []string           `json:"allowed_ip_ranges,omitempty"`
	BlockedIPRanges     []string           `json:"blocked_ip_ranges,omitempty"`
	AllowedNetworkTypes []NetworkTrust     `json:"allowed_network_types,omitempty"`
	AllowedWiFiSSIDs    []string           `json:"allowed_wifi_ssids,omitempty"`
	AllowedTimeWindows  []TimeWindowDef    `json:"allowed_time_windows,omitempty"`
	MaxRiskScore        float64            `json:"max_risk_score"`
	RequireMFAAbove     float64            `json:"require_mfa_above_risk"`
	BlockRootedDevices  bool               `json:"block_rooted_devices"`
	RequireDeviceTrust  float64            `json:"require_device_trust"`
	Actions             PolicyActions      `json:"actions"`
	CreatedAt           types.Timestamp    `json:"created_at"`
	UpdatedAt           types.Timestamp    `json:"updated_at"`
	Status              types.EntityStatus `json:"status"`
}

// TimeWindowDef defines a time window for access
type TimeWindowDef struct {
	Name      string `json:"name"`
	StartTime string `json:"start_time"` // HH:MM
	EndTime   string `json:"end_time"`   // HH:MM
	Days      []int  `json:"days"`       // 0=Sunday
	Timezone  string `json:"timezone"`
}

// PolicyActions defines actions to take based on context
type PolicyActions struct {
	OnHighRisk      AccessDecision `json:"on_high_risk"`
	OnMediumRisk    AccessDecision `json:"on_medium_risk"`
	OnUnknownGeo    AccessDecision `json:"on_unknown_geo"`
	OnBlockedGeo    AccessDecision `json:"on_blocked_geo"`
	OnPublicWifi    AccessDecision `json:"on_public_wifi"`
	OnRootedDevice  AccessDecision `json:"on_rooted_device"`
	OnTimeViolation AccessDecision `json:"on_time_violation"`
}

// AccessHistory represents historical access record for anomaly detection
type AccessHistory struct {
	IdentityID     types.ID         `json:"identity_id"`
	Locations      []GeoLocation    `json:"locations"`
	AccessTimes    []time.Time      `json:"access_times"`
	DeviceIDs      []types.ID       `json:"device_ids"`
	IPAddresses    []string         `json:"ip_addresses"`
	TypicalPattern *BehaviorPattern `json:"typical_pattern,omitempty"`
	LastUpdated    types.Timestamp  `json:"last_updated"`
}

// BehaviorPattern represents typical user behavior
type BehaviorPattern struct {
	TypicalCountries       []string      `json:"typical_countries"`
	TypicalHours           []int         `json:"typical_hours"` // 0-23
	TypicalDays            []int         `json:"typical_days"`  // 0-6
	AvgAccessesPerDay      float64       `json:"avg_accesses_per_day"`
	TypicalDeviceCount     int           `json:"typical_device_count"`
	TypicalSessionDuration time.Duration `json:"typical_session_duration"`
}

// EvaluationResult represents the result of context evaluation
type EvaluationResult struct {
	Context          *AccessContext `json:"context"`
	Decision         AccessDecision `json:"decision"`
	Reason           string         `json:"reason,omitempty"`
	RiskFactors      []RiskFactor   `json:"risk_factors,omitempty"`
	RequiredMFA      bool           `json:"required_mfa"`
	RequiredApproval bool           `json:"required_approval"`
	Recommendations  []string       `json:"recommendations,omitempty"`
	EvaluatedAt      time.Time      `json:"evaluated_at"`
}

// RiskFactor represents a factor contributing to risk
type RiskFactor struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Score       float64 `json:"score"`
	Weight      float64 `json:"weight"`
}

// Engine provides context-aware access evaluation
type Engine struct {
	mu            sync.RWMutex
	store         *storage.Store
	crypto        *crypto.Engine
	policyStore   *storage.TypedStore[ContextPolicy]
	historyStore  *storage.TypedStore[AccessHistory]
	geoProvider   GeoProvider
	knownNetworks map[string]NetworkTrust
	threatIPs     map[string]bool
}

// GeoProvider provides geo-location lookup
type GeoProvider interface {
	Lookup(ip string) (*GeoLocation, error)
}

// EngineConfig configures the context engine
type EngineConfig struct {
	Store       *storage.Store
	GeoProvider GeoProvider
}

// NewEngine creates a new context engine
func NewEngine(cfg EngineConfig) *Engine {
	e := &Engine{
		store:         cfg.Store,
		crypto:        crypto.NewEngine(""),
		policyStore:   storage.NewTypedStore[ContextPolicy](cfg.Store, "context_policies"),
		historyStore:  storage.NewTypedStore[AccessHistory](cfg.Store, "access_history"),
		geoProvider:   cfg.GeoProvider,
		knownNetworks: make(map[string]NetworkTrust),
		threatIPs:     make(map[string]bool),
	}
	e.initializeKnownNetworks()
	return e
}

// initializeKnownNetworks sets up known network classifications
func (e *Engine) initializeKnownNetworks() {
	// Common corporate VPN ranges (example)
	corporateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
	for _, r := range corporateRanges {
		e.knownNetworks[r] = NetworkTrustCorporate
	}
}

// EvaluateContext evaluates the access context and returns a decision
func (e *Engine) EvaluateContext(ctx context.Context, input ContextInput) (*EvaluationResult, error) {
	// Build full access context
	accessCtx := e.buildContext(ctx, input)

	// Calculate risk scores
	riskFactors := e.calculateRiskFactors(ctx, accessCtx, input.IdentityID)
	accessCtx.OverallRiskScore = e.aggregateRiskScore(riskFactors)
	accessCtx.RiskLevel = e.determineRiskLevel(accessCtx.OverallRiskScore)

	// Get applicable policies
	policies, err := e.listActivePolicies(ctx)
	if err != nil {
		policies = []*ContextPolicy{}
	}

	// Evaluate against policies
	result := &EvaluationResult{
		Context:     accessCtx,
		Decision:    AccessDecisionAllow,
		RiskFactors: riskFactors,
		EvaluatedAt: time.Now(),
	}

	// Apply policy rules
	for _, policy := range policies {
		decision, reason := e.evaluatePolicy(accessCtx, policy)
		if decision != AccessDecisionAllow {
			result.Decision = decision
			result.Reason = reason
			break
		}
	}

	// Default risk-based decisions if no specific policy matched
	if result.Decision == AccessDecisionAllow {
		switch accessCtx.RiskLevel {
		case RiskLevelCritical:
			result.Decision = AccessDecisionDeny
			result.Reason = "Critical risk level detected"
		case RiskLevelHigh:
			result.Decision = AccessDecisionAllowWithMFA
			result.RequiredMFA = true
			result.Reason = "High risk level requires MFA"
		case RiskLevelMedium:
			if accessCtx.OverallRiskScore > 0.6 {
				result.RequiredMFA = true
			}
		}
	}

	// Update access history for behavior learning
	_ = e.updateAccessHistory(ctx, input.IdentityID, accessCtx)

	return result, nil
}

// ContextInput represents input for context evaluation
type ContextInput struct {
	IdentityID        types.ID
	DeviceID          types.ID
	DeviceFingerprint string
	IPAddress         string
	UserAgent         string
	WiFiSSID          string
	IsRooted          bool
	SessionAge        time.Duration
	RecentFailures    int
}

// buildContext builds the full access context
func (e *Engine) buildContext(_ context.Context, input ContextInput) *AccessContext {
	accessCtx := &AccessContext{
		DeviceID:          input.DeviceID,
		DeviceFingerprint: input.DeviceFingerprint,
		IPAddress:         input.IPAddress,
		WiFiSSID:          input.WiFiSSID,
		TimeOfAccess:      time.Now(),
		IsRooted:          input.IsRooted,
		SessionAge:        input.SessionAge,
		RecentFailures:    input.RecentFailures,
	}

	// Lookup geo-location
	if e.geoProvider != nil && input.IPAddress != "" {
		if geo, err := e.geoProvider.Lookup(input.IPAddress); err == nil {
			accessCtx.GeoLocation = geo
		}
	}

	// Parse browser info from user agent
	accessCtx.BrowserInfo = e.parseUserAgent(input.UserAgent)

	// Determine network trust level
	accessCtx.NetworkTrustLevel = e.determineNetworkTrust(input.IPAddress, input.WiFiSSID)

	return accessCtx
}

// parseUserAgent parses user agent string
func (e *Engine) parseUserAgent(ua string) *BrowserInfo {
	info := &BrowserInfo{
		UserAgent: ua,
	}

	lowerUA := strings.ToLower(ua)

	// Detect device type
	if strings.Contains(lowerUA, "mobile") || strings.Contains(lowerUA, "android") {
		info.DeviceType = "mobile"
	} else if strings.Contains(lowerUA, "tablet") || strings.Contains(lowerUA, "ipad") {
		info.DeviceType = "tablet"
	} else {
		info.DeviceType = "desktop"
	}

	// Detect browser
	if strings.Contains(lowerUA, "chrome") && !strings.Contains(lowerUA, "chromium") {
		info.Browser = "Chrome"
	} else if strings.Contains(lowerUA, "firefox") {
		info.Browser = "Firefox"
	} else if strings.Contains(lowerUA, "safari") && !strings.Contains(lowerUA, "chrome") {
		info.Browser = "Safari"
	} else if strings.Contains(lowerUA, "edge") {
		info.Browser = "Edge"
	}

	// Detect OS
	if strings.Contains(lowerUA, "windows") {
		info.OS = "Windows"
	} else if strings.Contains(lowerUA, "mac os") || strings.Contains(lowerUA, "macos") {
		info.OS = "macOS"
	} else if strings.Contains(lowerUA, "linux") {
		info.OS = "Linux"
	} else if strings.Contains(lowerUA, "android") {
		info.OS = "Android"
	} else if strings.Contains(lowerUA, "ios") || strings.Contains(lowerUA, "iphone") {
		info.OS = "iOS"
	}

	// Detect headless/bot
	info.IsBot = strings.Contains(lowerUA, "bot") || strings.Contains(lowerUA, "crawler")
	info.IsHeadless = strings.Contains(lowerUA, "headless")

	return info
}

// determineNetworkTrust determines the trust level of a network
func (e *Engine) determineNetworkTrust(ip, wifiSSID string) NetworkTrust {
	// Check known hostile IPs
	e.mu.RLock()
	if e.threatIPs[ip] {
		e.mu.RUnlock()
		return NetworkTrustHostile
	}
	e.mu.RUnlock()

	// Check if it's a private IP
	if e.isPrivateIP(ip) {
		return NetworkTrustCorporate
	}

	// Check WiFi SSID patterns
	lowerSSID := strings.ToLower(wifiSSID)
	if strings.Contains(lowerSSID, "guest") || strings.Contains(lowerSSID, "public") {
		return NetworkTrustPublicWifi
	}

	// Default to unknown
	return NetworkTrustUnknown
}

// isPrivateIP checks if an IP is private
func (e *Engine) isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}

	return false
}

// calculateRiskFactors calculates individual risk factors
func (e *Engine) calculateRiskFactors(ctx context.Context, accessCtx *AccessContext, identityID types.ID) []RiskFactor {
	var factors []RiskFactor

	// Device risk
	if accessCtx.IsRooted || accessCtx.IsJailbroken {
		factors = append(factors, RiskFactor{
			Name:        "rooted_device",
			Description: "Device is rooted or jailbroken",
			Score:       0.8,
			Weight:      1.5,
		})
	}

	if accessCtx.DeviceTrustScore < 0.5 {
		factors = append(factors, RiskFactor{
			Name:        "low_device_trust",
			Description: "Device has low trust score",
			Score:       1.0 - accessCtx.DeviceTrustScore,
			Weight:      1.2,
		})
	}

	// Network risk
	switch accessCtx.NetworkTrustLevel {
	case NetworkTrustHostile:
		factors = append(factors, RiskFactor{
			Name:        "hostile_network",
			Description: "Access from hostile network",
			Score:       1.0,
			Weight:      2.0,
		})
	case NetworkTrustPublicWifi:
		factors = append(factors, RiskFactor{
			Name:        "public_wifi",
			Description: "Access from public WiFi",
			Score:       0.6,
			Weight:      1.0,
		})
	case NetworkTrustUnknown:
		factors = append(factors, RiskFactor{
			Name:        "unknown_network",
			Description: "Access from unknown network",
			Score:       0.4,
			Weight:      0.8,
		})
	}

	// Geo-location risk
	if accessCtx.GeoLocation != nil {
		if accessCtx.GeoLocation.IsProxy || accessCtx.GeoLocation.IsVPN || accessCtx.GeoLocation.IsTor {
			factors = append(factors, RiskFactor{
				Name:        "anonymizing_service",
				Description: "Access via proxy, VPN, or Tor",
				Score:       0.5,
				Weight:      1.0,
			})
		}
	}

	// Browser/client risk
	if accessCtx.BrowserInfo != nil {
		if accessCtx.BrowserInfo.IsBot {
			factors = append(factors, RiskFactor{
				Name:        "bot_detected",
				Description: "Bot or crawler detected",
				Score:       0.9,
				Weight:      1.5,
			})
		}
		if accessCtx.BrowserInfo.IsHeadless {
			factors = append(factors, RiskFactor{
				Name:        "headless_browser",
				Description: "Headless browser detected",
				Score:       0.6,
				Weight:      1.0,
			})
		}
	}

	// Time-based risk
	hour := accessCtx.TimeOfAccess.Hour()
	if hour < 6 || hour > 22 {
		factors = append(factors, RiskFactor{
			Name:        "unusual_time",
			Description: "Access at unusual time",
			Score:       0.3,
			Weight:      0.5,
		})
	}

	// Recent failures
	if accessCtx.RecentFailures > 3 {
		factors = append(factors, RiskFactor{
			Name:        "recent_failures",
			Description: "Multiple recent authentication failures",
			Score:       math.Min(float64(accessCtx.RecentFailures)/10, 1.0),
			Weight:      1.5,
		})
	}

	// Check for behavioral anomalies
	if history, err := e.getAccessHistory(ctx, identityID); err == nil && history.TypicalPattern != nil {
		anomalyFactors := e.detectBehaviorAnomalies(accessCtx, history)
		factors = append(factors, anomalyFactors...)
	}

	return factors
}

// aggregateRiskScore aggregates risk factors into a single score
func (e *Engine) aggregateRiskScore(factors []RiskFactor) float64 {
	if len(factors) == 0 {
		return 0.0
	}

	var totalScore, totalWeight float64
	for _, f := range factors {
		totalScore += f.Score * f.Weight
		totalWeight += f.Weight
	}

	if totalWeight == 0 {
		return 0.0
	}

	return math.Min(totalScore/totalWeight, 1.0)
}

// determineRiskLevel determines the risk level from score
func (e *Engine) determineRiskLevel(score float64) RiskLevel {
	switch {
	case score >= 0.8:
		return RiskLevelCritical
	case score >= 0.6:
		return RiskLevelHigh
	case score >= 0.3:
		return RiskLevelMedium
	default:
		return RiskLevelLow
	}
}

// evaluatePolicy evaluates context against a policy
func (e *Engine) evaluatePolicy(accessCtx *AccessContext, policy *ContextPolicy) (AccessDecision, string) {
	// Check blocked countries
	if accessCtx.GeoLocation != nil && len(policy.BlockedCountries) > 0 {
		for _, country := range policy.BlockedCountries {
			if strings.EqualFold(accessCtx.GeoLocation.CountryCode, country) {
				return policy.Actions.OnBlockedGeo, "Access from blocked country"
			}
		}
	}

	// Check allowed countries
	if accessCtx.GeoLocation != nil && len(policy.AllowedCountries) > 0 {
		allowed := false
		for _, country := range policy.AllowedCountries {
			if strings.EqualFold(accessCtx.GeoLocation.CountryCode, country) {
				allowed = true
				break
			}
		}
		if !allowed {
			return policy.Actions.OnBlockedGeo, "Access from non-allowed country"
		}
	}

	// Check network types
	if len(policy.AllowedNetworkTypes) > 0 {
		allowed := false
		for _, nt := range policy.AllowedNetworkTypes {
			if nt == accessCtx.NetworkTrustLevel {
				allowed = true
				break
			}
		}
		if !allowed {
			return policy.Actions.OnPublicWifi, "Access from non-allowed network type"
		}
	}

	// Check rooted devices
	if policy.BlockRootedDevices && (accessCtx.IsRooted || accessCtx.IsJailbroken) {
		return policy.Actions.OnRootedDevice, "Rooted/jailbroken device detected"
	}

	// Check risk threshold
	if accessCtx.OverallRiskScore > policy.MaxRiskScore {
		return policy.Actions.OnHighRisk, "Risk score exceeds threshold"
	}

	// Check time windows
	if len(policy.AllowedTimeWindows) > 0 {
		inWindow := false
		for _, tw := range policy.AllowedTimeWindows {
			if e.isInTimeWindow(accessCtx.TimeOfAccess, tw) {
				inWindow = true
				break
			}
		}
		if !inWindow {
			return policy.Actions.OnTimeViolation, "Access outside allowed time window"
		}
	}

	return AccessDecisionAllow, ""
}

// isInTimeWindow checks if a time is within a time window
func (e *Engine) isInTimeWindow(t time.Time, tw TimeWindowDef) bool {
	loc, err := time.LoadLocation(tw.Timezone)
	if err != nil {
		loc = time.UTC
	}

	localTime := t.In(loc)
	weekday := int(localTime.Weekday())

	// Check day
	dayAllowed := false
	for _, d := range tw.Days {
		if d == weekday {
			dayAllowed = true
			break
		}
	}
	if !dayAllowed {
		return false
	}

	// Parse start and end times
	startParts := strings.Split(tw.StartTime, ":")
	endParts := strings.Split(tw.EndTime, ":")
	if len(startParts) != 2 || len(endParts) != 2 {
		return false
	}

	currentMinutes := localTime.Hour()*60 + localTime.Minute()

	// Simple parsing
	startMinutes := e.parseTimeMinutes(tw.StartTime)
	endMinutes := e.parseTimeMinutes(tw.EndTime)

	return currentMinutes >= startMinutes && currentMinutes <= endMinutes
}

// parseTimeMinutes parses HH:MM to minutes
func (e *Engine) parseTimeMinutes(timeStr string) int {
	parts := strings.Split(timeStr, ":")
	if len(parts) != 2 {
		return 0
	}
	hours := 0
	minutes := 0
	_, _ = time.Parse("15:04", timeStr)
	if t, err := time.Parse("15:04", timeStr); err == nil {
		hours = t.Hour()
		minutes = t.Minute()
	}
	return hours*60 + minutes
}

// detectBehaviorAnomalies detects behavioral anomalies
func (e *Engine) detectBehaviorAnomalies(accessCtx *AccessContext, history *AccessHistory) []RiskFactor {
	var factors []RiskFactor

	if history.TypicalPattern == nil {
		return factors
	}

	pattern := history.TypicalPattern

	// Check for unusual location
	if accessCtx.GeoLocation != nil && len(pattern.TypicalCountries) > 0 {
		isTypical := false
		for _, country := range pattern.TypicalCountries {
			if strings.EqualFold(country, accessCtx.GeoLocation.CountryCode) {
				isTypical = true
				break
			}
		}
		if !isTypical {
			factors = append(factors, RiskFactor{
				Name:        "unusual_location",
				Description: "Access from unusual geographic location",
				Score:       0.5,
				Weight:      1.0,
			})
		}
	}

	// Check for unusual time
	hour := accessCtx.TimeOfAccess.Hour()
	isTypicalHour := false
	for _, h := range pattern.TypicalHours {
		if h == hour {
			isTypicalHour = true
			break
		}
	}
	if !isTypicalHour && len(pattern.TypicalHours) > 0 {
		factors = append(factors, RiskFactor{
			Name:        "unusual_hour",
			Description: "Access at unusual hour for this user",
			Score:       0.3,
			Weight:      0.7,
		})
	}

	return factors
}

// getAccessHistory retrieves access history for an identity
func (e *Engine) getAccessHistory(ctx context.Context, identityID types.ID) (*AccessHistory, error) {
	return e.historyStore.Get(ctx, string(identityID))
}

// updateAccessHistory updates access history with new access
func (e *Engine) updateAccessHistory(ctx context.Context, identityID types.ID, accessCtx *AccessContext) error {
	history, err := e.getAccessHistory(ctx, identityID)
	if err != nil {
		// Create new history
		history = &AccessHistory{
			IdentityID:  identityID,
			Locations:   []GeoLocation{},
			AccessTimes: []time.Time{},
			DeviceIDs:   []types.ID{},
			IPAddresses: []string{},
		}
	}

	// Add this access
	history.AccessTimes = append(history.AccessTimes, accessCtx.TimeOfAccess)
	if accessCtx.GeoLocation != nil {
		history.Locations = append(history.Locations, *accessCtx.GeoLocation)
	}
	if accessCtx.DeviceID != "" {
		history.DeviceIDs = append(history.DeviceIDs, accessCtx.DeviceID)
	}
	if accessCtx.IPAddress != "" {
		history.IPAddresses = append(history.IPAddresses, accessCtx.IPAddress)
	}

	// Keep only recent history (last 100 entries)
	if len(history.AccessTimes) > 100 {
		history.AccessTimes = history.AccessTimes[len(history.AccessTimes)-100:]
	}
	if len(history.Locations) > 100 {
		history.Locations = history.Locations[len(history.Locations)-100:]
	}
	if len(history.DeviceIDs) > 100 {
		history.DeviceIDs = history.DeviceIDs[len(history.DeviceIDs)-100:]
	}
	if len(history.IPAddresses) > 100 {
		history.IPAddresses = history.IPAddresses[len(history.IPAddresses)-100:]
	}

	history.LastUpdated = types.Now()

	// Update typical pattern
	history.TypicalPattern = e.computeTypicalPattern(history)

	return e.historyStore.Set(ctx, string(identityID), history)
}

// computeTypicalPattern computes typical behavior pattern from history
func (e *Engine) computeTypicalPattern(history *AccessHistory) *BehaviorPattern {
	if len(history.AccessTimes) < 10 {
		return nil // Not enough data
	}

	pattern := &BehaviorPattern{}

	// Compute typical countries
	countryCount := make(map[string]int)
	for _, loc := range history.Locations {
		countryCount[loc.CountryCode]++
	}
	for country, count := range countryCount {
		if float64(count)/float64(len(history.Locations)) > 0.2 {
			pattern.TypicalCountries = append(pattern.TypicalCountries, country)
		}
	}

	// Compute typical hours
	hourCount := make(map[int]int)
	for _, t := range history.AccessTimes {
		hourCount[t.Hour()]++
	}
	for hour, count := range hourCount {
		if float64(count)/float64(len(history.AccessTimes)) > 0.1 {
			pattern.TypicalHours = append(pattern.TypicalHours, hour)
		}
	}

	// Compute typical days
	dayCount := make(map[int]int)
	for _, t := range history.AccessTimes {
		dayCount[int(t.Weekday())]++
	}
	for day, count := range dayCount {
		if float64(count)/float64(len(history.AccessTimes)) > 0.1 {
			pattern.TypicalDays = append(pattern.TypicalDays, day)
		}
	}

	// Compute average accesses per day
	if len(history.AccessTimes) > 1 {
		first := history.AccessTimes[0]
		last := history.AccessTimes[len(history.AccessTimes)-1]
		days := last.Sub(first).Hours() / 24
		if days > 0 {
			pattern.AvgAccessesPerDay = float64(len(history.AccessTimes)) / days
		}
	}

	// Count unique devices
	deviceSet := make(map[types.ID]bool)
	for _, d := range history.DeviceIDs {
		deviceSet[d] = true
	}
	pattern.TypicalDeviceCount = len(deviceSet)

	return pattern
}

// listActivePolicies lists active context policies
func (e *Engine) listActivePolicies(ctx context.Context) ([]*ContextPolicy, error) {
	all, err := e.policyStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var active []*ContextPolicy
	for _, p := range all {
		if p.Status == types.StatusActive {
			active = append(active, p)
		}
	}

	return active, nil
}

// CreatePolicy creates a new context policy
func (e *Engine) CreatePolicy(ctx context.Context, policy *ContextPolicy) error {
	id, err := e.crypto.GenerateRandomID()
	if err != nil {
		return err
	}

	policy.ID = id
	policy.CreatedAt = types.Now()
	policy.UpdatedAt = types.Now()
	policy.Status = types.StatusActive

	return e.policyStore.Set(ctx, string(policy.ID), policy)
}

// GetPolicy retrieves a policy by ID
func (e *Engine) GetPolicy(ctx context.Context, id types.ID) (*ContextPolicy, error) {
	return e.policyStore.Get(ctx, string(id))
}

// UpdatePolicy updates a policy
func (e *Engine) UpdatePolicy(ctx context.Context, id types.ID, policy *ContextPolicy) error {
	policy.ID = id
	policy.UpdatedAt = types.Now()
	return e.policyStore.Set(ctx, string(id), policy)
}

// DeletePolicy deletes a policy
func (e *Engine) DeletePolicy(ctx context.Context, id types.ID) error {
	return e.policyStore.Delete(ctx, string(id))
}

// AddThreatIP adds an IP to the threat list
func (e *Engine) AddThreatIP(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.threatIPs[ip] = true
}

// RemoveThreatIP removes an IP from the threat list
func (e *Engine) RemoveThreatIP(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.threatIPs, ip)
}

// GetRiskScore returns the current risk score for an identity
func (e *Engine) GetRiskScore(ctx context.Context, identityID types.ID, input ContextInput) (float64, error) {
	result, err := e.EvaluateContext(ctx, input)
	if err != nil {
		return 0, err
	}
	return result.Context.OverallRiskScore, nil
}

// Close cleans up resources
func (e *Engine) Close() error {
	return e.crypto.Close()
}
