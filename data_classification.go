package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DataClassificationEngine automatically classifies sensitive data
type DataClassificationEngine struct {
	db           *DB
	scanners     []DataScanner
	piiPatterns  []*PIIPattern
	phiPatterns  []*PHIDetectionPattern
	pciPatterns  []*PCIPattern
	config       *ClassificationConfig
	mu           sync.RWMutex
}

// DataScanner interface for data scanning
type DataScanner interface {
	Scan(data []byte) ([]*DataMatch, error)
	Type() string
}

// PIIPattern defines Personally Identifiable Information patterns
type PIIPattern struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"` // ssn, email, phone, passport, etc.
	Regex      *regexp.Regexp
	RegexStr   string   `json:"regex"`
	Confidence float64  `json:"confidence"` // 0.0 to 1.0
	Action     string   `json:"action"` // encrypt, mask, redact, block, alert
	Countries  []string `json:"countries,omitempty"` // Geographic scope
}

// PHIDetectionPattern defines Protected Health Information patterns
type PHIDetectionPattern struct {
	Name       string  `json:"name"`
	Type       string  `json:"type"` // mrn, npi, icd, medication, diagnosis
	Regex      *regexp.Regexp
	RegexStr   string  `json:"regex"`
	Confidence float64 `json:"confidence"`
	Action     string  `json:"action"`
}

// PCIPattern defines Payment Card Industry patterns
type PCIPattern struct {
	Name       string  `json:"name"`
	Type       string  `json:"type"` // card_number, cvv, expiry
	Regex      *regexp.Regexp
	RegexStr   string  `json:"regex"`
	Confidence float64 `json:"confidence"`
	Action     string  `json:"action"`
	Validator  func(string) bool // Luhn algorithm for cards
}

// ClassificationConfig defines classification behavior
type ClassificationConfig struct {
	Enabled         bool                   `json:"enabled"`
	AutoEncrypt     bool                   `json:"auto_encrypt"`     // Automatically encrypt detected PII/PHI
	AutoMask        bool                   `json:"auto_mask"`        // Mask sensitive data in logs
	BlockOnDetect   bool                   `json:"block_on_detect"`  // Block operations on unclassified sensitive data
	AlertOnDetect   bool                   `json:"alert_on_detect"`  // Alert security team
	ScanOnWrite     bool                   `json:"scan_on_write"`    // Scan data on write operations
	ScanThreshold   float64                `json:"scan_threshold"`   // Confidence threshold (0.0-1.0)
	DefaultClass    DataClassification     `json:"default_class"`
}

// NewDataClassificationEngine creates a new classification engine
func NewDataClassificationEngine(db *DB) *DataClassificationEngine {
	dce := &DataClassificationEngine{
		db:          db,
		scanners:    make([]DataScanner, 0),
		piiPatterns: make([]*PIIPattern, 0),
		phiPatterns: make([]*PHIDetectionPattern, 0),
		pciPatterns: make([]*PCIPattern, 0),
		config: &ClassificationConfig{
			Enabled:       true,
			AutoEncrypt:   true,
			AutoMask:      true,
			BlockOnDetect: false,
			AlertOnDetect: true,
			ScanOnWrite:   true,
			ScanThreshold: 0.7, // 70% confidence
			DefaultClass:  DataClassInternal,
		},
	}

	// Initialize patterns
	dce.initializePIIPatterns()
	dce.initializePHIPatterns()
	dce.initializePCIPatterns()

	return dce
}

// initializePIIPatterns sets up PII detection patterns
func (dce *DataClassificationEngine) initializePIIPatterns() {
	patterns := []struct {
		name    string
		typ     string
		regex   string
		conf    float64
		action  string
		countries []string
	}{
		// US Social Security Number
		{"US SSN", "ssn", `\b\d{3}-\d{2}-\d{4}\b`, 0.95, "encrypt", []string{"US"}},
		{"US SSN (no dashes)", "ssn", `\b\d{9}\b`, 0.80, "encrypt", []string{"US"}},

		// Email addresses
		{"Email", "email", `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`, 0.90, "mask", nil},

		// Phone numbers
		{"US Phone", "phone", `\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`, 0.85, "mask", []string{"US"}},
		{"Intl Phone", "phone", `\+\d{1,3}[-.]?\d{1,14}`, 0.85, "mask", nil},

		// Passport numbers (generic)
		{"Passport", "passport", `\b[A-Z]{1,2}\d{6,9}\b`, 0.75, "encrypt", nil},

		// Driver's license (US format)
		{"US Driver License", "drivers_license", `\b[A-Z]{1,2}\d{5,8}\b`, 0.70, "encrypt", []string{"US"}},

		// IP Addresses
		{"IPv4 Address", "ip_address", `\b(?:\d{1,3}\.){3}\d{1,3}\b`, 0.80, "mask", nil},

		// Credit cards (handled separately with Luhn validation)

		// Date of birth patterns
		{"Date of Birth", "dob", `\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b`, 0.75, "mask", nil},

		// National Insurance Number (UK)
		{"UK NIN", "nin", `\b[A-Z]{2}\d{6}[A-Z]\b`, 0.90, "encrypt", []string{"GB"}},

		// Social Insurance Number (Canada)
		{"Canada SIN", "sin", `\b\d{3}-\d{3}-\d{3}\b`, 0.90, "encrypt", []string{"CA"}},
	}

	for _, p := range patterns {
		regex, err := regexp.Compile(p.regex)
		if err != nil {
			continue
		}

		dce.piiPatterns = append(dce.piiPatterns, &PIIPattern{
			Name:       p.name,
			Type:       p.typ,
			Regex:      regex,
			RegexStr:   p.regex,
			Confidence: p.conf,
			Action:     p.action,
			Countries:  p.countries,
		})
	}
}

// initializePHIPatterns sets up PHI detection patterns
func (dce *DataClassificationEngine) initializePHIPatterns() {
	patterns := []struct {
		name   string
		typ    string
		regex  string
		conf   float64
		action string
	}{
		// Medical Record Number
		{"MRN", "mrn", `\bMRN[:\s]?\d{6,10}\b`, 0.95, "encrypt"},

		// National Provider Identifier (NPI)
		{"NPI", "npi", `\bNPI[:\s]?\d{10}\b`, 0.95, "encrypt"},

		// ICD codes
		{"ICD-10", "icd10", `\b[A-Z]\d{2}(?:\.\d{1,4})?\b`, 0.70, "encrypt"},

		// Medication names (common patterns)
		{"Medication", "medication", `\b(?:mg|mcg|mL|tablet|capsule|injection)\b`, 0.60, "mask"},

		// Patient identifiers
		{"Patient ID", "patient_id", `\b(?:Patient|PT)[:\s]?\d{6,10}\b`, 0.85, "encrypt"},

		// Health insurance claim numbers
		{"Claim Number", "claim_number", `\b(?:Claim|CLM)[:\s]?\d{8,15}\b`, 0.80, "encrypt"},
	}

	for _, p := range patterns {
		regex, err := regexp.Compile(p.regex)
		if err != nil {
			continue
		}

		dce.phiPatterns = append(dce.phiPatterns, &PHIDetectionPattern{
			Name:       p.name,
			Type:       p.typ,
			Regex:      regex,
			RegexStr:   p.regex,
			Confidence: p.conf,
			Action:     p.action,
		})
	}
}

// initializePCIPatterns sets up PCI detection patterns
func (dce *DataClassificationEngine) initializePCIPatterns() {
	// Credit card patterns with Luhn validation
	patterns := []struct {
		name      string
		typ       string
		regex     string
		conf      float64
		action    string
		validator func(string) bool
	}{
		// Visa: starts with 4, 13 or 16 digits
		{"Visa Card", "card_visa", `\b4\d{12}(?:\d{3})?\b`, 0.90, "encrypt", luhnCheck},

		// MasterCard: starts with 51-55 or 2221-2720, 16 digits
		{"MasterCard", "card_mastercard", `\b5[1-5]\d{14}\b`, 0.90, "encrypt", luhnCheck},

		// American Express: starts with 34 or 37, 15 digits
		{"Amex Card", "card_amex", `\b3[47]\d{13}\b`, 0.90, "encrypt", luhnCheck},

		// Discover: starts with 6011, 622126-622925, 644-649, 65, 16 digits
		{"Discover Card", "card_discover", `\b6(?:011|5\d{2}|4[4-9]\d|22(?:1(?:2[6-9]|[3-9]\d)|[2-8]\d{2}|9(?:[01]\d|2[0-5])))\d{12}\b`, 0.90, "encrypt", luhnCheck},

		// CVV: 3 or 4 digits (very generic, low confidence)
		{"CVV", "cvv", `\bCVV[:\s]?\d{3,4}\b`, 0.70, "block", nil},

		// Expiry date: MM/YY or MM/YYYY
		{"Card Expiry", "card_expiry", `\b(?:0[1-9]|1[0-2])[/-](?:\d{2}|\d{4})\b`, 0.65, "mask", nil},
	}

	for _, p := range patterns {
		regex, err := regexp.Compile(p.regex)
		if err != nil {
			continue
		}

		dce.pciPatterns = append(dce.pciPatterns, &PCIPattern{
			Name:       p.name,
			Type:       p.typ,
			Regex:      regex,
			RegexStr:   p.regex,
			Confidence: p.conf,
			Action:     p.action,
			Validator:  p.validator,
		})
	}
}

// ClassifyData scans and classifies data
func (dce *DataClassificationEngine) ClassifyData(ctx context.Context, data []byte) (*ClassificationResult, error) {
	dce.mu.RLock()
	defer dce.mu.RUnlock()

	if !dce.config.Enabled {
		return &ClassificationResult{
			Classification: dce.config.DefaultClass,
			Confidence:     0.5,
		}, nil
	}

	result := &ClassificationResult{
		Classification: DataClassPublic,
		Confidence:     0.0,
		Matches:        make([]*DataMatch, 0),
		Actions:        make([]string, 0),
	}

	dataStr := string(data)

	// Scan for PII
	for _, pattern := range dce.piiPatterns {
		matches := pattern.Regex.FindAllString(dataStr, -1)
		for _, match := range matches {
			dataMatch := &DataMatch{
				Type:       "pii",
				SubType:    pattern.Type,
				Value:      match,
				Pattern:    pattern.Name,
				Confidence: pattern.Confidence,
				Action:     pattern.Action,
				Position:   strings.Index(dataStr, match),
			}
			result.Matches = append(result.Matches, dataMatch)

			// Update classification if higher confidence
			if pattern.Confidence > result.Confidence {
				result.Confidence = pattern.Confidence
				result.Classification = DataClassRestricted
				result.Actions = append(result.Actions, pattern.Action)
			}
		}
	}

	// Scan for PHI
	for _, pattern := range dce.phiPatterns {
		matches := pattern.Regex.FindAllString(dataStr, -1)
		for _, match := range matches {
			dataMatch := &DataMatch{
				Type:       "phi",
				SubType:    pattern.Type,
				Value:      match,
				Pattern:    pattern.Name,
				Confidence: pattern.Confidence,
				Action:     pattern.Action,
				Position:   strings.Index(dataStr, match),
			}
			result.Matches = append(result.Matches, dataMatch)

			if pattern.Confidence > result.Confidence {
				result.Confidence = pattern.Confidence
				result.Classification = DataClassRestricted
				result.Actions = append(result.Actions, pattern.Action)
			}
		}
	}

	// Scan for PCI data
	for _, pattern := range dce.pciPatterns {
		matches := pattern.Regex.FindAllString(dataStr, -1)
		for _, match := range matches {
			// Validate with Luhn if validator present
			if pattern.Validator != nil && !pattern.Validator(match) {
				continue // False positive
			}

			dataMatch := &DataMatch{
				Type:       "pci",
				SubType:    pattern.Type,
				Value:      maskSensitiveData(match),
				Pattern:    pattern.Name,
				Confidence: pattern.Confidence,
				Action:     pattern.Action,
				Position:   strings.Index(dataStr, match),
			}
			result.Matches = append(result.Matches, dataMatch)

			if pattern.Confidence > result.Confidence {
				result.Confidence = pattern.Confidence
				result.Classification = DataClassRestricted
				result.Actions = append(result.Actions, pattern.Action)
			}
		}
	}

	// Check threshold
	if result.Confidence < dce.config.ScanThreshold {
		result.Classification = dce.config.DefaultClass
	}

	return result, nil
}

// DataMatch represents a detected sensitive data match
type DataMatch struct {
	Type       string  `json:"type"` // pii, phi, pci
	SubType    string  `json:"sub_type"`
	Value      string  `json:"value"` // May be masked
	Pattern    string  `json:"pattern"`
	Confidence float64 `json:"confidence"`
	Action     string  `json:"action"`
	Position   int     `json:"position"`
}

// ClassificationResult contains classification results
type ClassificationResult struct {
	Classification DataClassification `json:"classification"`
	Confidence     float64             `json:"confidence"`
	Matches        []*DataMatch        `json:"matches"`
	Actions        []string            `json:"actions"`
	ScanTime       int64               `json:"scan_time_ms"`
}

// MaskData masks sensitive data based on classification
func (dce *DataClassificationEngine) MaskData(data []byte, result *ClassificationResult) []byte {
	if len(result.Matches) == 0 {
		return data
	}

	masked := string(data)

	// Sort matches by position (descending) to avoid index shifts
	for i := len(result.Matches) - 1; i >= 0; i-- {
		match := result.Matches[i]
		if match.Action == "mask" || match.Action == "redact" {
			replacement := maskSensitiveData(match.Value)
			masked = strings.Replace(masked, match.Value, replacement, 1)
		}
	}

	return []byte(masked)
}

// maskSensitiveData masks a sensitive value
func maskSensitiveData(value string) string {
	if len(value) <= 4 {
		return strings.Repeat("*", len(value))
	}
	// Show last 4 characters
	return strings.Repeat("*", len(value)-4) + value[len(value)-4:]
}

// luhnCheck validates credit card numbers using Luhn algorithm
func luhnCheck(cardNumber string) bool {
	// Remove spaces and dashes
	cardNumber = strings.ReplaceAll(cardNumber, " ", "")
	cardNumber = strings.ReplaceAll(cardNumber, "-", "")

	if len(cardNumber) < 13 || len(cardNumber) > 19 {
		return false
	}

	sum := 0
	alternate := false

	for i := len(cardNumber) - 1; i >= 0; i-- {
		digit := int(cardNumber[i] - '0')
		if digit < 0 || digit > 9 {
			return false
		}

		if alternate {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}

		sum += digit
		alternate = !alternate
	}

	return sum%10 == 0
}

// EnforceDataPolicy enforces data protection policies
func (dce *DataClassificationEngine) EnforceDataPolicy(ctx context.Context, data []byte, operation string) error {
	result, err := dce.ClassifyData(ctx, data)
	if err != nil {
		return err
	}

	// Check if operation should be blocked
	if dce.config.BlockOnDetect {
		for _, match := range result.Matches {
			if match.Action == "block" {
				return fmt.Errorf("operation blocked: detected %s (%s) with confidence %.2f",
					match.Type, match.SubType, match.Confidence)
			}
		}
	}

	// Auto-encrypt if configured
	if dce.config.AutoEncrypt && result.Classification == DataClassRestricted {
		// Data should be encrypted (handled by caller)
		return nil
	}

	// Alert if configured
	if dce.config.AlertOnDetect && len(result.Matches) > 0 {
		go dce.sendSecurityAlert(result, operation)
	}

	return nil
}

// sendSecurityAlert sends an alert about detected sensitive data
func (dce *DataClassificationEngine) sendSecurityAlert(result *ClassificationResult, operation string) {
	alert := SecurityAlert{
		Timestamp:      time.Now(),
		Type:           "sensitive_data_detected",
		Severity:       "high",
		Classification: result.Classification,
		MatchCount:     len(result.Matches),
		Operation:      operation,
		Confidence:     result.Confidence,
	}

	// Log to audit system
	data, _ := json.Marshal(alert)
	dce.db.Put([]byte(fmt.Sprintf("_alert:%d", time.Now().UnixNano())), data)
}

// SecurityAlert represents a security alert
type SecurityAlert struct {
	Timestamp      time.Time          `json:"timestamp"`
	Type           string             `json:"type"`
	Severity       string             `json:"severity"`
	Classification DataClassification `json:"classification"`
	MatchCount     int                `json:"match_count"`
	Operation      string             `json:"operation"`
	Confidence     float64            `json:"confidence"`
	Details        string             `json:"details,omitempty"`
}

// GetClassificationStats returns classification statistics
func (dce *DataClassificationEngine) GetClassificationStats() *ClassificationStats {
	dce.mu.RLock()
	defer dce.mu.RUnlock()

	return &ClassificationStats{
		PIIPatterns: len(dce.piiPatterns),
		PHIPatterns: len(dce.phiPatterns),
		PCIPatterns: len(dce.pciPatterns),
		Enabled:     dce.config.Enabled,
		AutoEncrypt: dce.config.AutoEncrypt,
	}
}

// ClassificationStats provides statistics
type ClassificationStats struct {
	PIIPatterns int  `json:"pii_patterns"`
	PHIPatterns int  `json:"phi_patterns"`
	PCIPatterns int  `json:"pci_patterns"`
	Enabled     bool `json:"enabled"`
	AutoEncrypt bool `json:"auto_encrypt"`
}
