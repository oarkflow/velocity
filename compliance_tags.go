package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Compliance frameworks are already defined in compliance.go

// ComplianceTag represents compliance requirements applied to a resource
type ComplianceTag struct {
	TagID          string                 `json:"tag_id"`          // Unique identifier for this specific tag
	Path           string                 `json:"path"`            // Folder, file, or key path
	Frameworks     []ComplianceFramework  `json:"frameworks"`      // Applied frameworks
	DataClass      DataClassification     `json:"data_class"`      // Data classification level
	Owner          string                 `json:"owner"`           // Data owner
	Custodian      string                 `json:"custodian"`       // Data custodian
	RetentionDays  int                    `json:"retention_days"`  // Retention period
	EncryptionReq  bool                   `json:"encryption_req"`  // Encryption required
	AuditLevel     string                 `json:"audit_level"`     // high, medium, low
	AccessPolicy   string                 `json:"access_policy"`   // RBAC policy name
	CreatedAt      time.Time              `json:"created_at"`
	CreatedBy      string                 `json:"created_by"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// ComplianceTagManager manages compliance tags for paths
type ComplianceTagManager struct {
	db    *DB
	tags  map[string][]*ComplianceTag // path -> multiple tags
	mu    sync.RWMutex

	consentMgr    *ConsentManager
	retentionMgr  *RetentionManager
	residencyMgr  *DataResidencyManager
	breakGlassMgr *BreakGlassManager
	keyMgr        *DataClassKeyManager
	maskingEngine *DataMaskingEngine
	lineageMgr    *LineageManager
	auditMgr      *AuditLogManager
	violationsMgr *ViolationsManager
	policyEngine  *PolicyEngine
}

// NewComplianceTagManager creates a new compliance tag manager
func NewComplianceTagManager(db *DB) *ComplianceTagManager {
	ctm := &ComplianceTagManager{
		db:   db,
		tags: make(map[string][]*ComplianceTag),
	}

	// Wire default managers
	ctm.consentMgr = NewConsentManager(db)
	ctm.retentionMgr = NewRetentionManager(db)
	ctm.residencyMgr = NewDataResidencyManager(db)
	ctm.breakGlassMgr = NewBreakGlassManager(db)
	ctm.keyMgr = NewDataClassKeyManager(db)
	ctm.maskingEngine = NewDataMaskingEngine()
	ctm.lineageMgr = NewLineageManager(db)
	ctm.auditMgr = NewAuditLogManager(db)
	ctm.violationsMgr = NewViolationsManager(db)
	alertMgr := NewAlertManager(db)
	ctm.violationsMgr.SetAlertManager(alertMgr)
	breachSystem := NewBreachNotificationSystem(db)
	ctm.violationsMgr.SetBreachNotificationSystem(breachSystem)
	ctm.policyEngine = NewPolicyEngine(db)
	_ = ctm.policyEngine.LoadPolicies(context.Background())
	if len(ctm.policyEngine.policies) == 0 {
		_ = ctm.policyEngine.InstallDefaultPacks(context.Background())
	}

	// Add basic masking rules
	_ = ctm.maskingEngine.AddRule(&MaskingRule{
		RuleID:     "email",
		PatternStr: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
		Strategy:   "partial",
		DataClass:  DataClassConfidential,
	})
	_ = ctm.maskingEngine.AddRule(&MaskingRule{
		RuleID:     "ssn",
		PatternStr: `\d{3}-?\d{2}-?\d{4}`,
		Strategy:   "full",
		DataClass:  DataClassRestricted,
	})
	_ = ctm.maskingEngine.AddRule(&MaskingRule{
		RuleID:     "credit_card",
		PatternStr: `\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}`,
		Strategy:   "partial",
		DataClass:  DataClassRestricted,
	})

	ctm.loadTags()
	return ctm
}

// SetConsentManager sets the consent manager.
func (ctm *ComplianceTagManager) SetConsentManager(cm *ConsentManager) {
	ctm.consentMgr = cm
}

// SetRetentionManager sets the retention manager.
func (ctm *ComplianceTagManager) SetRetentionManager(rm *RetentionManager) {
	ctm.retentionMgr = rm
}

// SetResidencyManager sets the data residency manager.
func (ctm *ComplianceTagManager) SetResidencyManager(drm *DataResidencyManager) {
	ctm.residencyMgr = drm
}

// SetBreakGlassManager sets the break-glass manager.
func (ctm *ComplianceTagManager) SetBreakGlassManager(bg *BreakGlassManager) {
	ctm.breakGlassMgr = bg
}

// SetKeyManager sets the data-class key manager.
func (ctm *ComplianceTagManager) SetKeyManager(km *DataClassKeyManager) {
	ctm.keyMgr = km
}

// SetMaskingEngine sets the data masking engine.
func (ctm *ComplianceTagManager) SetMaskingEngine(engine *DataMaskingEngine) {
	ctm.maskingEngine = engine
}

// SetLineageManager sets the data lineage manager.
func (ctm *ComplianceTagManager) SetLineageManager(lm *LineageManager) {
	ctm.lineageMgr = lm
}

// SetAuditLogManager sets the audit log manager.
func (ctm *ComplianceTagManager) SetAuditLogManager(am *AuditLogManager) {
	ctm.auditMgr = am
}

// SetViolationsManager sets the violations manager.
func (ctm *ComplianceTagManager) SetViolationsManager(vm *ViolationsManager) {
	ctm.violationsMgr = vm
}

// SetPolicyEngine sets the policy engine.
func (ctm *ComplianceTagManager) SetPolicyEngine(pe *PolicyEngine) {
	ctm.policyEngine = pe
}

// TagPath applies compliance frameworks to a path (folder, file, or key)
func (ctm *ComplianceTagManager) TagPath(ctx context.Context, tag *ComplianceTag) error {
	ctm.mu.Lock()
	defer ctm.mu.Unlock()

	// Validate frameworks
	if len(tag.Frameworks) == 0 {
		return fmt.Errorf("at least one compliance framework required")
	}

	// Normalize path
	tag.Path = normalizeCompliancePath(tag.Path)

	// Generate TagID if not provided
	if tag.TagID == "" {
		tag.TagID = fmt.Sprintf("%s:%d", tag.Path, time.Now().UnixNano())
	}

	// Set defaults
	if tag.CreatedAt.IsZero() {
		tag.CreatedAt = time.Now()
	}
	if tag.AuditLevel == "" {
		tag.AuditLevel = "high"
	}

	// Store in memory - append to support multiple tags per path
	ctm.tags[tag.Path] = append(ctm.tags[tag.Path], tag)

	// Persist to database with TagID as unique key
	data, err := json.Marshal(tag)
	if err != nil {
		return fmt.Errorf("failed to marshal tag: %w", err)
	}

	key := []byte("compliance:tag:" + tag.TagID)
	if err := ctm.db.Put(key, data); err != nil {
		return fmt.Errorf("failed to persist tag: %w", err)
	}

	return nil
}

// GetTag retrieves the compliance tag for a path (with inheritance)
// If multiple tags exist, returns a merged tag with all frameworks
func (ctm *ComplianceTagManager) GetTag(path string) *ComplianceTag {
	ctm.mu.RLock()
	defer ctm.mu.RUnlock()

	path = normalizeCompliancePath(path)

	// Check exact match first
	if tags, ok := ctm.tags[path]; ok && len(tags) > 0 {
		// If multiple tags, merge them
		if len(tags) == 1 {
			return tags[0]
		}
		return mergeTags(tags, path)
	}

	// Check parent paths for inheritance
	// e.g., /folderA/file1.txt inherits from /folderA
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		parentPath := "/" + strings.Join(parts[:i+1], "/")
		if tags, ok := ctm.tags[parentPath]; ok && len(tags) > 0 {
			// Return inherited tag (child inherits parent's compliance)
			if len(tags) == 1 {
				inherited := *tags[0]
				inherited.Path = path
				return &inherited
			}
			// Merge multiple parent tags
			merged := mergeTags(tags, path)
			return merged
		}
	}

	return nil
}

// GetTags retrieves all compliance tags for a specific path (with inheritance)
func (ctm *ComplianceTagManager) GetTags(path string) []*ComplianceTag {
	ctm.mu.RLock()
	defer ctm.mu.RUnlock()

	path = normalizeCompliancePath(path)

	// Check exact match first
	if tags, ok := ctm.tags[path]; ok && len(tags) > 0 {
		// Return copies to prevent modification
		result := make([]*ComplianceTag, len(tags))
		for i, tag := range tags {
			copy := *tag
			result[i] = &copy
		}
		return result
	}

	// Check parent paths for inheritance
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		parentPath := "/" + strings.Join(parts[:i+1], "/")
		if tags, ok := ctm.tags[parentPath]; ok && len(tags) > 0 {
			// Return inherited tags
			result := make([]*ComplianceTag, len(tags))
			for i, tag := range tags {
				inherited := *tag
				inherited.Path = path
				result[i] = &inherited
			}
			return result
		}
	}

	return nil
}

// GetAllTags returns all compliance tags
func (ctm *ComplianceTagManager) GetAllTags() []*ComplianceTag {
	ctm.mu.RLock()
	defer ctm.mu.RUnlock()

	var allTags []*ComplianceTag
	for _, tagList := range ctm.tags {
		allTags = append(allTags, tagList...)
	}
	return allTags
}

// mergeTags merges multiple tags into a single tag with combined frameworks
func mergeTags(tags []*ComplianceTag, path string) *ComplianceTag {
	if len(tags) == 0 {
		return nil
	}
	if len(tags) == 1 {
		return tags[0]
	}

	// Start with first tag as base
	merged := *tags[0]
	merged.Path = path

	// Collect all unique frameworks
	frameworkSet := make(map[ComplianceFramework]bool)
	for _, tag := range tags {
		for _, fw := range tag.Frameworks {
			frameworkSet[fw] = true
		}
	}

	// Convert to slice
	merged.Frameworks = make([]ComplianceFramework, 0, len(frameworkSet))
	for fw := range frameworkSet {
		merged.Frameworks = append(merged.Frameworks, fw)
	}

	// Use most restrictive settings from all tags
	for _, tag := range tags[1:] {
		// Most restrictive data class
		if tag.DataClass > merged.DataClass {
			merged.DataClass = tag.DataClass
		}
		// Require encryption if any tag requires it
		if tag.EncryptionReq {
			merged.EncryptionReq = true
		}
		// Longest retention period
		if tag.RetentionDays > merged.RetentionDays {
			merged.RetentionDays = tag.RetentionDays
		}
		// Highest audit level
		if tag.AuditLevel == "high" || (tag.AuditLevel == "medium" && merged.AuditLevel == "low") {
			merged.AuditLevel = tag.AuditLevel
		}
	}

	return &merged
}

// RemoveTag removes a compliance tag from a path
func (ctm *ComplianceTagManager) RemoveTag(ctx context.Context, path string) error {
	ctm.mu.Lock()
	defer ctm.mu.Unlock()

	path = normalizeCompliancePath(path)

	// Remove from memory
	delete(ctm.tags, path)

	// Remove all tags for this path from database
	allKeys, err := ctm.db.Keys("*")
	if err != nil {
		return err
	}

	prefix := "compliance:tag:" + path
	for _, key := range allKeys {
		if strings.HasPrefix(key, prefix) {
			if err := ctm.db.Delete([]byte(key)); err != nil {
				return err
			}
		}
	}

	return nil
}

// ValidateOperation checks if an operation complies with tagged requirements
func (ctm *ComplianceTagManager) ValidateOperation(ctx context.Context, req *ComplianceOperationRequest) (*ComplianceValidationResult, error) {
	// System operations bypass all compliance checks
	if req.SystemOperation {
		return &ComplianceValidationResult{
			Allowed: true,
			Reason:  "system operation - compliance checks bypassed",
		}, nil
	}

	tag := ctm.GetTag(req.Path)
	if tag == nil {
		// No compliance requirements - allow
		return &ComplianceValidationResult{
			Allowed: true,
			Reason:  "no compliance tags applied",
		}, nil
	}

	result := &ComplianceValidationResult{
		Allowed:        true,
		AppliedTag:     tag,
		ViolatedRules:  make([]string, 0),
		RequiredActions: make([]string, 0),
	}

	// Check each framework
	for _, framework := range tag.Frameworks {
		switch framework {
		case FrameworkGDPR:
			ctm.validateGDPR(req, tag, result)
		case FrameworkHIPAA:
			ctm.validateHIPAA(req, tag, result)
		case FrameworkNIST:
			ctm.validateNIST(req, tag, result)
		case FrameworkPCIDSS:
			ctm.validatePCIDSS(req, tag, result)
		case FrameworkSOC2:
			ctm.validateSOC2(req, tag, result)
		case FrameworkFIPS:
			ctm.validateFIPS(req, tag, result)
		}
	}

	// If encryption is required, check it (skip for system operations)
	if !req.SystemOperation && tag.EncryptionReq && req.Operation == "write" && !req.Encrypted {
		result.Allowed = false
		result.ViolatedRules = append(result.ViolatedRules, "encryption required but data is not encrypted")
		result.RequiredActions = append(result.RequiredActions, "encrypt data before write")
	}

	// Consent checks for GDPR
	if !req.SystemOperation && ctm.consentMgr != nil && containsFramework(tag.Frameworks, FrameworkGDPR) && (req.Operation == "read" || req.Operation == "write") {
		if req.SubjectID == "" || req.Purpose == "" {
			result.RequiredActions = append(result.RequiredActions, "identify data subject and purpose for consent verification")
		} else {
			hasConsent, _, err := ctm.consentMgr.HasActiveConsent(ctx, req.SubjectID, req.Purpose)
			if err != nil {
				return nil, err
			}
			if !hasConsent {
				result.Allowed = false
				result.ViolatedRules = append(result.ViolatedRules, "GDPR: missing valid consent for processing")
				result.RequiredActions = append(result.RequiredActions, "obtain valid consent before processing")
			}
		}
	}

	// Retention enforcement
	if ctm.retentionMgr != nil && tag.RetentionDays > 0 && req.DataAge > 0 {
		dataAge := time.Duration(req.DataAge) * 24 * time.Hour
		exceeds, policy, err := ctm.retentionMgr.EvaluateRetention(ctx, string(tag.DataClass), dataAge)
		if err != nil {
			return nil, err
		}
		if exceeds {
			if policy != nil {
				result.ViolatedRules = append(result.ViolatedRules, fmt.Sprintf("retention policy exceeded: %s", policy.PolicyID))
			} else {
				result.ViolatedRules = append(result.ViolatedRules, "retention policy exceeded")
			}
			result.RequiredActions = append(result.RequiredActions, "delete or anonymize expired data")
			if !req.SystemOperation {
				result.Allowed = false
			}
		}
	}

	// Data residency enforcement
	if ctm.residencyMgr != nil && req.Region != "" {
		allowed, policy, err := ctm.residencyMgr.ValidateResidency(ctx, req.Path, req.Region)
		if err != nil {
			return nil, err
		}
		if !allowed {
			result.Allowed = false
			if policy != nil {
				result.ViolatedRules = append(result.ViolatedRules, fmt.Sprintf("data residency violation: %s", policy.PolicyID))
			} else {
				result.ViolatedRules = append(result.ViolatedRules, "data residency violation")
			}
			result.RequiredActions = append(result.RequiredActions, "store data in approved region")
		}
	}

	// Break-glass enforcement for restricted data (only when explicitly required)
	breakGlassRequired := false
	if tag.Metadata != nil {
		if v, ok := tag.Metadata["break_glass_required"]; ok {
			switch val := v.(type) {
			case bool:
				breakGlassRequired = val
			case string:
				breakGlassRequired = strings.EqualFold(val, "true")
			}
		}
	}
	if !req.SystemOperation && breakGlassRequired && ctm.breakGlassMgr != nil && tag.DataClass >= DataClassRestricted {
		if req.BreakGlassRequestID == "" {
			result.RequiredActions = append(result.RequiredActions, "request break-glass approval for restricted data")
			result.Allowed = false
			result.ViolatedRules = append(result.ViolatedRules, "break-glass approval required")
		} else {
			active, err := ctm.breakGlassMgr.IsActive(ctx, req.BreakGlassRequestID)
			if err != nil {
				return nil, err
			}
			if !active {
				result.Allowed = false
				result.ViolatedRules = append(result.ViolatedRules, "break-glass approval expired or not active")
			}
		}
	}

	// Key management requirement
	if ctm.keyMgr != nil && tag.EncryptionReq && req.Operation == "write" {
		_, version, err := ctm.keyMgr.GetKeyForClass(tag.DataClass)
		if err == nil {
			result.RequiredActions = append(result.RequiredActions, fmt.Sprintf("use class-specific encryption key version %d", version))
		}
	}

	// Masking requirements for reads of sensitive data
	if ctm.maskingEngine != nil && req.Operation == "read" && tag.DataClass >= DataClassConfidential {
		result.RequiredActions = append(result.RequiredActions, "apply data masking before returning content")
	}

	// Data lineage tracking
	if ctm.lineageMgr != nil {
		result.RequiredActions = append(result.RequiredActions, "record data lineage event")
	}

	// Check access policy
	if tag.AccessPolicy != "" && req.Actor != "" {
		// This would integrate with RBAC
		result.RequiredActions = append(result.RequiredActions, fmt.Sprintf("verify RBAC policy: %s", tag.AccessPolicy))
	}

	// Check audit requirements
	if tag.AuditLevel == "high" {
		result.RequiredActions = append(result.RequiredActions, "log audit event with high severity")
	}

	// Policy engine evaluation
	if !req.SystemOperation && ctm.policyEngine != nil {
		if err := ctm.policyEngine.EvaluatePolicies(ctx, tag.Frameworks, req, tag, result); err != nil {
			return nil, err
		}
	}

	// Record audit and violations
	if ctm.auditMgr != nil {
		_ = ctm.auditMgr.LogComplianceOperation(ctx, req, result, 0)
	}
	if ctm.violationsMgr != nil && !result.Allowed {
		_ = ctm.violationsMgr.RecordFromValidation(ctx, req, result)
	}

	// Record lineage event
	if ctm.lineageMgr != nil {
		_ = ctm.lineageMgr.RecordEvent(ctx, &LineageEvent{
			Path:      req.Path,
			Action:    req.Operation,
			Actor:     req.Actor,
			Timestamp: time.Now(),
		})
	}

	return result, nil
}

// validateGDPR checks GDPR compliance requirements
func (ctm *ComplianceTagManager) validateGDPR(req *ComplianceOperationRequest, tag *ComplianceTag, result *ComplianceValidationResult) {
	// GDPR Article 17: Right to erasure
	if req.Operation == "delete" && req.Reason == "" {
		result.RequiredActions = append(result.RequiredActions, "record deletion reason for GDPR compliance")
	}

	// GDPR Article 32: Security of processing
	if !req.SystemOperation && req.Operation == "write" && !req.Encrypted && tag.DataClass >= DataClassConfidential {
		result.Allowed = false
		result.ViolatedRules = append(result.ViolatedRules, "GDPR Article 32: confidential data must be encrypted")
	}

	// GDPR Article 5(1)(e): Storage limitation
	if tag.RetentionDays > 0 && req.DataAge > tag.RetentionDays {
		result.ViolatedRules = append(result.ViolatedRules, "GDPR Article 5: data exceeds retention period")
		result.RequiredActions = append(result.RequiredActions, "delete or anonymize expired data")
	}

	// GDPR consent requirements
	if req.Operation == "read" || req.Operation == "write" {
		result.RequiredActions = append(result.RequiredActions, "verify consent for personal data processing")
	}
}

// validateHIPAA checks HIPAA compliance requirements
func (ctm *ComplianceTagManager) validateHIPAA(req *ComplianceOperationRequest, tag *ComplianceTag, result *ComplianceValidationResult) {
	// HIPAA Security Rule: Encryption requirement
	if !req.SystemOperation && req.Operation == "write" && !req.Encrypted {
		result.Allowed = false
		result.ViolatedRules = append(result.ViolatedRules, "HIPAA Security Rule: PHI must be encrypted")
	}

	// HIPAA Privacy Rule: Minimum necessary
	if req.Operation == "read" {
		result.RequiredActions = append(result.RequiredActions, "enforce minimum necessary access for PHI")
	}

	// HIPAA Audit Controls
	result.RequiredActions = append(result.RequiredActions, "log PHI access for HIPAA audit trail")

	// Business Associate Agreement check
	if req.Actor != "" && !strings.Contains(req.Actor, "internal") {
		result.RequiredActions = append(result.RequiredActions, "verify BAA exists for external access")
	}
}

// validateNIST checks NIST 800-53 compliance requirements
func (ctm *ComplianceTagManager) validateNIST(req *ComplianceOperationRequest, tag *ComplianceTag, result *ComplianceValidationResult) {
	// AC-3: Access Enforcement
	if req.Actor == "" {
		result.Allowed = false
		result.ViolatedRules = append(result.ViolatedRules, "NIST AC-3: authenticated identity required")
	}

	// SC-8: Transmission Confidentiality
	if req.Operation == "write" || req.Operation == "read" {
		result.RequiredActions = append(result.RequiredActions, "NIST SC-8: ensure TLS 1.3 for transmission")
	}

	// AU-2: Audit Events
	result.RequiredActions = append(result.RequiredActions, "NIST AU-2: log security-relevant events")

	// SC-13: Cryptographic Protection
	if tag.DataClass >= DataClassConfidential && !req.Encrypted {
		result.Allowed = false
		result.ViolatedRules = append(result.ViolatedRules, "NIST SC-13: FIPS-approved crypto required")
	}
}

// validatePCIDSS checks PCI DSS compliance requirements
func (ctm *ComplianceTagManager) validatePCIDSS(req *ComplianceOperationRequest, tag *ComplianceTag, result *ComplianceValidationResult) {
	// PCI DSS Requirement 3: Protect stored cardholder data
	if req.Operation == "write" && !req.Encrypted {
		result.Allowed = false
		result.ViolatedRules = append(result.ViolatedRules, "PCI DSS 3.4: cardholder data must be encrypted")
	}

	// PCI DSS Requirement 8: Identify and authenticate access
	if req.Actor == "" || !req.MFAVerified {
		result.Allowed = false
		result.ViolatedRules = append(result.ViolatedRules, "PCI DSS 8.3: MFA required for cardholder data access")
	}

	// PCI DSS Requirement 10: Track and monitor all access
	result.RequiredActions = append(result.RequiredActions, "PCI DSS 10.1: log all access to cardholder data")

	// PCI DSS Requirement 3.1: Retention policy
	if tag.RetentionDays == 0 {
		result.ViolatedRules = append(result.ViolatedRules, "PCI DSS 3.1: retention policy required")
	}
}

// validateSOC2 checks SOC 2 compliance requirements
func (ctm *ComplianceTagManager) validateSOC2(req *ComplianceOperationRequest, tag *ComplianceTag, result *ComplianceValidationResult) {
	// CC6.1: Logical and physical access controls
	if req.Actor == "" {
		result.Allowed = false
		result.ViolatedRules = append(result.ViolatedRules, "SOC2 CC6.1: authenticated access required")
	}

	// CC6.6: Encryption at rest
	if req.Operation == "write" && !req.Encrypted {
		result.ViolatedRules = append(result.ViolatedRules, "SOC2 CC6.6: encryption at rest required")
	}

	// CC7.2: Monitoring activities
	result.RequiredActions = append(result.RequiredActions, "SOC2 CC7.2: log and monitor system activities")
}

// validateFIPS checks FIPS 140-2 compliance requirements
func (ctm *ComplianceTagManager) validateFIPS(req *ComplianceOperationRequest, tag *ComplianceTag, result *ComplianceValidationResult) {
	// FIPS 140-2: Approved algorithms
	if req.Operation == "write" && req.CryptoAlgorithm != "" {
		approved := []string{"AES-256-GCM", "SHA-256", "SHA-512", "PBKDF2"}
		isApproved := false
		for _, algo := range approved {
			if req.CryptoAlgorithm == algo {
				isApproved = true
				break
			}
		}
		if !isApproved {
			result.Allowed = false
			result.ViolatedRules = append(result.ViolatedRules, "FIPS 140-2: non-approved cryptographic algorithm")
		}
	}

	// FIPS 140-2 Level 2: Key management
	result.RequiredActions = append(result.RequiredActions, "FIPS 140-2: use approved key management")
}

// ComplianceOperationRequest represents a request to validate an operation
type ComplianceOperationRequest struct {
	Path            string    `json:"path"`
	Operation       string    `json:"operation"` // read, write, delete
	Actor           string    `json:"actor"`
	IPAddress       string    `json:"ip_address"`
	Region          string    `json:"region"`
	SubjectID       string    `json:"subject_id"`
	Purpose         string    `json:"purpose"`
	BreakGlassRequestID string `json:"break_glass_request_id"`
	Encrypted       bool      `json:"encrypted"`
	SystemOperation bool      `json:"system_operation"`
	MFAVerified     bool      `json:"mfa_verified"`
	CryptoAlgorithm string    `json:"crypto_algorithm"`
	Reason          string    `json:"reason"`
	DataAge         int       `json:"data_age"` // days
	Timestamp       time.Time `json:"timestamp"`
}

func containsFramework(frameworks []ComplianceFramework, target ComplianceFramework) bool {
	for _, f := range frameworks {
		if f == target {
			return true
		}
	}
	return false
}

// ComplianceValidationResult represents the result of compliance validation
type ComplianceValidationResult struct {
	Allowed         bool               `json:"allowed"`
	Reason          string             `json:"reason"`
	AppliedTag      *ComplianceTag     `json:"applied_tag,omitempty"`
	ViolatedRules   []string           `json:"violated_rules"`
	RequiredActions []string           `json:"required_actions"`
}

// loadTags loads compliance tags from database
func (ctm *ComplianceTagManager) loadTags() error {
	// Get all keys and filter by prefix
	// Can't use wildcard pattern because path.Match treats "/" as separator
	allKeys, err := ctm.db.Keys("*")
	if err != nil {
		return err
	}

	prefix := "compliance:tag:"
	for _, key := range allKeys {
		// Filter keys that start with our prefix
		if len(key) < len(prefix) || key[:len(prefix)] != prefix {
			continue
		}

		value, err := ctm.db.Get([]byte(key))
		if err != nil {
			continue
		}

		var tag ComplianceTag
		if err := json.Unmarshal(value, &tag); err != nil {
			continue // Skip invalid tags
		}

		ctm.tags[tag.Path] = append(ctm.tags[tag.Path], &tag)
	}

	return nil
}

// ListTagsByFramework returns all paths tagged with a specific framework
func (ctm *ComplianceTagManager) ListTagsByFramework(framework ComplianceFramework) []*ComplianceTag {
	ctm.mu.RLock()
	defer ctm.mu.RUnlock()

	var result []*ComplianceTag
	for _, tagList := range ctm.tags {
		for _, tag := range tagList {
			for _, f := range tag.Frameworks {
				if f == framework {
					result = append(result, tag)
					break
				}
			}
		}
	}
	return result
}

// UpdateTag updates a specific compliance tag by TagID
func (ctm *ComplianceTagManager) UpdateTag(ctx context.Context, tagID string, updateFn func(*ComplianceTag) error) error {
	ctm.mu.Lock()
	defer ctm.mu.Unlock()

	// Find the tag by TagID
	var foundTag *ComplianceTag
	for _, tagList := range ctm.tags {
		for _, tag := range tagList {
			if tag.TagID == tagID {
				foundTag = tag
				break
			}
		}
		if foundTag != nil {
			break
		}
	}

	if foundTag == nil {
		return fmt.Errorf("compliance tag not found with ID: %s", tagID)
	}

	// Apply update function
	if err := updateFn(foundTag); err != nil {
		return err
	}

	// Persist updated tag
	data, err := json.Marshal(foundTag)
	if err != nil {
		return fmt.Errorf("failed to marshal tag: %w", err)
	}

	key := []byte("compliance:tag:" + tagID)
	if err := ctm.db.Put(key, data); err != nil {
		return fmt.Errorf("failed to persist updated tag: %w", err)
	}

	return nil
}

// UpdateTagByPathAndFramework updates the first tag matching path and framework
func (ctm *ComplianceTagManager) UpdateTagByPathAndFramework(ctx context.Context, path string, framework ComplianceFramework, updateFn func(*ComplianceTag) error) error {
	ctm.mu.Lock()
	defer ctm.mu.Unlock()

	path = normalizeCompliancePath(path)
	tagList, ok := ctm.tags[path]
	if !ok || len(tagList) == 0 {
		return fmt.Errorf("no compliance tags found for path: %s", path)
	}

	// Find tag with matching framework
	var foundTag *ComplianceTag
	for _, tag := range tagList {
		for _, fw := range tag.Frameworks {
			if fw == framework {
				foundTag = tag
				break
			}
		}
		if foundTag != nil {
			break
		}
	}

	if foundTag == nil {
		return fmt.Errorf("no tag found with framework %v for path: %s", framework, path)
	}

	// Apply update function
	if err := updateFn(foundTag); err != nil {
		return err
	}

	// Persist updated tag
	data, err := json.Marshal(foundTag)
	if err != nil {
		return fmt.Errorf("failed to marshal tag: %w", err)
	}

	key := []byte("compliance:tag:" + foundTag.TagID)
	return ctm.db.Put(key, data)
}

// UpdateAllTagsForPath updates all tags for a specific path
func (ctm *ComplianceTagManager) UpdateAllTagsForPath(ctx context.Context, path string, updateFn func(*ComplianceTag) error) error {
	ctm.mu.Lock()
	defer ctm.mu.Unlock()

	path = normalizeCompliancePath(path)
	tagList, ok := ctm.tags[path]
	if !ok || len(tagList) == 0 {
		return fmt.Errorf("no compliance tags found for path: %s", path)
	}

	// Update all tags
	for _, tag := range tagList {
		if err := updateFn(tag); err != nil {
			return fmt.Errorf("failed to update tag %s: %w", tag.TagID, err)
		}

		// Persist each updated tag
		data, err := json.Marshal(tag)
		if err != nil {
			return fmt.Errorf("failed to marshal tag %s: %w", tag.TagID, err)
		}

		key := []byte("compliance:tag:" + tag.TagID)
		if err := ctm.db.Put(key, data); err != nil {
			return fmt.Errorf("failed to persist tag %s: %w", tag.TagID, err)
		}
	}

	return nil
}

// RemoveTagByID removes a specific compliance tag by its TagID
func (ctm *ComplianceTagManager) RemoveTagByID(ctx context.Context, tagID string) error {
	ctm.mu.Lock()
	defer ctm.mu.Unlock()

	// Find and remove from memory
	for path, tagList := range ctm.tags {
		for i, tag := range tagList {
			if tag.TagID == tagID {
				// Remove from slice
				ctm.tags[path] = append(tagList[:i], tagList[i+1:]...)
				// Clean up empty lists
				if len(ctm.tags[path]) == 0 {
					delete(ctm.tags, path)
				}
				// Remove from database
				key := []byte("compliance:tag:" + tagID)
				return ctm.db.Delete(key)
			}
		}
	}

	return fmt.Errorf("tag not found with ID: %s", tagID)
}

func normalizeCompliancePath(path string) string {
	path = filepath.Clean(path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

// GetEffectiveFrameworks returns all frameworks applicable to a path (including inherited)
func (ctm *ComplianceTagManager) GetEffectiveFrameworks(path string) []ComplianceFramework {
	tag := ctm.GetTag(path)
	if tag == nil {
		return nil
	}
	return tag.Frameworks
}

// CheckCompliance is a convenience method that validates and returns a simple bool
func (ctm *ComplianceTagManager) CheckCompliance(ctx context.Context, path, operation, actor string, encrypted bool) (bool, error) {
	req := &ComplianceOperationRequest{
		Path:      path,
		Operation: operation,
		Actor:     actor,
		Encrypted: encrypted,
		Timestamp: time.Now(),
	}

	result, err := ctm.ValidateOperation(ctx, req)
	if err != nil {
		return false, err
	}

	return result.Allowed, nil
}
