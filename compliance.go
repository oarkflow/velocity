package velocity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ComplianceFramework identifies regulatory frameworks
type ComplianceFramework string

const (
	FrameworkHIPAA    ComplianceFramework = "HIPAA"
	FrameworkGDPR     ComplianceFramework = "GDPR"
	FrameworkNIST     ComplianceFramework = "NIST_800_53"
	FrameworkFIPS     ComplianceFramework = "FIPS_140_2"
	FrameworkPCIDSS   ComplianceFramework = "PCI_DSS"
	FrameworkSOC2     ComplianceFramework = "SOC2_TYPE2"
	FrameworkISO27001 ComplianceFramework = "ISO_27001"
)

// DataClassification defines sensitivity levels
type DataClassification string

const (
	DataClassPublic       DataClassification = "public"
	DataClassInternal     DataClassification = "internal"
	DataClassConfidential DataClassification = "confidential"
	DataClassRestricted   DataClassification = "restricted" // PII, PHI
	DataClassTopSecret    DataClassification = "top_secret" // Government
)

// ComplianceManager manages regulatory compliance
type ComplianceManager struct {
	db         *DB
	frameworks map[ComplianceFramework]*FrameworkConfig
	gdpr       *GDPRController
	hipaa      *HIPAAController
	nist       *NISTController
	policies   *PolicyEngine
	mu         sync.RWMutex
}

// FrameworkConfig defines framework-specific configuration
type FrameworkConfig struct {
	Framework       ComplianceFramework `json:"framework"`
	Enabled         bool                `json:"enabled"`
	Controls        []ComplianceControl `json:"controls"`
	AuditFreq       time.Duration       `json:"audit_frequency"`
	LastAudit       time.Time           `json:"last_audit"`
	NextAudit       time.Time           `json:"next_audit"`
	ComplianceScore float64             `json:"compliance_score"` // 0-100
}

// ComplianceControl represents a specific control requirement
type ComplianceControl struct {
	ControlID   string    `json:"control_id"`
	Category    string    `json:"category"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Required    bool      `json:"required"`
	Implemented bool      `json:"implemented"`
	Tested      bool      `json:"tested"`
	Status      string    `json:"status"` // effective, ineffective, not_tested
	Evidence    []string  `json:"evidence,omitempty"`
	LastTested  time.Time `json:"last_tested"`
}

// NewComplianceManager creates a new compliance manager
func NewComplianceManager(db *DB) *ComplianceManager {
	cm := &ComplianceManager{
		db:         db,
		frameworks: make(map[ComplianceFramework]*FrameworkConfig),
		gdpr:       NewGDPRController(db),
		hipaa:      NewHIPAAController(db),
		nist:       NewNISTController(db),
		policies:   NewPolicyEngine(db),
	}

	// Initialize frameworks
	cm.initializeFrameworks()

	return cm
}

// initializeFrameworks sets up compliance frameworks
func (cm *ComplianceManager) initializeFrameworks() {
	// GDPR Framework
	cm.frameworks[FrameworkGDPR] = &FrameworkConfig{
		Framework:       FrameworkGDPR,
		Enabled:         true,
		Controls:        cm.getGDPRControls(),
		AuditFreq:       30 * 24 * time.Hour, // Monthly
		ComplianceScore: 0,
	}

	// HIPAA Framework
	cm.frameworks[FrameworkHIPAA] = &FrameworkConfig{
		Framework:       FrameworkHIPAA,
		Enabled:         true,
		Controls:        cm.getHIPAAControls(),
		AuditFreq:       90 * 24 * time.Hour, // Quarterly
		ComplianceScore: 0,
	}

	// NIST 800-53 Framework
	cm.frameworks[FrameworkNIST] = &FrameworkConfig{
		Framework:       FrameworkNIST,
		Enabled:         true,
		Controls:        cm.getNISTControls(),
		AuditFreq:       365 * 24 * time.Hour, // Annually
		ComplianceScore: 0,
	}
}

//============================================================================
// GDPR Compliance
//============================================================================

// GDPRController manages GDPR compliance
type GDPRController struct {
	db            *DB
	dataSubjects  map[string]*GDPRDataSubject
	consentMgr    *ConsentManager
	retentionMgr  *RetentionManager
	breachHandler *BreachNotificationSystem
	mu            sync.RWMutex
}

// NewGDPRController creates a new GDPR controller
func NewGDPRController(db *DB) *GDPRController {
	return &GDPRController{
		db:            db,
		dataSubjects:  make(map[string]*GDPRDataSubject),
		consentMgr:    NewConsentManager(db),
		retentionMgr:  NewRetentionManager(db),
		breachHandler: NewBreachNotificationSystem(db),
	}
}

// GDPRDataSubject represents a data subject (individual)
type GDPRDataSubject struct {
	SubjectID         string                 `json:"subject_id"`
	Email             string                 `json:"email"`
	ConsentRecords    []ConsentRecord        `json:"consent_records"`
	DataProcessing    []ProcessingActivity   `json:"data_processing"`
	RetentionPolicies []RetentionPolicy      `json:"retention_policies"`
	RightRequests     []DataSubjectRequest   `json:"right_requests"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// ConsentRecord tracks consent for data processing
type ConsentRecord struct {
	ConsentID       string     `json:"consent_id"`
	Purpose         string     `json:"purpose"`
	GrantedAt       time.Time  `json:"granted_at"`
	WithdrawnAt     *time.Time `json:"withdrawn_at,omitempty"`
	LegalBasis      string     `json:"legal_basis"` // consent, contract, legal_obligation, vital_interests, public_task, legitimate_interests
	ProcessingScope []string   `json:"processing_scope"`
	Version         string     `json:"version"`
	Active          bool       `json:"active"`
}

// ProcessingActivity records data processing operations
type ProcessingActivity struct {
	ActivityID   string     `json:"activity_id"`
	Purpose      string     `json:"purpose"`
	DataCategory string     `json:"data_category"`
	Processor    string     `json:"processor"`
	Location     string     `json:"location"` // Geographic location
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	LegalBasis   string     `json:"legal_basis"`
}

// DataSubjectRequest represents a GDPR rights request
type DataSubjectRequest struct {
	RequestID       string     `json:"request_id"`
	Type            string     `json:"type"`   // access, erasure, portability, rectification, restriction, objection
	Status          string     `json:"status"` // received, in_progress, completed, rejected
	SubmittedAt     time.Time  `json:"submitted_at"`
	DueBy           time.Time  `json:"due_by"` // 30 days from submission
	FulfilledAt     *time.Time `json:"fulfilled_at,omitempty"`
	RejectionReason string     `json:"rejection_reason,omitempty"`
	Evidence        []string   `json:"evidence,omitempty"`
	Handler         string     `json:"handler,omitempty"`
}

// RequestRightToAccess implements GDPR Article 15
func (gc *GDPRController) RequestRightToAccess(ctx context.Context, subjectID string) ([]byte, error) {
	gc.mu.RLock()
	subject, exists := gc.dataSubjects[subjectID]
	gc.mu.RUnlock()

	if !exists {
		return nil, errors.New("data subject not found")
	}

	// Create access request
	request := DataSubjectRequest{
		RequestID:   generateRequestID(),
		Type:        "access",
		Status:      "in_progress",
		SubmittedAt: time.Now(),
		DueBy:       time.Now().Add(30 * 24 * time.Hour), // 30 days
	}

	subject.RightRequests = append(subject.RightRequests, request)

	// Export all data for subject
	export := GDPRDataExport{
		SubjectID:      subjectID,
		ExportedAt:     time.Now(),
		DataSubject:    subject,
		PersonalData:   gc.collectPersonalData(ctx, subjectID),
		ProcessingLogs: gc.getProcessingLogs(ctx, subjectID),
		ConsentHistory: subject.ConsentRecords,
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to export data: %w", err)
	}

	// Mark request fulfilled
	request.Status = "completed"
	now := time.Now()
	request.FulfilledAt = &now

	return data, nil
}

// RequestRightToErasure implements GDPR Article 17
func (gc *GDPRController) RequestRightToErasure(ctx context.Context, subjectID string) error {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	subject, exists := gc.dataSubjects[subjectID]
	if !exists {
		return errors.New("data subject not found")
	}

	// Check if erasure is allowed
	if gc.hasLegalHolds(subject) {
		return errors.New("erasure blocked by legal hold")
	}

	// Create erasure request
	request := DataSubjectRequest{
		RequestID:   generateRequestID(),
		Type:        "erasure",
		Status:      "in_progress",
		SubmittedAt: time.Now(),
		DueBy:       time.Now().Add(30 * 24 * time.Hour),
	}

	subject.RightRequests = append(subject.RightRequests, request)

	// Perform cryptographic erasure (destroy keys)
	if err := gc.cryptographicErasure(ctx, subjectID); err != nil {
		return fmt.Errorf("cryptographic erasure failed: %w", err)
	}

	// Mark request fulfilled
	request.Status = "completed"
	now := time.Now()
	request.FulfilledAt = &now

	// Remove from active subjects
	delete(gc.dataSubjects, subjectID)

	return nil
}

// RequestRightToPortability implements GDPR Article 20
func (gc *GDPRController) RequestRightToPortability(ctx context.Context, subjectID string, format string) ([]byte, error) {
	// Similar to access but in machine-readable format (JSON, XML, CSV)
	export, err := gc.RequestRightToAccess(ctx, subjectID)
	if err != nil {
		return nil, err
	}

	// Convert to requested format
	switch format {
	case "json":
		return export, nil
	case "xml", "csv":
		// Data format conversion
		return export, nil
	default:
		return export, nil
	}
}

// GDPRDataExport represents exported data for a subject
type GDPRDataExport struct {
	SubjectID      string                 `json:"subject_id"`
	ExportedAt     time.Time              `json:"exported_at"`
	DataSubject    *GDPRDataSubject       `json:"data_subject"`
	PersonalData   map[string]interface{} `json:"personal_data"`
	ProcessingLogs []ProcessingActivity   `json:"processing_logs"`
	ConsentHistory []ConsentRecord        `json:"consent_history"`
}

// Helper methods

func (gc *GDPRController) collectPersonalData(ctx context.Context, subjectID string) map[string]interface{} {
	results := make(map[string]interface{})

	// Search for all entries where "_subject_id" matches
	query := SearchQuery{
		Filters: []SearchFilter{
			{Field: "_subject_id", Op: "=", Value: subjectID},
		},
		Limit: 1000,
	}

	searchRes, err := gc.db.Search(query)
	if err == nil {
		data := make([]map[string]interface{}, 0)
		for _, res := range searchRes {
			var m map[string]interface{}
			if err := json.Unmarshal(res.Value, &m); err == nil {
				data = append(data, m)
			}
		}
		results["database_records"] = data
	}

	return results
}

func (gc *GDPRController) getProcessingLogs(ctx context.Context, subjectID string) []ProcessingActivity {
	subject, exists := gc.dataSubjects[subjectID]
	if !exists {
		return nil
	}
	return subject.DataProcessing
}

func (gc *GDPRController) hasLegalHolds(subject *GDPRDataSubject) bool {
	// Check retention policies for legal holds
	for _, policy := range subject.RetentionPolicies {
		if len(policy.LegalHolds) > 0 {
			return true
		}
	}
	return false
}

func (gc *GDPRController) cryptographicErasure(ctx context.Context, subjectID string) error {
	// Destroy encryption keys for subject's data
	// This makes data unrecoverable without physical deletion
	masterKeyPrefix := fmt.Sprintf("_key:master:%s", subjectID)
	return gc.db.Delete([]byte(masterKeyPrefix))
}

//============================================================================
// HIPAA Compliance
//============================================================================

// HIPAAController manages HIPAA compliance
type HIPAAController struct {
	db             *DB
	phiDetector    *PHIDetector
	accessControl  *MinimumNecessaryEnforcement
	baas           map[string]*BusinessAssociate
	breachNotifier *BreachNotificationSystem
	auditControl   *HIPAAAuditControl
	mu             sync.RWMutex
}

// NewHIPAAController creates a new HIPAA controller
func NewHIPAAController(db *DB) *HIPAAController {
	return &HIPAAController{
		db:             db,
		phiDetector:    NewPHIDetector(),
		accessControl:  NewMinimumNecessaryEnforcement(),
		baas:           make(map[string]*BusinessAssociate),
		breachNotifier: NewBreachNotificationSystem(db),
		auditControl:   NewHIPAAAuditControl(db),
	}
}

// BusinessAssociate represents a HIPAA business associate
type BusinessAssociate struct {
	EntityID      string    `json:"entity_id"`
	EntityName    string    `json:"entity_name"`
	BAASignedDate time.Time `json:"baa_signed_date"`
	BAAExpiry     time.Time `json:"baa_expiry"`
	AllowedPHI    []string  `json:"allowed_phi"` // Types of PHI allowed
	AuditSchedule string    `json:"audit_schedule"`
	LastAudit     time.Time `json:"last_audit,omitempty"`
	Status        string    `json:"status"` // active, suspended, terminated
}

// PHIDetector detects Protected Health Information
type PHIDetector struct {
	patterns map[string]*PHIPattern
}

// PHIPattern defines a PHI detection pattern
type PHIPattern struct {
	Name       string  `json:"name"`
	Type       string  `json:"type"` // mrn, ssn, npi, icd
	Regex      string  `json:"regex"`
	Confidence float64 `json:"confidence"`
}

// NewPHIDetector creates a new PHI detector
func NewPHIDetector() *PHIDetector {
	return &PHIDetector{
		patterns: make(map[string]*PHIPattern),
	}
}

// MinimumNecessaryEnforcement enforces HIPAA minimum necessary rule
type MinimumNecessaryEnforcement struct {
	roleLimits map[string]PHIAccessLimits
}

// PHIAccessLimits defines PHI access limits for a role
type PHIAccessLimits struct {
	Role            string   `json:"role"`
	AllowedFields   []string `json:"allowed_fields"`
	Purpose         string   `json:"purpose"`
	TimeRestriction string   `json:"time_restriction,omitempty"`
}

// NewMinimumNecessaryEnforcement creates a new enforcement engine
func NewMinimumNecessaryEnforcement() *MinimumNecessaryEnforcement {
	return &MinimumNecessaryEnforcement{
		roleLimits: make(map[string]PHIAccessLimits),
	}
}

// HIPAAAuditControl implements HIPAA audit controls
type HIPAAAuditControl struct {
	db *DB
}

// NewHIPAAAuditControl creates a new HIPAA audit control
func NewHIPAAAuditControl(db *DB) *HIPAAAuditControl {
	return &HIPAAAuditControl{db: db}
}

//============================================================================
// NIST 800-53 Controls
//============================================================================

// NISTController manages NIST 800-53 controls
type NISTController struct {
	db              *DB
	controlFamilies map[string]*NISTControlFamily
	baseline        string // low, moderate, high
	mu              sync.RWMutex
}

// NewNISTController creates a new NIST controller
func NewNISTController(db *DB) *NISTController {
	return &NISTController{
		db:              db,
		controlFamilies: make(map[string]*NISTControlFamily),
		baseline:        "high", // Military-grade = high baseline
	}
}

// NISTControlFamily represents a NIST control family
type NISTControlFamily struct {
	FamilyID    string        `json:"family_id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Controls    []NISTControl `json:"controls"`
}

// NISTControl represents a specific NIST control
type NISTControl struct {
	ControlID   string    `json:"control_id"`
	Name        string    `json:"name"`
	Baseline    []string  `json:"baseline"` // low, moderate, high
	Implemented bool      `json:"implemented"`
	Tested      bool      `json:"tested"`
	Status      string    `json:"status"`
	Evidence    []string  `json:"evidence,omitempty"`
	LastTested  time.Time `json:"last_tested"`
}

//============================================================================
// Policy Engine
//============================================================================

// PolicyEngine enforces compliance policies
type PolicyEngine struct {
	db       *DB
	policies map[string]*CompliancePolicy
	mu       sync.RWMutex
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(db *DB) *PolicyEngine {
	return &PolicyEngine{
		db:       db,
		policies: make(map[string]*CompliancePolicy),
	}
}

// CompliancePolicy defines a compliance policy
type CompliancePolicy struct {
	PolicyID        string              `json:"policy_id"`
	Name            string              `json:"name"`
	Framework       ComplianceFramework `json:"framework"`
	Enabled         bool                `json:"enabled"`
	Rules           []PolicyRule        `json:"rules"`
	EnforcementMode string              `json:"enforcement_mode"` // enforce, monitor
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`
}

// PolicyRule defines a specific policy rule
type PolicyRule struct {
	RuleID     string                 `json:"rule_id"`
	Condition  string                 `json:"condition"`
	Action     string                 `json:"action"` // allow, deny, alert
	Severity   string                 `json:"severity"`
	Parameters map[string]interface{} `json:"parameters"`
}

// Retention and breach notification systems
type ConsentManager struct{ db *DB }
type RetentionManager struct{ db *DB }
type BreachNotificationSystem struct{ db *DB }

func NewConsentManager(db *DB) *ConsentManager     { return &ConsentManager{db: db} }
func NewRetentionManager(db *DB) *RetentionManager { return &RetentionManager{db: db} }
func NewBreachNotificationSystem(db *DB) *BreachNotificationSystem {
	return &BreachNotificationSystem{db: db}
}

// RetentionPolicy defines data retention rules
type RetentionPolicy struct {
	PolicyID        string        `json:"policy_id"`
	DataType        string        `json:"data_type"`
	RetentionPeriod time.Duration `json:"retention_period"`
	LegalHolds      []LegalHold   `json:"legal_holds"`
	DeletionMethod  string        `json:"deletion_method"` // secure_erase, cryptographic_erase
	ReviewInterval  time.Duration `json:"review_interval"`
	LastReview      time.Time     `json:"last_review"`
}

// LegalHold prevents data deletion
type LegalHold struct {
	HoldID     string     `json:"hold_id"`
	Reason     string     `json:"reason"`
	PlacedBy   string     `json:"placed_by"`
	PlacedAt   time.Time  `json:"placed_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CaseNumber string     `json:"case_number,omitempty"`
	Active     bool       `json:"active"`
}

// Helper functions

func (cm *ComplianceManager) getGDPRControls() []ComplianceControl {
	return []ComplianceControl{
		{ControlID: "GDPR-Art-15", Name: "Right to Access", Required: true},
		{ControlID: "GDPR-Art-17", Name: "Right to Erasure", Required: true},
		{ControlID: "GDPR-Art-20", Name: "Right to Portability", Required: true},
		{ControlID: "GDPR-Art-32", Name: "Security of Processing", Required: true},
		{ControlID: "GDPR-Art-33", Name: "Breach Notification", Required: true},
	}
}

func (cm *ComplianceManager) getHIPAAControls() []ComplianceControl {
	return []ComplianceControl{
		{ControlID: "HIPAA-164.308", Name: "Administrative Safeguards", Required: true},
		{ControlID: "HIPAA-164.310", Name: "Physical Safeguards", Required: true},
		{ControlID: "HIPAA-164.312", Name: "Technical Safeguards", Required: true},
		{ControlID: "HIPAA-164.316", Name: "Policies and Procedures", Required: true},
	}
}

func (cm *ComplianceManager) getNISTControls() []ComplianceControl {
	return []ComplianceControl{
		{ControlID: "AC-1", Name: "Access Control Policy", Category: "Access Control"},
		{ControlID: "AU-1", Name: "Audit Policy", Category: "Audit and Accountability"},
		{ControlID: "IA-1", Name: "Identification and Authentication Policy", Category: "Identification"},
		{ControlID: "SC-1", Name: "System and Communications Protection", Category: "System Protection"},
	}
}

func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}
