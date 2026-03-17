// Package compliance provides compliance frameworks, reporting, and governance features.
package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/core/policy"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrFrameworkNotSupported  = errors.New("compliance: framework not supported")
	ErrControlNotFound        = errors.New("compliance: control not found")
	ErrReportGenerationFailed = errors.New("compliance: report generation failed")
	ErrNoEvidenceFound        = errors.New("compliance: no evidence found for control")
)

// Framework represents a compliance framework
type Framework string

const (
	FrameworkSOC2      Framework = "SOC2"
	FrameworkHIPAA     Framework = "HIPAA"
	FrameworkGDPR      Framework = "GDPR"
	FrameworkPCIDSS    Framework = "PCI-DSS"
	FrameworkISO27001  Framework = "ISO27001"
	FrameworkNIST80053 Framework = "NIST-800-53"
	FrameworkNISTCSF   Framework = "NIST-CSF"
	FrameworkFedRAMP   Framework = "FedRAMP"
	FrameworkCJIS      Framework = "CJIS"
	FrameworkFIPS140   Framework = "FIPS-140"
)

// DataClassification represents data sensitivity levels
type DataClassification string

const (
	ClassificationPublic       DataClassification = "public"
	ClassificationInternal     DataClassification = "internal"
	ClassificationConfidential DataClassification = "confidential"
	ClassificationRestricted   DataClassification = "restricted"
	ClassificationSecret       DataClassification = "secret"
)

// ControlStatus represents the status of a compliance control
type ControlStatus string

const (
	ControlStatusCompliant     ControlStatus = "compliant"
	ControlStatusNonCompliant  ControlStatus = "non_compliant"
	ControlStatusPartial       ControlStatus = "partial"
	ControlStatusNotApplicable ControlStatus = "not_applicable"
	ControlStatusPending       ControlStatus = "pending"
)

// EvidenceType represents types of compliance evidence
type EvidenceType string

const (
	EvidenceTypeAuditLog      EvidenceType = "audit_log"
	EvidenceTypePolicy        EvidenceType = "policy"
	EvidenceTypeAccessGrant   EvidenceType = "access_grant"
	EvidenceTypeEncryption    EvidenceType = "encryption"
	EvidenceTypeConfiguration EvidenceType = "configuration"
	EvidenceTypeAttestation   EvidenceType = "attestation"
)

// Control represents a compliance control
type Control struct {
	ID          string            `json:"id"`
	Framework   Framework         `json:"framework"`
	Category    string            `json:"category"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Status      ControlStatus     `json:"status"`
	Evidence    []Evidence        `json:"evidence,omitempty"`
	LastChecked *types.Timestamp  `json:"last_checked,omitempty"`
	Mappings    map[string]string `json:"mappings,omitempty"` // maps to other frameworks
}

// Evidence represents compliance evidence
type Evidence struct {
	ID          types.ID        `json:"id"`
	Type        EvidenceType    `json:"type"`
	ResourceID  types.ID        `json:"resource_id"`
	Description string          `json:"description"`
	CollectedAt types.Timestamp `json:"collected_at"`
	Data        types.Metadata  `json:"data,omitempty"`
}

// ComplianceScore represents overall compliance metrics
type ComplianceScore struct {
	Framework          Framework       `json:"framework"`
	Score              float64         `json:"score"`
	TotalControls      int             `json:"total_controls"`
	CompliantCount     int             `json:"compliant_count"`
	PartialCount       int             `json:"partial_count"`
	NonCompliantCount  int             `json:"non_compliant_count"`
	NotApplicableCount int             `json:"not_applicable_count"`
	CalculatedAt       time.Time       `json:"calculated_at"`
	Categories         []CategoryScore `json:"categories"`
}

// CategoryScore represents compliance score for a category
type CategoryScore struct {
	Category       string  `json:"category"`
	Score          float64 `json:"score"`
	TotalControls  int     `json:"total_controls"`
	CompliantCount int     `json:"compliant_count"`
}

// Report represents a compliance report
type Report struct {
	ID          types.ID        `json:"id"`
	Framework   Framework       `json:"framework"`
	OrgID       types.ID        `json:"org_id"`
	Title       string          `json:"title"`
	GeneratedAt time.Time       `json:"generated_at"`
	GeneratedBy types.ID        `json:"generated_by"`
	Period      ReportPeriod    `json:"period"`
	Score       ComplianceScore `json:"score"`
	Controls    []Control       `json:"controls"`
	Summary     string          `json:"summary"`
	Signature   []byte          `json:"signature,omitempty"`
}

// ReportPeriod represents the time period for a report
type ReportPeriod struct {
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
}

// SensitivityTag represents a data sensitivity tag
type SensitivityTag struct {
	ID             types.ID           `json:"id"`
	Name           string             `json:"name"`
	Classification DataClassification `json:"classification"`
	Description    string             `json:"description"`
	Color          string             `json:"color,omitempty"`
	CreatedAt      types.Timestamp    `json:"created_at"`
}

// Engine provides compliance management and reporting
type Engine struct {
	store           *storage.Store
	crypto          *crypto.Engine
	auditEngine     *audit.Engine
	policyEngine    *policy.Engine
	controlStore    *storage.TypedStore[Control]
	reportStore     *storage.TypedStore[Report]
	assessmentStore *storage.TypedStore[Assessment]
	tagStore        *storage.TypedStore[SensitivityTag]
	definitions     map[Framework]*FrameworkDefinition
	signerKey       []byte
}

// FrameworkDefinition defines the structure of a compliance framework
type FrameworkDefinition struct {
	Framework  Framework            `json:"framework"`
	Name       string               `json:"name"`
	Version    string               `json:"version"`
	Categories []CategoryDefinition `json:"categories"`
}

// CategoryDefinition defines a category within a framework
type CategoryDefinition struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Controls []ControlTemplate `json:"controls"`
}

// ControlTemplate defines a control template
type ControlTemplate struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Automated   bool     `json:"automated"`
	Mappings    []string `json:"mappings,omitempty"`
}

// EngineConfig configures the compliance engine
type EngineConfig struct {
	Store        *storage.Store
	AuditEngine  *audit.Engine
	PolicyEngine *policy.Engine
	SignerKey    []byte
}

// NewEngine creates a new compliance engine
func NewEngine(cfg EngineConfig) *Engine {
	e := &Engine{
		store:           cfg.Store,
		crypto:          crypto.NewEngine(""),
		auditEngine:     cfg.AuditEngine,
		policyEngine:    cfg.PolicyEngine,
		controlStore:    storage.NewTypedStore[Control](cfg.Store, "compliance_controls"),
		reportStore:     storage.NewTypedStore[Report](cfg.Store, "compliance_reports"),
		assessmentStore: storage.NewTypedStore[Assessment](cfg.Store, "compliance_assessments"),
		tagStore:        storage.NewTypedStore[SensitivityTag](cfg.Store, "sensitivity_tags"),
		definitions:     make(map[Framework]*FrameworkDefinition),
		signerKey:       cfg.SignerKey,
	}
	e.initializeFrameworks()
	return e
}

// initializeFrameworks loads built-in framework definitions
func (e *Engine) initializeFrameworks() {
	// SOC 2 Type II
	e.definitions[FrameworkSOC2] = &FrameworkDefinition{
		Framework: FrameworkSOC2,
		Name:      "SOC 2 Type II",
		Version:   "2017",
		Categories: []CategoryDefinition{
			{
				ID:   "CC1",
				Name: "Control Environment",
				Controls: []ControlTemplate{
					{ID: "CC1.1", Name: "COSO Principle 1", Description: "Demonstrates commitment to integrity and ethical values", Automated: false},
					{ID: "CC1.2", Name: "COSO Principle 2", Description: "Board exercises oversight responsibility", Automated: false},
					{ID: "CC1.3", Name: "COSO Principle 3", Description: "Management establishes structure and authority", Automated: false},
				},
			},
			{
				ID:   "CC2",
				Name: "Communication and Information",
				Controls: []ControlTemplate{
					{ID: "CC2.1", Name: "COSO Principle 13", Description: "Uses relevant information", Automated: true},
					{ID: "CC2.2", Name: "COSO Principle 14", Description: "Internal communication", Automated: false},
					{ID: "CC2.3", Name: "COSO Principle 15", Description: "External communication", Automated: false},
				},
			},
			{
				ID:   "CC5",
				Name: "Control Activities",
				Controls: []ControlTemplate{
					{ID: "CC5.1", Name: "COSO Principle 10", Description: "Selects and develops control activities", Automated: true},
					{ID: "CC5.2", Name: "COSO Principle 11", Description: "Technology controls", Automated: true},
					{ID: "CC5.3", Name: "COSO Principle 12", Description: "Deploys policies and procedures", Automated: true},
				},
			},
			{
				ID:   "CC6",
				Name: "Logical and Physical Access Controls",
				Controls: []ControlTemplate{
					{ID: "CC6.1", Name: "Access Control", Description: "Restricts logical access", Automated: true, Mappings: []string{"HIPAA-164.312(a)", "GDPR-Art32"}},
					{ID: "CC6.2", Name: "Registration and Authorization", Description: "User access registration", Automated: true},
					{ID: "CC6.3", Name: "Role-Based Access", Description: "Role-based access control", Automated: true},
					{ID: "CC6.6", Name: "Encryption", Description: "Data encryption in transit and at rest", Automated: true, Mappings: []string{"HIPAA-164.312(e)", "PCI-DSS-3.4"}},
					{ID: "CC6.7", Name: "Authentication", Description: "Multi-factor authentication", Automated: true},
				},
			},
			{
				ID:   "CC7",
				Name: "System Operations",
				Controls: []ControlTemplate{
					{ID: "CC7.1", Name: "Detection", Description: "Detects anomalous access", Automated: true},
					{ID: "CC7.2", Name: "Monitoring", Description: "Monitors system components", Automated: true},
					{ID: "CC7.3", Name: "Incident Management", Description: "Evaluates security events", Automated: true},
					{ID: "CC7.4", Name: "Incident Response", Description: "Responds to identified incidents", Automated: true},
				},
			},
			{
				ID:   "CC8",
				Name: "Change Management",
				Controls: []ControlTemplate{
					{ID: "CC8.1", Name: "Change Control", Description: "Authorizes, documents, tests changes", Automated: true},
				},
			},
		},
	}

	// HIPAA
	e.definitions[FrameworkHIPAA] = &FrameworkDefinition{
		Framework: FrameworkHIPAA,
		Name:      "HIPAA Security Rule",
		Version:   "2013",
		Categories: []CategoryDefinition{
			{
				ID:   "164.308",
				Name: "Administrative Safeguards",
				Controls: []ControlTemplate{
					{ID: "164.308(a)(1)", Name: "Security Management", Description: "Security management process", Automated: false},
					{ID: "164.308(a)(3)", Name: "Workforce Security", Description: "Workforce security policies", Automated: true},
					{ID: "164.308(a)(4)", Name: "Access Management", Description: "Information access management", Automated: true},
					{ID: "164.308(a)(5)", Name: "Security Awareness", Description: "Security awareness training", Automated: false},
					{ID: "164.308(a)(6)", Name: "Incident Procedures", Description: "Security incident procedures", Automated: true},
				},
			},
			{
				ID:   "164.312",
				Name: "Technical Safeguards",
				Controls: []ControlTemplate{
					{ID: "164.312(a)", Name: "Access Control", Description: "Unique user identification", Automated: true, Mappings: []string{"SOC2-CC6.1"}},
					{ID: "164.312(b)", Name: "Audit Controls", Description: "Audit controls and logs", Automated: true},
					{ID: "164.312(c)", Name: "Integrity Controls", Description: "Data integrity controls", Automated: true},
					{ID: "164.312(d)", Name: "Authentication", Description: "Person or entity authentication", Automated: true},
					{ID: "164.312(e)", Name: "Transmission Security", Description: "Transmission security", Automated: true, Mappings: []string{"SOC2-CC6.6"}},
				},
			},
		},
	}

	// GDPR
	e.definitions[FrameworkGDPR] = &FrameworkDefinition{
		Framework: FrameworkGDPR,
		Name:      "General Data Protection Regulation",
		Version:   "2018",
		Categories: []CategoryDefinition{
			{
				ID:   "Chapter2",
				Name: "Principles",
				Controls: []ControlTemplate{
					{ID: "Art5", Name: "Processing Principles", Description: "Lawfulness, fairness, transparency", Automated: false},
					{ID: "Art6", Name: "Lawful Processing", Description: "Lawfulness of processing", Automated: false},
				},
			},
			{
				ID:   "Chapter3",
				Name: "Rights of Data Subject",
				Controls: []ControlTemplate{
					{ID: "Art15", Name: "Right of Access", Description: "Right of access by data subject", Automated: true},
					{ID: "Art16", Name: "Right to Rectification", Description: "Right to rectification", Automated: true},
					{ID: "Art17", Name: "Right to Erasure", Description: "Right to erasure (right to be forgotten)", Automated: true},
					{ID: "Art20", Name: "Data Portability", Description: "Right to data portability", Automated: true},
				},
			},
			{
				ID:   "Chapter4",
				Name: "Controller and Processor",
				Controls: []ControlTemplate{
					{ID: "Art25", Name: "Data Protection by Design", Description: "Data protection by design and default", Automated: true},
					{ID: "Art30", Name: "Records of Processing", Description: "Records of processing activities", Automated: true},
					{ID: "Art32", Name: "Security of Processing", Description: "Security of processing", Automated: true, Mappings: []string{"SOC2-CC6.1"}},
					{ID: "Art33", Name: "Breach Notification", Description: "Notification of personal data breach", Automated: true},
					{ID: "Art35", Name: "Impact Assessment", Description: "Data protection impact assessment", Automated: false},
				},
			},
		},
	}

	// PCI-DSS
	e.definitions[FrameworkPCIDSS] = &FrameworkDefinition{
		Framework: FrameworkPCIDSS,
		Name:      "Payment Card Industry Data Security Standard",
		Version:   "4.0",
		Categories: []CategoryDefinition{
			{
				ID:   "Req1",
				Name: "Network Security",
				Controls: []ControlTemplate{
					{ID: "1.1", Name: "Security Policies", Description: "Processes to install and maintain network security", Automated: false},
					{ID: "1.2", Name: "Network Security Controls", Description: "Network security controls configured", Automated: true},
					{ID: "1.3", Name: "Network Access Controls", Description: "Network access restricted", Automated: true},
				},
			},
			{
				ID:   "Req3",
				Name: "Protect Account Data",
				Controls: []ControlTemplate{
					{ID: "3.1", Name: "Data Retention", Description: "Processes to protect stored account data", Automated: true},
					{ID: "3.4", Name: "Encryption", Description: "Strong cryptography for stored PAN", Automated: true, Mappings: []string{"SOC2-CC6.6"}},
					{ID: "3.5", Name: "Key Management", Description: "Cryptographic keys secured", Automated: true},
				},
			},
			{
				ID:   "Req7",
				Name: "Access Control",
				Controls: []ControlTemplate{
					{ID: "7.1", Name: "Access Restriction", Description: "Access to system components restricted", Automated: true},
					{ID: "7.2", Name: "Access Control Systems", Description: "Access control systems configured", Automated: true},
				},
			},
			{
				ID:   "Req8",
				Name: "Authentication",
				Controls: []ControlTemplate{
					{ID: "8.2", Name: "User Identification", Description: "Strong user identification", Automated: true},
					{ID: "8.3", Name: "Strong Authentication", Description: "Multi-factor authentication", Automated: true},
					{ID: "8.4", Name: "MFA Implementation", Description: "MFA for all access", Automated: true},
				},
			},
			{
				ID:   "Req10",
				Name: "Logging and Monitoring",
				Controls: []ControlTemplate{
					{ID: "10.1", Name: "Audit Logging", Description: "Log all access to system components", Automated: true},
					{ID: "10.2", Name: "Audit Trail", Description: "Implement automated audit trails", Automated: true},
					{ID: "10.3", Name: "Log Protection", Description: "Protect audit logs", Automated: true},
					{ID: "10.7", Name: "Log Retention", Description: "Retain audit log history", Automated: true},
				},
			},
		},
	}
}

// GetFrameworks returns all supported frameworks
func (e *Engine) GetFrameworks() []Framework {
	return []Framework{
		FrameworkSOC2,
		FrameworkHIPAA,
		FrameworkGDPR,
		FrameworkPCIDSS,
		FrameworkISO27001,
		FrameworkNIST80053,
		FrameworkNISTCSF,
	}
}

// GetFrameworkDefinition returns the definition for a framework
func (e *Engine) GetFrameworkDefinition(framework Framework) (*FrameworkDefinition, error) {
	def, ok := e.definitions[framework]
	if !ok {
		return nil, ErrFrameworkNotSupported
	}
	return def, nil
}

// EvaluateControl evaluates a specific control and collects evidence
func (e *Engine) EvaluateControl(ctx context.Context, framework Framework, controlID string) (*Control, error) {
	def, err := e.GetFrameworkDefinition(framework)
	if err != nil {
		return nil, err
	}

	var template *ControlTemplate
	var categoryName string
	for _, cat := range def.Categories {
		for _, ctrl := range cat.Controls {
			if ctrl.ID == controlID {
				template = &ctrl
				categoryName = cat.Name
				break
			}
		}
	}
	if template == nil {
		return nil, ErrControlNotFound
	}

	control := &Control{
		ID:          controlID,
		Framework:   framework,
		Category:    categoryName,
		Name:        template.Name,
		Description: template.Description,
		Status:      ControlStatusPending,
		Evidence:    []Evidence{},
	}

	// Automated evidence collection based on control type
	if template.Automated {
		evidence, status := e.collectAutomatedEvidence(ctx, framework, controlID)
		control.Evidence = evidence
		control.Status = status
	} else {
		// Manual evidence check
		evidence, status := e.collectAssessmentEvidence(ctx, framework, controlID)
		if len(evidence) > 0 {
			control.Evidence = evidence
			control.Status = status
		}
	}

	now := types.Now()
	control.LastChecked = &now

	return control, nil
}

// collectAutomatedEvidence collects evidence for automated controlså
func (e *Engine) collectAutomatedEvidence(ctx context.Context, _ Framework, _ string) ([]Evidence, ControlStatus) {
	var evidence []Evidence
	status := ControlStatusPending

	// Get relevant audit events as evidence
	events, err := e.auditEngine.Query(ctx, audit.QueryOptions{
		StartTime: time.Now().Add(-30 * 24 * time.Hour), // Last 30 days
		Limit:     100,
	})
	if err == nil && len(events) > 0 {
		evidence = append(evidence, Evidence{
			Type:        EvidenceTypeAuditLog,
			Description: "Audit trail demonstrating control activity",
			CollectedAt: types.Now(),
			Data: types.Metadata{
				"event_count": len(events),
				"period":      "30 days",
			},
		})
	}

	// Get policies as evidence
	policies, err := e.policyEngine.List(ctx)
	if err == nil && len(policies) > 0 {
		evidence = append(evidence, Evidence{
			Type:        EvidenceTypePolicy,
			Description: "Security policies in place",
			CollectedAt: types.Now(),
			Data: types.Metadata{
				"policy_count": len(policies),
			},
		})
	}

	// Determine compliance status based on evidence
	if len(evidence) >= 2 {
		status = ControlStatusCompliant
	} else if len(evidence) == 1 {
		status = ControlStatusPartial
	} else {
		status = ControlStatusNonCompliant
	}

	return evidence, status
}

// collectAssessmentEvidence checks for manual assessments covering this control
func (e *Engine) collectAssessmentEvidence(ctx context.Context, framework Framework, controlID string) ([]Evidence, ControlStatus) {
	var evidence []Evidence
	status := ControlStatusPending

	// List all assessments
	// In a real system, we would query by (framework, status)
	assessments, _ := e.assessmentStore.List(ctx, "")

	for _, a := range assessments {
		if a.Framework != framework || a.CompletedAt == nil {
			continue
		}

		for _, q := range a.Questions {
			if q.ControlID == controlID && q.Answer != nil {
				notes := q.Answer.Notes
				if notes == "" {
					notes = "Manual assessment response: " + q.Answer.Value
				}

				ev := Evidence{
					Type:        EvidenceTypeAttestation,
					Description: notes,
					CollectedAt: q.Answer.AnsweredAt,
					ResourceID:  a.ID,
					Data: types.Metadata{
						"assessment_id": a.ID,
						"answered_by":   q.Answer.AnsweredBy,
						"value":         q.Answer.Value,
					},
				}
				evidence = append(evidence, ev)

				// If answered positively, marks as compliant
				if q.Answer.Value == "yes" || q.Answer.Value == "true" {
					status = ControlStatusCompliant
				} else {
					status = ControlStatusNonCompliant
				}
			}
		}
	}

	return evidence, status
}

// GetComplianceScore calculates the compliance score for a framework
func (e *Engine) GetComplianceScore(ctx context.Context, framework Framework, orgID types.ID) (*ComplianceScore, error) {
	def, err := e.GetFrameworkDefinition(framework)
	if err != nil {
		return nil, err
	}

	score := &ComplianceScore{
		Framework:    framework,
		CalculatedAt: time.Now(),
		Categories:   []CategoryScore{},
	}

	for _, cat := range def.Categories {
		catScore := CategoryScore{
			Category:      cat.Name,
			TotalControls: len(cat.Controls),
		}

		for _, ctrl := range cat.Controls {
			control, err := e.EvaluateControl(ctx, framework, ctrl.ID)
			if err != nil {
				continue
			}

			score.TotalControls++
			catScore.TotalControls++

			switch control.Status {
			case ControlStatusCompliant:
				score.CompliantCount++
				catScore.CompliantCount++
			case ControlStatusPartial:
				score.PartialCount++
			case ControlStatusNonCompliant:
				score.NonCompliantCount++
			case ControlStatusNotApplicable:
				score.NotApplicableCount++
			}
		}

		if catScore.TotalControls > 0 {
			catScore.Score = float64(catScore.CompliantCount) / float64(catScore.TotalControls) * 100
		}
		score.Categories = append(score.Categories, catScore)
	}

	// Calculate overall score (excluding N/A controls)
	applicable := score.TotalControls - score.NotApplicableCount
	if applicable > 0 {
		// Partial controls count as 50%
		effectiveCompliant := float64(score.CompliantCount) + float64(score.PartialCount)*0.5
		score.Score = effectiveCompliant / float64(applicable) * 100
	}

	return score, nil
}

// GenerateReport generates a compliance report
func (e *Engine) GenerateReport(ctx context.Context, opts GenerateReportOptions) (*Report, error) {
	def, err := e.GetFrameworkDefinition(opts.Framework)
	if err != nil {
		return nil, err
	}

	// Get compliance score
	score, err := e.GetComplianceScore(ctx, opts.Framework, opts.OrgID)
	if err != nil {
		return nil, err
	}

	// Collect all controls
	var controls []Control
	for _, cat := range def.Categories {
		for _, ctrl := range cat.Controls {
			control, err := e.EvaluateControl(ctx, opts.Framework, ctrl.ID)
			if err != nil {
				continue
			}
			controls = append(controls, *control)
		}
	}

	// Sort controls by status (non-compliant first)
	sort.Slice(controls, func(i, j int) bool {
		statusOrder := map[ControlStatus]int{
			ControlStatusNonCompliant:  0,
			ControlStatusPartial:       1,
			ControlStatusPending:       2,
			ControlStatusCompliant:     3,
			ControlStatusNotApplicable: 4,
		}
		return statusOrder[controls[i].Status] < statusOrder[controls[j].Status]
	})

	id, err := e.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	report := &Report{
		ID:          id,
		Framework:   opts.Framework,
		OrgID:       opts.OrgID,
		Title:       def.Name + " Compliance Report",
		GeneratedAt: time.Now(),
		GeneratedBy: opts.GeneratedBy,
		Period:      opts.Period,
		Score:       *score,
		Controls:    controls,
		Summary:     e.generateSummary(score, controls),
	}

	// Sign the report
	if len(e.signerKey) > 0 {
		reportData, _ := json.Marshal(report)
		report.Signature, _ = e.crypto.Sign(e.signerKey, reportData)
	}

	// Store the report
	if err := e.reportStore.Set(ctx, string(report.ID), report); err != nil {
		return nil, err
	}

	return report, nil
}

// GenerateReportOptions holds options for generating a report
type GenerateReportOptions struct {
	Framework   Framework
	OrgID       types.ID
	GeneratedBy types.ID
	Period      ReportPeriod
}

// generateSummary generates a human-readable summary
func (e *Engine) generateSummary(score *ComplianceScore, _ []Control) string {
	if score.Score >= 90 {
		return "Organization demonstrates strong compliance posture with comprehensive controls in place."
	} else if score.Score >= 70 {
		return "Organization shows good compliance with some areas requiring improvement."
	} else if score.Score >= 50 {
		return "Organization has partial compliance. Significant improvements needed in multiple areas."
	}
	return "Organization requires substantial compliance improvements across most control areas."
}

// GetReport retrieves a report by ID
func (e *Engine) GetReport(ctx context.Context, id types.ID) (*Report, error) {
	return e.reportStore.Get(ctx, string(id))
}

// ListReports lists reports for an organization
func (e *Engine) ListReports(ctx context.Context, orgID types.ID) ([]*Report, error) {
	all, err := e.reportStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var reports []*Report
	for _, r := range all {
		if r.OrgID == orgID {
			reports = append(reports, r)
		}
	}

	// Sort by date descending
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].GeneratedAt.After(reports[j].GeneratedAt)
	})

	return reports, nil
}

// VerifyReport verifies a report's signature
func (e *Engine) VerifyReport(report *Report, signerPubKey []byte) error {
	reportCopy := *report
	reportCopy.Signature = nil
	data, _ := json.Marshal(reportCopy)
	return e.crypto.Verify(signerPubKey, data, report.Signature)
}

// CreateSensitivityTag creates a new sensitivity tag
func (e *Engine) CreateSensitivityTag(ctx context.Context, opts CreateTagOptions) (*SensitivityTag, error) {
	id, err := e.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	tag := &SensitivityTag{
		ID:             id,
		Name:           opts.Name,
		Classification: opts.Classification,
		Description:    opts.Description,
		Color:          opts.Color,
		CreatedAt:      types.Now(),
	}

	if err := e.tagStore.Set(ctx, string(tag.ID), tag); err != nil {
		return nil, err
	}

	return tag, nil
}

// CreateTagOptions holds options for creating a tag
type CreateTagOptions struct {
	Name           string
	Classification DataClassification
	Description    string
	Color          string
}

// GetSensitivityTag retrieves a tag by ID
func (e *Engine) GetSensitivityTag(ctx context.Context, id types.ID) (*SensitivityTag, error) {
	return e.tagStore.Get(ctx, string(id))
}

// ListSensitivityTags lists all sensitivity tags
func (e *Engine) ListSensitivityTags(ctx context.Context) ([]*SensitivityTag, error) {
	return e.tagStore.List(ctx, "")
}

// DeleteSensitivityTag deletes a sensitivity tag
func (e *Engine) DeleteSensitivityTag(ctx context.Context, id types.ID) error {
	return e.tagStore.Delete(ctx, string(id))
}

// Close cleans up resources
func (e *Engine) Close() error {
	return e.crypto.Close()
}
