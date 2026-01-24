package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ComplianceReport represents a comprehensive compliance report
type ComplianceReport struct {
	ReportID       string                `json:"report_id"`
	GeneratedAt    time.Time             `json:"generated_at"`
	GeneratedBy    string                `json:"generated_by"`
	ReportType     string                `json:"report_type"` // hipaa, gdpr, pci_dss, sox, all
	Period         ReportPeriod          `json:"period"`
	Summary        *ComplianceSummary    `json:"summary"`
	AuditStats     *AuditStatsSummary    `json:"audit_stats"`
	ViolationStats *ViolationStats       `json:"violation_stats"`
	DataInventory  *DataInventorySummary `json:"data_inventory"`
	Recommendations []string             `json:"recommendations"`
	ExportFormat   string                `json:"export_format"` // json, pdf, csv
}

// ReportPeriod defines the time period for a report
type ReportPeriod struct {
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
	Duration  string    `json:"duration"` // daily, weekly, monthly, quarterly, yearly
}

// ComplianceSummary provides high-level compliance metrics
type ComplianceSummary struct {
	TotalOperations       int                `json:"total_operations"`
	AllowedOperations     int                `json:"allowed_operations"`
	DeniedOperations      int                `json:"denied_operations"`
	ComplianceRate        float64            `json:"compliance_rate"` // percentage
	FrameworkBreakdown    map[string]int     `json:"framework_breakdown"`
	DataClassBreakdown    map[string]int     `json:"data_class_breakdown"`
	EncryptedOperations   int                `json:"encrypted_operations"`
	MFAVerifiedOperations int                `json:"mfa_verified_operations"`
	TopPaths              []PathAccess       `json:"top_paths"`
}

// AuditStatsSummary summarizes audit trail data
type AuditStatsSummary struct {
	TotalEvents       int                `json:"total_events"`
	ByAction          map[string]int     `json:"by_action"`
	ByOutcome         map[string]int     `json:"by_outcome"`
	UniqueActors      int                `json:"unique_actors"`
	TopActors         []ActorActivity    `json:"top_actors"`
	AverageDuration   float64            `json:"average_duration_ms"`
	IntegrityVerified bool               `json:"integrity_verified"`
}

// DataInventorySummary provides inventory of classified data
type DataInventorySummary struct {
	TotalRecords       int                `json:"total_records"`
	ByDataClass        map[string]int     `json:"by_data_class"`
	ByFramework        map[string]int     `json:"by_framework"`
	TaggedFolders      int                `json:"tagged_folders"`
	TaggedKeys         int                `json:"tagged_keys"`
	UntaggedRecords    int                `json:"untagged_records"`
	RetentionExpiring  []RetentionAlert   `json:"retention_expiring"`
}

// PathAccess represents access statistics for a path
type PathAccess struct {
	Path          string `json:"path"`
	AccessCount   int    `json:"access_count"`
	LastAccessed  time.Time `json:"last_accessed"`
	DataClass     string `json:"data_class"`
}

// ActorActivity represents activity statistics for an actor
type ActorActivity struct {
	Actor      string   `json:"actor"`
	EventCount int      `json:"event_count"`
	Actions    []string `json:"actions"`
}

// RetentionAlert represents data approaching retention limits
type RetentionAlert struct {
	Path           string    `json:"path"`
	DataClass      string    `json:"data_class"`
	Framework      string    `json:"framework"`
	RetentionDays  int       `json:"retention_days"`
	ExpiresAt      time.Time `json:"expires_at"`
	DaysRemaining  int       `json:"days_remaining"`
}

// ReportingManager manages compliance reporting
type ReportingManager struct {
	db                *DB
	auditManager      *AuditLogManager
	violationsManager *ViolationsManager
	mu                sync.RWMutex
}

// NewReportingManager creates a new reporting manager
func NewReportingManager(
	db *DB,
	auditManager *AuditLogManager,
	violationsManager *ViolationsManager,
) *ReportingManager {
	return &ReportingManager{
		db:                db,
		auditManager:      auditManager,
		violationsManager: violationsManager,
	}
}

// GenerateReport generates a comprehensive compliance report
func (rm *ReportingManager) GenerateReport(
	ctx context.Context,
	reportType string,
	period ReportPeriod,
	generatedBy string,
) (*ComplianceReport, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	report := &ComplianceReport{
		ReportID:    fmt.Sprintf("report:%d", time.Now().UnixNano()),
		GeneratedAt: time.Now(),
		GeneratedBy: generatedBy,
		ReportType:  reportType,
		Period:      period,
		ExportFormat: "json",
	}

	// Generate compliance summary
	summary, err := rm.generateComplianceSummary(ctx, reportType, period)
	if err != nil {
		return nil, fmt.Errorf("failed to generate compliance summary: %w", err)
	}
	report.Summary = summary

	// Generate audit stats
	auditStats, err := rm.generateAuditStats(ctx, reportType, period)
	if err != nil {
		return nil, fmt.Errorf("failed to generate audit stats: %w", err)
	}
	report.AuditStats = auditStats

	// Generate violation stats
	violationFilter := &ViolationFilter{
		StartTime: period.StartDate,
		EndTime:   period.EndDate,
	}
	if reportType != "all" {
		violationFilter.Framework = strings.ToUpper(reportType)
	}
	violationStats, err := rm.violationsManager.GetViolationStats(ctx, violationFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to generate violation stats: %w", err)
	}
	report.ViolationStats = violationStats

	// Generate data inventory
	inventory, err := rm.generateDataInventory(ctx, reportType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data inventory: %w", err)
	}
	report.DataInventory = inventory

	// Generate recommendations
	report.Recommendations = rm.generateRecommendations(
		summary,
		violationStats,
		inventory,
	)

	return report, nil
}

// generateComplianceSummary creates compliance summary metrics
func (rm *ReportingManager) generateComplianceSummary(
	ctx context.Context,
	reportType string,
	period ReportPeriod,
) (*ComplianceSummary, error) {
	summary := &ComplianceSummary{
		FrameworkBreakdown: make(map[string]int),
		DataClassBreakdown: make(map[string]int),
		TopPaths:           make([]PathAccess, 0),
	}

	// Get audit logs for period
	logs, err := rm.auditManager.GetComplianceLogs(&AuditLogFilter{
		StartTime: period.StartDate,
		EndTime:   period.EndDate,
	})
	if err != nil {
		return nil, err
	}

	pathAccessMap := make(map[string]*PathAccess)

	for _, log := range logs {
		summary.TotalOperations++

		if log.Result == "success" || log.Result == "allowed" {
			summary.AllowedOperations++
		} else {
			summary.DeniedOperations++
		}

		// Framework breakdown
		for _, fw := range log.ComplianceTags {
			fwStr := string(fw)
			if reportType == "all" || strings.ToLower(fwStr) == strings.ToLower(reportType) {
				summary.FrameworkBreakdown[fwStr]++
			}
		}

		// Data class breakdown
		if log.Classification != "" {
			summary.DataClassBreakdown[string(log.Classification)]++
		}

		// Encryption and MFA tracking would require additional metadata
		// For now, we'll estimate from the audit event metadata
		if log.Metadata != nil {
			if encrypted, ok := log.Metadata["encrypted"].(bool); ok && encrypted {
				summary.EncryptedOperations++
			}
			if mfa, ok := log.Metadata["mfa_verified"].(bool); ok && mfa {
				summary.MFAVerifiedOperations++
			}
		}

		// Path access tracking
		if log.Resource != "" {
			if pathAccessMap[log.Resource] == nil {
				pathAccessMap[log.Resource] = &PathAccess{
					Path:         log.Resource,
					AccessCount:  0,
					DataClass:    string(log.Classification),
				}
			}
			pathAccessMap[log.Resource].AccessCount++
			if log.Timestamp.After(pathAccessMap[log.Resource].LastAccessed) {
				pathAccessMap[log.Resource].LastAccessed = log.Timestamp
			}
		}
	}

	// Calculate compliance rate
	if summary.TotalOperations > 0 {
		summary.ComplianceRate = float64(summary.AllowedOperations) / float64(summary.TotalOperations) * 100
	}

	// Get top paths
	for _, pa := range pathAccessMap {
		summary.TopPaths = append(summary.TopPaths, *pa)
	}
	// Sort by access count
	for i := 0; i < len(summary.TopPaths)-1; i++ {
		for j := i + 1; j < len(summary.TopPaths); j++ {
			if summary.TopPaths[i].AccessCount < summary.TopPaths[j].AccessCount {
				summary.TopPaths[i], summary.TopPaths[j] = summary.TopPaths[j], summary.TopPaths[i]
			}
		}
	}
	if len(summary.TopPaths) > 10 {
		summary.TopPaths = summary.TopPaths[:10]
	}

	return summary, nil
}

// generateAuditStats creates audit trail statistics
func (rm *ReportingManager) generateAuditStats(
	ctx context.Context,
	reportType string,
	period ReportPeriod,
) (*AuditStatsSummary, error) {
	stats, err := rm.auditManager.GetStats(ctx, &AuditLogFilter{
		StartTime: period.StartDate,
		EndTime:   period.EndDate,
	})
	if err != nil {
		return nil, err
	}

	// Verify audit log integrity
	integrityErr := rm.auditManager.VerifyIntegrity(ctx)

	summary := &AuditStatsSummary{
		TotalEvents:       int(stats.TotalLogs),
		ByAction:          make(map[string]int),
		ByOutcome:         make(map[string]int),
		UniqueActors:      len(stats.TopViolators),
		TopActors:         make([]ActorActivity, 0),
		AverageDuration:   0, // Would calculate from logs
		IntegrityVerified: integrityErr == nil,
	}

	// Convert int64 to int for ByAction
	for action, count := range stats.CommonActions {
		summary.ByAction[action] = int(count)
	}

	summary.ByOutcome["allowed"] = int(stats.AllowedOps)
	summary.ByOutcome["denied"] = int(stats.DeniedOps)

	// Convert top violators to top actors
	for _, tv := range stats.TopViolators {
		summary.TopActors = append(summary.TopActors, ActorActivity{
			Actor:      tv.Actor,
			EventCount: int(tv.TotalOps),
			Actions:    []string{}, // Would need to track from events
		})
	}

	return summary, nil
}

// generateDataInventory creates data inventory summary
func (rm *ReportingManager) generateDataInventory(
	ctx context.Context,
	reportType string,
) (*DataInventorySummary, error) {
	inventory := &DataInventorySummary{
		ByDataClass:       make(map[string]int),
		ByFramework:       make(map[string]int),
		RetentionExpiring: make([]RetentionAlert, 0),
	}

	// Load compliance tags directly by querying the database
	allKeys, err := rm.db.Keys("compliance:tag:*")
	if err != nil {
		return inventory, nil
	}

	allTags := make(map[string][]*ComplianceTag)
	for _, key := range allKeys {
		data, err := rm.db.Get([]byte(key))
		if err != nil {
			continue
		}

		var tags []*ComplianceTag
		if err := json.Unmarshal(data, &tags); err != nil {
			continue
		}

		// Extract path from key
		path := strings.TrimPrefix(key, "compliance:tag:")
		allTags[path] = tags
	}

	for path, tags := range allTags {
		inventory.TotalRecords++

		for _, tag := range tags {
			// Framework breakdown
			for _, fw := range tag.Frameworks {
				fwStr := string(fw)
				if reportType == "all" || strings.ToLower(fwStr) == strings.ToLower(reportType) {
					inventory.ByFramework[fwStr]++
				}
			}

			// Data class breakdown
			if tag.DataClass != "" {
				inventory.ByDataClass[string(tag.DataClass)]++
			}

			// Count folder vs key tags
			if strings.Contains(path, "/") && !strings.Contains(path, ":") {
				inventory.TaggedFolders++
			} else {
				inventory.TaggedKeys++
			}

			// Check retention expiration
			if tag.RetentionDays > 0 {
				expiresAt := tag.CreatedAt.AddDate(0, 0, tag.RetentionDays)
				daysRemaining := int(time.Until(expiresAt).Hours() / 24)

				// Alert if expiring within 30 days
				if daysRemaining <= 30 && daysRemaining >= 0 {
					alert := RetentionAlert{
						Path:          path,
						DataClass:     string(tag.DataClass),
						RetentionDays: tag.RetentionDays,
						ExpiresAt:     expiresAt,
						DaysRemaining: daysRemaining,
					}
					if len(tag.Frameworks) > 0 {
						alert.Framework = string(tag.Frameworks[0])
					}
					inventory.RetentionExpiring = append(inventory.RetentionExpiring, alert)
				}
			}
		}
	}

	return inventory, nil
}

// generateRecommendations creates actionable recommendations
func (rm *ReportingManager) generateRecommendations(
	summary *ComplianceSummary,
	violations *ViolationStats,
	inventory *DataInventorySummary,
) []string {
	recommendations := []string{}

	// Low compliance rate
	if summary.ComplianceRate < 90 {
		recommendations = append(recommendations,
			fmt.Sprintf("CRITICAL: Compliance rate is %.2f%%. Target 95%% or higher. Review access controls and training.", summary.ComplianceRate))
	}

	// High violation count
	if violations.Total > 10 {
		recommendations = append(recommendations,
			fmt.Sprintf("HIGH: %d violations detected. Review top violators and implement corrective actions.", violations.Total))
	}

	// Unresolved violations
	if violations.UnresolvedCount > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("HIGH: %d unresolved violations. Assign ownership and set resolution deadlines.", violations.UnresolvedCount))
	}

	// Low encryption usage
	encryptionRate := 0.0
	if summary.TotalOperations > 0 {
		encryptionRate = float64(summary.EncryptedOperations) / float64(summary.TotalOperations) * 100
	}
	if encryptionRate < 95 && summary.EncryptedOperations > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("MEDIUM: Only %.2f%% of operations use encryption. Enforce encryption for all restricted/confidential data.", encryptionRate))
	}

	// Low MFA usage
	mfaRate := 0.0
	if summary.TotalOperations > 0 {
		mfaRate = float64(summary.MFAVerifiedOperations) / float64(summary.TotalOperations) * 100
	}
	if mfaRate < 80 && summary.MFAVerifiedOperations > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("MEDIUM: Only %.2f%% of operations use MFA. Require MFA for sensitive data access.", mfaRate))
	}

	// Retention expiring
	if len(inventory.RetentionExpiring) > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("MEDIUM: %d records approaching retention limits. Review and take action (archive/delete).", len(inventory.RetentionExpiring)))
	}

	// Untagged records
	if inventory.UntaggedRecords > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("LOW: %d untagged records found. Implement data classification for all sensitive data.", inventory.UntaggedRecords))
	}

	// Critical violations
	if violations.BySeverity["critical"] > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("CRITICAL: %d critical violations detected. Immediate investigation required.", violations.BySeverity["critical"]))
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "✓ No critical issues detected. Continue monitoring compliance metrics.")
	}

	return recommendations
}

// ExportReport exports report in specified format
func (rm *ReportingManager) ExportReport(
	ctx context.Context,
	report *ComplianceReport,
	format string,
) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(report, "", "  ")
	case "csv":
		return rm.exportCSV(report)
	case "text":
		return rm.exportText(report)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// exportCSV exports report as CSV
func (rm *ReportingManager) exportCSV(report *ComplianceReport) ([]byte, error) {
	var sb strings.Builder

	// Header
	sb.WriteString("Compliance Report\n")
	sb.WriteString(fmt.Sprintf("Generated: %s\n", report.GeneratedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Type: %s\n", report.ReportType))
	sb.WriteString(fmt.Sprintf("Period: %s to %s\n\n",
		report.Period.StartDate.Format("2006-01-02"),
		report.Period.EndDate.Format("2006-01-02")))

	// Summary metrics
	sb.WriteString("Summary\n")
	sb.WriteString("Metric,Value\n")
	sb.WriteString(fmt.Sprintf("Total Operations,%d\n", report.Summary.TotalOperations))
	sb.WriteString(fmt.Sprintf("Allowed Operations,%d\n", report.Summary.AllowedOperations))
	sb.WriteString(fmt.Sprintf("Denied Operations,%d\n", report.Summary.DeniedOperations))
	sb.WriteString(fmt.Sprintf("Compliance Rate,%.2f%%\n", report.Summary.ComplianceRate))
	sb.WriteString("\n")

	// Violations
	sb.WriteString("Violations\n")
	sb.WriteString("Severity,Count\n")
	for severity, count := range report.ViolationStats.BySeverity {
		sb.WriteString(fmt.Sprintf("%s,%d\n", severity, count))
	}
	sb.WriteString("\n")

	// Recommendations
	sb.WriteString("Recommendations\n")
	for _, rec := range report.Recommendations {
		sb.WriteString(fmt.Sprintf("%s\n", rec))
	}

	return []byte(sb.String()), nil
}

// exportText exports report as formatted text
func (rm *ReportingManager) exportText(report *ComplianceReport) ([]byte, error) {
	var sb strings.Builder

	sb.WriteString("═══════════════════════════════════════════════════════════\n")
	sb.WriteString("              COMPLIANCE REPORT\n")
	sb.WriteString("═══════════════════════════════════════════════════════════\n\n")

	sb.WriteString(fmt.Sprintf("Report ID:   %s\n", report.ReportID))
	sb.WriteString(fmt.Sprintf("Generated:   %s\n", report.GeneratedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Report Type: %s\n", strings.ToUpper(report.ReportType)))
	sb.WriteString(fmt.Sprintf("Period:      %s to %s\n\n",
		report.Period.StartDate.Format("2006-01-02"),
		report.Period.EndDate.Format("2006-01-02")))

	sb.WriteString("───────────────────────────────────────────────────────────\n")
	sb.WriteString("COMPLIANCE SUMMARY\n")
	sb.WriteString("───────────────────────────────────────────────────────────\n\n")
	sb.WriteString(fmt.Sprintf("  Total Operations:     %d\n", report.Summary.TotalOperations))
	sb.WriteString(fmt.Sprintf("  ├─ Allowed:           %d\n", report.Summary.AllowedOperations))
	sb.WriteString(fmt.Sprintf("  └─ Denied:            %d\n", report.Summary.DeniedOperations))
	sb.WriteString(fmt.Sprintf("  Compliance Rate:      %.2f%%\n\n", report.Summary.ComplianceRate))

	if report.ViolationStats.Total > 0 {
		sb.WriteString("───────────────────────────────────────────────────────────\n")
		sb.WriteString("VIOLATIONS\n")
		sb.WriteString("───────────────────────────────────────────────────────────\n\n")
		sb.WriteString(fmt.Sprintf("  Total Violations:     %d\n", report.ViolationStats.Total))
		sb.WriteString(fmt.Sprintf("  Unresolved:           %d\n\n", report.ViolationStats.UnresolvedCount))
		sb.WriteString("  By Severity:\n")
		for severity, count := range report.ViolationStats.BySeverity {
			sb.WriteString(fmt.Sprintf("    ├─ %-12s: %d\n", severity, count))
		}
		sb.WriteString("\n")
	}

	if len(report.Recommendations) > 0 {
		sb.WriteString("───────────────────────────────────────────────────────────\n")
		sb.WriteString("RECOMMENDATIONS\n")
		sb.WriteString("───────────────────────────────────────────────────────────\n\n")
		for i, rec := range report.Recommendations {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, rec))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("═══════════════════════════════════════════════════════════\n")

	return []byte(sb.String()), nil
}

// ScheduleReport schedules periodic report generation
func (rm *ReportingManager) ScheduleReport(
	ctx context.Context,
	reportType string,
	frequency string, // daily, weekly, monthly
	recipient string,
) error {
	// This would implement scheduled reporting
	// For now, just store the schedule config
	config := map[string]interface{}{
		"report_type": reportType,
		"frequency":   frequency,
		"recipient":   recipient,
		"created_at":  time.Now(),
	}

	data, err := json.Marshal(config)
	if err != nil {
		return err
	}

	key := []byte(fmt.Sprintf("compliance:schedule:%s:%s", reportType, frequency))
	return rm.db.Put(key, data)
}
