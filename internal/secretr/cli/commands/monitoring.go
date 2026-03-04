package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	client "github.com/oarkflow/velocity/internal/secretr/cli"
	"github.com/oarkflow/velocity/internal/secretr/core/alerts"
	"github.com/oarkflow/velocity/internal/secretr/core/monitoring"
	"github.com/oarkflow/velocity/internal/secretr/types"
	"github.com/urfave/cli/v3"
)

// Monitoring commands

func MonitoringDashboard(ctx context.Context, cmd *cli.Command) error {
	orgID, err := GetOrgID(ctx, cmd)
	if err != nil {
		return err
	}
	period := cmd.String("period")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireSession(); err != nil {
		return err
	}

	m := NewMonitoringCommands(c.Monitoring)
	return m.GetDashboard(string(orgID), period)
}

func MonitoringEvents(ctx context.Context, cmd *cli.Command) error {
	eventType := cmd.String("type")
	actorID := cmd.String("actor")
	limit := int(cmd.Int("limit"))

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireSession(); err != nil {
		return err
	}

	m := NewMonitoringCommands(c.Monitoring)
	return m.QueryEvents(eventType, actorID, limit)
}

// Alert commands

func AlertList(ctx context.Context, cmd *cli.Command) error {
	status := cmd.String("status")
	severity := cmd.String("severity")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireSession(); err != nil {
		return err
	}

	a := NewAlertCommands(c.Alerts)
	return a.ListAlerts(status, severity)
}

func AlertRules(ctx context.Context, cmd *cli.Command) error {
	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireSession(); err != nil {
		return err
	}

	a := NewAlertCommands(c.Alerts)
	return a.ListRules()
}

func AlertAcknowledge(ctx context.Context, cmd *cli.Command) error {
	alertID := cmd.String("id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireSession(); err != nil {
		return err
	}

	session := c.CurrentSession()
	a := NewAlertCommands(c.Alerts)
	return a.AcknowledgeAlert(alertID, string(session.IdentityID))
}

func AlertResolve(ctx context.Context, cmd *cli.Command) error {
	alertID := cmd.String("id")

	c, err := client.GetClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RequireSession(); err != nil {
		return err
	}

	session := c.CurrentSession()
	a := NewAlertCommands(c.Alerts)
	return a.ResolveAlert(alertID, string(session.IdentityID))
}

// MonitoringCommands provides CLI commands for monitoring features
type MonitoringCommands struct {
	engine *monitoring.Engine
}

// NewMonitoringCommands creates a new MonitoringCommands instance
func NewMonitoringCommands(engine *monitoring.Engine) *MonitoringCommands {
	return &MonitoringCommands{engine: engine}
}

// GetDashboard displays dashboard data
func (m *MonitoringCommands) GetDashboard(orgID string, period string) error {
	ctx := context.Background()

	var periodDuration time.Duration
	switch period {
	case "1h":
		periodDuration = time.Hour
	case "24h":
		periodDuration = 24 * time.Hour
	case "7d":
		periodDuration = 7 * 24 * time.Hour
	case "30d":
		periodDuration = 30 * 24 * time.Hour
	default:
		periodDuration = 7 * 24 * time.Hour
	}

	data, err := m.engine.GetDashboardData(ctx, types.ID(orgID), monitoring.DashboardOptions{
		Period: &periodDuration,
	})
	if err != nil {
		return fmt.Errorf("failed to get dashboard data: %w", err)
	}

	fmt.Println("\n=== Monitoring Dashboard ===")
	fmt.Printf("Period: Last %s\n", period)
	fmt.Printf("Generated: %s\n", data.GeneratedAt.Format(time.RFC3339))
	fmt.Println(strings.Repeat("-", 50))

	fmt.Printf("\nTotal Events: %d\n", data.TotalEvents)

	fmt.Println("\nEvents by Type:")
	for t, count := range data.EventCounts {
		fmt.Printf("  %-15s %d\n", t, count)
	}

	fmt.Println("\nEvents by Severity:")
	for s, count := range data.SeverityCounts {
		fmt.Printf("  %-15s %d\n", s, count)
	}

	fmt.Println("\nTop Actors:")
	for i, actor := range data.TopActors {
		if i >= 5 {
			break
		}
		fmt.Printf("  %d. %s (%d actions)\n", i+1, actor.ActorID, actor.ActionCount)
	}

	fmt.Println("\nHourly Distribution:")
	maxCount := 0
	for _, c := range data.HourlyDistribution {
		if c > maxCount {
			maxCount = c
		}
	}
	for hour, count := range data.HourlyDistribution {
		bar := ""
		if maxCount > 0 {
			barLen := (count * 20) / maxCount
			bar = strings.Repeat("█", barLen)
		}
		fmt.Printf("  %02d:00 %s %d\n", hour, bar, count)
	}

	return nil
}

// QueryEvents queries monitoring events
func (m *MonitoringCommands) QueryEvents(eventType string, actorID string, limit int) error {
	ctx := context.Background()

	opts := monitoring.QueryOptions{
		Limit: limit,
	}

	if eventType != "" {
		opts.Types = []monitoring.EventType{monitoring.EventType(eventType)}
	}
	if actorID != "" {
		opts.ActorID = types.ID(actorID)
	}

	events, err := m.engine.Query(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to query events: %w", err)
	}

	if len(events) == 0 {
		fmt.Println("No events found.")
		return nil
	}

	fmt.Println("Monitoring Events:")
	fmt.Println(strings.Repeat("-", 100))
	fmt.Printf("%-20s %-12s %-10s %-20s %s\n", "Timestamp", "Type", "Severity", "Actor", "Action")
	fmt.Println(strings.Repeat("-", 100))

	for _, e := range events {
		fmt.Printf("%-20s %-12s %-10s %-20s %s\n",
			e.Timestamp.Format("2006-01-02 15:04:05"),
			e.Type,
			e.Severity,
			e.ActorID,
			e.Action)
	}

	return nil
}

// GetBehaviorAnalysis displays user behavior analysis
func (m *MonitoringCommands) GetBehaviorAnalysis(identityID string) error {
	ctx := context.Background()

	analysis, err := m.engine.GetUserBehaviorAnalysis(ctx, types.ID(identityID))
	if err != nil {
		return fmt.Errorf("failed to get behavior analysis: %w", err)
	}

	fmt.Printf("\n=== Behavior Analysis for %s ===\n", identityID)
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("Total Events: %d\n", analysis.EventCount)
	fmt.Printf("First Activity: %s\n", analysis.FirstActivity.Format(time.RFC3339))
	fmt.Printf("Last Activity: %s\n", analysis.LastActivity.Format(time.RFC3339))
	fmt.Printf("Avg Daily Activity: %.1f\n", analysis.AvgDailyActivity)
	fmt.Printf("Unique Resources: %d\n", analysis.UniqueResourcesAccessed)

	fmt.Println("\nAction Breakdown:")
	for action, count := range analysis.ActionBreakdown {
		fmt.Printf("  %-20s %d\n", action, count)
	}

	if len(analysis.Anomalies) > 0 {
		fmt.Println("\n⚠ Anomalies Detected:")
		for _, a := range analysis.Anomalies {
			fmt.Printf("  • %s\n", a)
		}
	}

	return nil
}

// ExportEvents exports events to a file
func (m *MonitoringCommands) ExportEvents(output string, period string) error {
	ctx := context.Background()

	var periodDuration time.Duration
	switch period {
	case "1h":
		periodDuration = time.Hour
	case "24h":
		periodDuration = 24 * time.Hour
	case "7d":
		periodDuration = 7 * 24 * time.Hour
	default:
		periodDuration = 24 * time.Hour
	}

	data, err := m.engine.ExportEvents(ctx, monitoring.QueryOptions{
		StartTime: time.Now().Add(-periodDuration),
	})
	if err != nil {
		return fmt.Errorf("failed to export events: %w", err)
	}

	if err := os.WriteFile(output, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("Events exported to: %s\n", output)
	return nil
}

// AlertCommands provides CLI commands for alerting features
type AlertCommands struct {
	engine *alerts.Engine
}

// NewAlertCommands creates a new AlertCommands instance
func NewAlertCommands(engine *alerts.Engine) *AlertCommands {
	return &AlertCommands{engine: engine}
}

// ListRules lists all alert rules
func (a *AlertCommands) ListRules() error {
	ctx := context.Background()

	rules, err := a.engine.ListRules(ctx)
	if err != nil {
		return fmt.Errorf("failed to list rules: %w", err)
	}

	if len(rules) == 0 {
		fmt.Println("No alert rules found.")
		return nil
	}

	fmt.Println("Alert Rules:")
	fmt.Println(strings.Repeat("-", 90))
	fmt.Printf("%-36s %-25s %-10s %-10s\n", "ID", "Name", "Severity", "Enabled")
	fmt.Println(strings.Repeat("-", 90))

	for _, r := range rules {
		enabled := "no"
		if r.Enabled {
			enabled = "yes"
		}
		fmt.Printf("%-36s %-25s %-10s %-10s\n", r.ID, r.Name, r.Severity, enabled)
	}

	return nil
}

// CreateRule creates a new alert rule
func (a *AlertCommands) CreateRule(name, description, severity string, eventTypes []string, threshold float64) error {
	ctx := context.Background()

	rule := &alerts.Rule{
		Name:        name,
		Description: description,
		Severity:    alerts.AlertSeverity(severity),
		Condition: alerts.Condition{
			Type:       alerts.ConditionTypeThreshold,
			EventTypes: eventTypes,
			Threshold:  threshold,
			Operator:   ">=",
			Field:      "risk_score",
		},
		Actions: []alerts.Action{
			{Type: "webhook"},
		},
		Cooldown: 5 * time.Minute,
	}

	if err := a.engine.CreateRule(ctx, rule); err != nil {
		return fmt.Errorf("failed to create rule: %w", err)
	}

	fmt.Printf("Created alert rule: %s (ID: %s)\n", rule.Name, rule.ID)
	return nil
}

// DeleteRule deletes an alert rule
func (a *AlertCommands) DeleteRule(ruleID string) error {
	ctx := context.Background()

	if err := a.engine.DeleteRule(ctx, types.ID(ruleID)); err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	fmt.Printf("Deleted rule: %s\n", ruleID)
	return nil
}

// ListAlerts lists alerts
func (a *AlertCommands) ListAlerts(status, severity string) error {
	ctx := context.Background()

	opts := alerts.ListAlertsOptions{}
	if status != "" {
		opts.Status = alerts.AlertStatus(status)
	}
	if severity != "" {
		opts.Severity = alerts.AlertSeverity(severity)
	}

	alertList, err := a.engine.ListAlerts(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to list alerts: %w", err)
	}

	if len(alertList) == 0 {
		fmt.Println("No alerts found.")
		return nil
	}

	fmt.Println("Alerts:")
	fmt.Println(strings.Repeat("-", 100))
	fmt.Printf("%-36s %-25s %-10s %-12s %s\n", "ID", "Rule", "Severity", "Status", "Triggered")
	fmt.Println(strings.Repeat("-", 100))

	for _, alert := range alertList {
		fmt.Printf("%-36s %-25s %-10s %-12s %s\n",
			alert.ID, alert.RuleName, alert.Severity, alert.Status,
			alert.TriggeredAt.Format("2006-01-02 15:04"))
	}

	return nil
}

// AcknowledgeAlert acknowledges an alert
func (a *AlertCommands) AcknowledgeAlert(alertID, actorID string) error {
	ctx := context.Background()

	if err := a.engine.AcknowledgeAlert(ctx, types.ID(alertID), types.ID(actorID)); err != nil {
		return fmt.Errorf("failed to acknowledge alert: %w", err)
	}

	fmt.Printf("Acknowledged alert: %s\n", alertID)
	return nil
}

// ResolveAlert resolves an alert
func (a *AlertCommands) ResolveAlert(alertID, actorID string) error {
	ctx := context.Background()

	if err := a.engine.ResolveAlert(ctx, types.ID(alertID), types.ID(actorID)); err != nil {
		return fmt.Errorf("failed to resolve alert: %w", err)
	}

	fmt.Printf("Resolved alert: %s\n", alertID)
	return nil
}

// GetAlertDetails displays alert details
func (a *AlertCommands) GetAlertDetails(alertID string) error {
	ctx := context.Background()

	alert, err := a.engine.GetAlert(ctx, types.ID(alertID))
	if err != nil {
		return fmt.Errorf("failed to get alert: %w", err)
	}

	fmt.Printf("\n=== Alert Details ===\n")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("ID: %s\n", alert.ID)
	fmt.Printf("Title: %s\n", alert.Title)
	fmt.Printf("Rule: %s\n", alert.RuleName)
	fmt.Printf("Severity: %s\n", alert.Severity)
	fmt.Printf("Status: %s\n", alert.Status)
	fmt.Printf("Source: %s\n", alert.Source)
	fmt.Printf("Triggered: %s\n", alert.TriggeredAt.Format(time.RFC3339))

	if alert.AcknowledgedAt != nil {
		fmt.Printf("Acknowledged: %s by %s\n", alert.AcknowledgedAt.Format(time.RFC3339), alert.AcknowledgedBy)
	}

	if alert.ResolvedAt != nil {
		fmt.Printf("Resolved: %s by %s\n", alert.ResolvedAt.Format(time.RFC3339), alert.ResolvedBy)
	}

	fmt.Printf("\nDescription:\n%s\n", alert.Description)

	if alert.Details != nil {
		fmt.Println("\nDetails:")
		details, _ := json.MarshalIndent(alert.Details, "  ", "  ")
		fmt.Printf("  %s\n", string(details))
	}

	return nil
}

// ListNotifiers lists all notifiers
func (a *AlertCommands) ListNotifiers() error {
	ctx := context.Background()

	notifiers, err := a.engine.ListNotifiers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list notifiers: %w", err)
	}

	if len(notifiers) == 0 {
		fmt.Println("No notifiers configured.")
		return nil
	}

	fmt.Println("Notifiers:")
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("%-36s %-20s %-10s %-10s\n", "ID", "Name", "Type", "Status")
	fmt.Println(strings.Repeat("-", 70))

	for _, n := range notifiers {
		status := "disabled"
		if n.Enabled {
			status = "enabled"
		}
		fmt.Printf("%-36s %-20s %-10s %-10s\n", n.ID, n.Name, n.Type, status)
	}

	return nil
}

// CreateWebhookNotifier creates a webhook notifier
func (a *AlertCommands) CreateWebhookNotifier(name, url string) error {
	ctx := context.Background()

	notifier := &alerts.Notifier{
		Name: name,
		Type: "webhook",
		Config: alerts.NotifierConfig{
			WebhookURL:    url,
			WebhookMethod: "POST",
		},
	}

	if err := a.engine.CreateNotifier(ctx, notifier); err != nil {
		return fmt.Errorf("failed to create notifier: %w", err)
	}

	fmt.Printf("Created webhook notifier: %s (ID: %s)\n", notifier.Name, notifier.ID)
	return nil
}

// CreateSlackNotifier creates a Slack notifier
func (a *AlertCommands) CreateSlackNotifier(name, webhookURL, channel string) error {
	ctx := context.Background()

	notifier := &alerts.Notifier{
		Name: name,
		Type: "slack",
		Config: alerts.NotifierConfig{
			SlackWebhookURL: webhookURL,
			SlackChannel:    channel,
		},
	}

	if err := a.engine.CreateNotifier(ctx, notifier); err != nil {
		return fmt.Errorf("failed to create notifier: %w", err)
	}

	fmt.Printf("Created Slack notifier: %s (ID: %s)\n", notifier.Name, notifier.ID)
	return nil
}

// TestNotifier tests a notifier
func (a *AlertCommands) TestNotifier(notifierID string) error {
	ctx := context.Background()

	if err := a.engine.TestNotifier(ctx, types.ID(notifierID)); err != nil {
		return fmt.Errorf("failed to test notifier: %w", err)
	}

	fmt.Printf("Test notification sent successfully.\n")
	return nil
}

// GetActiveAlertCount displays the count of active alerts
func (a *AlertCommands) GetActiveAlertCount(orgID types.ID) error {
	ctx := context.Background()

	count, err := a.engine.GetActiveAlertCount(ctx, orgID)
	if err != nil {
		return fmt.Errorf("failed to get alert count: %w", err)
	}

	fmt.Printf("Active alerts: %d\n", count)
	return nil
}
