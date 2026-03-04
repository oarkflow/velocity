package audit

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/types"
)

// SIEMFormat defines the output format for SIEM integration
type SIEMFormat string

const (
	SIEMFormatGELF    SIEMFormat = "gelf"    // Graylog Extended Log Format
	SIEMFormatSplunk  SIEMFormat = "splunk"  // Splunk HEC JSON
	SIEMFormatElastic SIEMFormat = "elastic" // Elastic ECS / Bulk JSON
	SIEMFormatCEF     SIEMFormat = "cef"     // Common Event Format (ArcSight)
)

// ExportEvent exports an audit event in the specified SIEM format
func ExportEvent(event *types.AuditEvent, format SIEMFormat) ([]byte, error) {
	switch format {
	case SIEMFormatGELF:
		return formatGELF(event)
	case SIEMFormatSplunk:
		return formatSplunk(event)
	case SIEMFormatElastic:
		return formatElastic(event)
	case SIEMFormatCEF:
		return formatCEF(event)
	default:
		return nil, fmt.Errorf("audit: unsupported SIEM format %s", format)
	}
}

// formatGELF formats event as Graylog GELF JSON
func formatGELF(e *types.AuditEvent) ([]byte, error) {
	// timestamp in GELF is seconds (float)
	ts := float64(e.Timestamp) / 1e9

	gelf := map[string]interface{}{
		"version":       "1.1",
		"host":          "secretr",
		"short_message": fmt.Sprintf("[%s] %s %s", e.Type, e.Action, e.ResourceType),
		"full_message":  string(e.Hash), // Use hash as signature/full message? Or details?
		"timestamp":     ts,
		"level":         1, // Alert level
		"_actor_id":     e.ActorID,
		"_action":       e.Action,
		"_resource_id":  e.ResourceID,
		"_ip_address":   e.IPAddress,
		"_session_id":   e.SessionID,
	}

	for k, v := range e.Details {
		gelf["_"+k] = v
	}

	return json.Marshal(gelf)
}

// formatSplunk formats event as Splunk HEC event
func formatSplunk(e *types.AuditEvent) ([]byte, error) {
	splunk := map[string]interface{}{
		"time":       e.Timestamp / 1e9,
		"host":       "secretr",
		"source":     "secretr-audit",
		"sourcetype": "json",
		"event":      e,
	}
	return json.Marshal(splunk)
}

// formatElastic formats event for Elasticsearch
func formatElastic(e *types.AuditEvent) ([]byte, error) {
	// Elastic ECS mapping could be more complex, but dumping raw event is often enough
	elastic := map[string]interface{}{
		"@timestamp":     time.Unix(0, int64(e.Timestamp)).Format(time.RFC3339),
		"event.kind":     "event",
		"event.category": "iam",
		"event.type":     e.Type,
		"event.action":   e.Action,
		"user.id":        e.ActorID,
		"source.ip":      e.IPAddress,
		"secretr":        e,
	}
	return json.Marshal(elastic)
}

// formatCEF formats event as Common Event Format string (not JSON)
func formatCEF(e *types.AuditEvent) ([]byte, error) {
	// CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
	cef := fmt.Sprintf("CEF:0|Oarkflow|Secretr|2.0|%s|%s|5|actorId=%s src=%s",
		e.Type, e.Action, e.ActorID, e.IPAddress)
	return []byte(cef), nil
}
