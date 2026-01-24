package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// LineageEvent tracks data lifecycle events.
type LineageEvent struct {
	EventID   string                 `json:"event_id"`
	Path      string                 `json:"path"`
	Action    string                 `json:"action"` // create, read, update, delete, move
	Actor     string                 `json:"actor"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// LineageManager manages lineage events.
type LineageManager struct {
	db *DB
}

// NewLineageManager creates a new lineage manager.
func NewLineageManager(db *DB) *LineageManager {
	return &LineageManager{db: db}
}

// RecordEvent records a lineage event.
func (lm *LineageManager) RecordEvent(ctx context.Context, event *LineageEvent) error {
	if event.EventID == "" {
		event.EventID = fmt.Sprintf("lineage:%d", time.Now().UnixNano())
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal lineage event: %w", err)
	}
	key := []byte(fmt.Sprintf("lineage:event:%s:%s", event.Path, event.EventID))
	return lm.db.Put(key, data)
}

// GetLineage returns lineage events for a path.
func (lm *LineageManager) GetLineage(ctx context.Context, path string) ([]LineageEvent, error) {
	keys, err := lm.db.Keys(fmt.Sprintf("lineage:event:%s:*", path))
	if err != nil {
		return nil, err
	}

	result := make([]LineageEvent, 0)
	for _, key := range keys {
		data, err := lm.db.Get([]byte(key))
		if err != nil {
			continue
		}
		var event LineageEvent
		if err := json.Unmarshal(data, &event); err != nil {
			continue
		}
		result = append(result, event)
	}

	return result, nil
}
