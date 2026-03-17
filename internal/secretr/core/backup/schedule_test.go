package backup

import (
	"context"
	"testing"

	"github.com/oarkflow/velocity/internal/secretr/storage"
)

func TestCreateAndListSchedule(t *testing.T) {
	store, err := storage.NewStore(storage.Config{
		Path:          t.TempDir(),
		EncryptionKey: []byte("01234567890123456789012345678901"),
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	m := NewManager(ManagerConfig{Store: store})
	ctx := context.Background()

	s, err := m.CreateSchedule(ctx, CreateScheduleOptions{
		OrgID:         "org-test",
		Type:          "full",
		CronExpr:      "0 * * * *",
		Destination:   "/tmp/backups",
		RetentionDays: 14,
		CreatorID:     "user-1",
	})
	if err != nil {
		t.Fatalf("create schedule: %v", err)
	}
	if s.Destination != "/tmp/backups" {
		t.Fatalf("destination mismatch: %q", s.Destination)
	}

	list, err := m.ListSchedules(ctx, "org-test")
	if err != nil {
		t.Fatalf("list schedules: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 schedule, got %d", len(list))
	}
	if list[0].CronExpr != "0 * * * *" {
		t.Fatalf("cron mismatch: %q", list[0].CronExpr)
	}
}
