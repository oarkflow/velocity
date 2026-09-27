package api

import "context"

// NotificationRule describes one webhook subscription: deliver a POST to
// WebhookURL whenever an event on Topic is published, while Enabled.
type NotificationRule struct {
	ID         string
	Topic      string
	WebhookURL string
	Enabled    bool
}

// NotificationService is the surface plugins/notifications exposes,
// ported from v1's notifications.go (bucket-event webhook delivery with
// a worker pool and retry). Rules are persisted so they survive restarts;
// delivery itself happens by the plugin subscribing to the kernel event
// bus internally — this interface only covers rule management, not
// delivery, since delivery has no caller-facing surface.
type NotificationService interface {
	AddRule(ctx context.Context, r NotificationRule) error
	RemoveRule(ctx context.Context, id string) error
	ListRules(ctx context.Context) ([]NotificationRule, error)
}
