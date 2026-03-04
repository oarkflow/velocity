package authz

import (
	"context"

	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

type AuditAdapter struct {
	Engine *audit.Engine
}

func (a *AuditAdapter) Log(ctx context.Context, eventType, action string, actorID types.ID, success bool, details map[string]any) {
	if a == nil || a.Engine == nil {
		return
	}
	_ = a.Engine.Log(ctx, audit.AuditEventInput{
		Type:      eventType,
		Action:    action,
		ActorID:   actorID,
		ActorType: "identity",
		Success:   success,
		Details:   details,
	})
}
