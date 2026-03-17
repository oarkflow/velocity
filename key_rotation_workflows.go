package velocity

import (
	"context"
	"fmt"
	"time"
)

// KeyRotationWorkflow provides high-level rotation operations.
type KeyRotationWorkflow struct {
	db        *DB
	auditMgr  *AuditLogManager
	classKeys *DataClassKeyManager
}

// NewKeyRotationWorkflow creates a new workflow.
func NewKeyRotationWorkflow(db *DB) *KeyRotationWorkflow {
	return &KeyRotationWorkflow{
		db:        db,
		auditMgr:  NewAuditLogManager(db),
		classKeys: NewDataClassKeyManager(db),
	}
}

// RotateMasterKey runs the master key rotation workflow.
func (krw *KeyRotationWorkflow) RotateMasterKey(ctx context.Context, policy KeyRotationPolicy) error {
	krm := NewKeyRotationManager(krw.db, policy)
	if err := krm.RotateKeys(ctx); err != nil {
		return err
	}
	if krw.auditMgr != nil {
		_ = krw.auditMgr.LogEvent(AuditEvent{
			Timestamp: time.Now(),
			Actor:     "key_rotation_system",
			Action:    "master_key_rotate",
			Resource:  "master_key",
			Result:    "success",
		})
	}
	return nil
}

// RotateClassKey rotates a data-class encryption key.
func (krw *KeyRotationWorkflow) RotateClassKey(ctx context.Context, class DataClassification) (int, error) {
	if krw.classKeys == nil {
		return 0, fmt.Errorf("class key manager not configured")
	}
	version, err := krw.classKeys.RotateKey(class)
	if err != nil {
		return 0, err
	}
	if krw.auditMgr != nil {
		_ = krw.auditMgr.LogEvent(AuditEvent{
			Timestamp: time.Now(),
			Actor:     "key_rotation_system",
			Action:    "data_class_key_rotate",
			Resource:  fmt.Sprintf("data_class:%s", class),
			Result:    "success",
		})
	}
	return version, nil
}