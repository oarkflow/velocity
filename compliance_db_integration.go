package velocity

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// SetComplianceTagManager overrides the default compliance tag manager.
func (db *DB) SetComplianceTagManager(ctm *ComplianceTagManager) {
	db.complianceTagManager = ctm
}

// ComplianceTagManager returns the configured compliance tag manager.
func (db *DB) ComplianceTagManager() *ComplianceTagManager {
	return db.complianceTagManager
}

// PutWithCompliance validates and writes data with compliance enforcement.
func (db *DB) PutWithCompliance(ctx context.Context, req *ComplianceOperationRequest, value []byte) error {
	if req == nil {
		return fmt.Errorf("compliance request required")
	}
	if req.Operation == "" {
		req.Operation = "write"
	}
	if req.Path == "" {
		return fmt.Errorf("path is required")
	}

	// Data classification enforcement on write + auto-tagging
	if db.classificationEngine != nil {
		if _, err := db.classifyAndTag(ctx, req.Path, value); err != nil {
			return err
		}
		if err := db.classificationEngine.EnforceDataPolicy(ctx, value, "write"); err != nil {
			return err
		}
	}

	if db.complianceTagManager != nil {
		result, err := db.complianceTagManager.ValidateOperation(ctx, req)
		if err != nil {
			return err
		}
		if !result.Allowed {
			return fmt.Errorf("compliance violation: %s", strings.Join(result.ViolatedRules, "; "))
		}
	}

	return db.Put([]byte(req.Path), value)
}

// GetWithCompliance validates and reads data with compliance enforcement and masking.
func (db *DB) GetWithCompliance(ctx context.Context, req *ComplianceOperationRequest) ([]byte, error) {
	if req == nil {
		return nil, fmt.Errorf("compliance request required")
	}
	if req.Operation == "" {
		req.Operation = "read"
	}
	if req.Path == "" {
		return nil, fmt.Errorf("path is required")
	}

	var result *ComplianceValidationResult
	if db.complianceTagManager != nil {
		var err error
		result, err = db.complianceTagManager.ValidateOperation(ctx, req)
		if err != nil {
			return nil, err
		}
		if !result.Allowed {
			return nil, fmt.Errorf("compliance violation: %s", strings.Join(result.ViolatedRules, "; "))
		}
	}

	data, err := db.Get([]byte(req.Path))
	if err != nil {
		return nil, err
	}

	// Apply masking if required
	if db.complianceTagManager != nil && result != nil && result.AppliedTag != nil {
		if db.complianceTagManager.maskingEngine != nil && result.AppliedTag.DataClass >= DataClassConfidential {
			masked := db.complianceTagManager.maskingEngine.MaskString(string(data), result.AppliedTag.DataClass)
			return []byte(masked), nil
		}
	}

	return data, nil
}

// DeleteWithCompliance validates and deletes data with compliance enforcement.
func (db *DB) DeleteWithCompliance(ctx context.Context, req *ComplianceOperationRequest) error {
	if req == nil {
		return fmt.Errorf("compliance request required")
	}
	if req.Operation == "" {
		req.Operation = "delete"
	}
	if req.Path == "" {
		return fmt.Errorf("path is required")
	}

	if db.complianceTagManager != nil {
		result, err := db.complianceTagManager.ValidateOperation(ctx, req)
		if err != nil {
			return err
		}
		if !result.Allowed {
			return fmt.Errorf("compliance violation: %s", strings.Join(result.ViolatedRules, "; "))
		}
	}

	return db.Delete([]byte(req.Path))
}

func (db *DB) classifyAndTag(ctx context.Context, path string, data []byte) (*ClassificationResult, error) {
	if db.classificationEngine == nil {
		return nil, nil
	}
	result, err := db.classificationEngine.ClassifyData(ctx, data)
	if err != nil {
		return nil, err
	}
	if db.complianceTagManager == nil {
		return result, nil
	}
	if existing := db.complianceTagManager.GetTag(path); existing != nil {
		return result, nil
	}

	frameworks := inferFrameworks(result)
	if len(frameworks) == 0 {
		return result, nil
	}

	tag := &ComplianceTag{
		Path:       path,
		Frameworks: frameworks,
		DataClass:  result.Classification,
		CreatedAt:  time.Now(),
		CreatedBy:  "auto-classifier",
	}
	_ = db.complianceTagManager.TagPath(ctx, tag)

	return result, nil
}

func inferFrameworks(result *ClassificationResult) []ComplianceFramework {
	if result == nil {
		return nil
	}
	frameworks := make([]ComplianceFramework, 0)
	seen := map[ComplianceFramework]struct{}{}
	for _, match := range result.Matches {
		switch strings.ToLower(match.Type) {
		case "phi":
			seen[FrameworkHIPAA] = struct{}{}
		case "pci":
			seen[FrameworkPCIDSS] = struct{}{}
		case "pii":
			seen[FrameworkGDPR] = struct{}{}
		}
	}
	for fw := range seen {
		frameworks = append(frameworks, fw)
	}
	return frameworks
}
