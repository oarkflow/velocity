package web

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/compliance"
)

func (s *HTTPServer) handleSystemHealth(c fiber.Ctx) error {
	health := fiber.Map{
		"status":    "ok",
		"time":      time.Now().UTC(),
		"role":      c.Locals("role"),
		"username":  c.Locals("username"),
		"kg":        fiber.Map{"available": s.db != nil && s.db.KnowledgeGraph() != nil},
		"object_io": fiber.Map{"available": s.db != nil},
	}
	if s.db != nil && s.db.KnowledgeGraph() != nil {
		health["kg"] = fiber.Map{
			"available": true,
			"analytics": s.db.KnowledgeGraph().GetAnalytics(),
			"sync":      s.db.KnowledgeGraphSyncStatus(),
		}
	}
	return c.JSON(health)
}

func (s *HTTPServer) handleComplianceListTags(c fiber.Ctx) error {
	manager := s.db.ComplianceTagManager()
	if manager == nil {
		return c.JSON(fiber.Map{"tags": []velocity.ComplianceTag{}, "count": 0})
	}

	tags := manager.GetAllTags()
	if framework := strings.TrimSpace(c.Query("framework")); framework != "" {
		tags = manager.ListTagsByFramework(compliance.Framework(strings.ToUpper(framework)))
	}

	return c.JSON(fiber.Map{"tags": tags, "count": len(tags)})
}

func (s *HTTPServer) handleComplianceGetTagsForResource(c fiber.Ctx) error {
	manager := s.db.ComplianceTagManager()
	if manager == nil {
		return c.JSON(fiber.Map{"tags": []velocity.ComplianceTag{}, "count": 0})
	}

	resource := strings.TrimSpace(c.Params("*"))
	if decoded, err := url.PathUnescape(resource); err == nil {
		resource = decoded
	}
	tags := manager.GetTags(resource)
	return c.JSON(fiber.Map{"resource": resource, "tags": tags, "count": len(tags)})
}

func (s *HTTPServer) handleComplianceCreateTag(c fiber.Ctx) error {
	var tag velocity.ComplianceTag
	if err := c.Bind().Body(&tag); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON"})
	}
	if tag.Path == "" && tag.ResourceRef == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "path or resource_ref is required"})
	}
	if len(tag.Frameworks) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "at least one framework is required"})
	}
	if tag.CreatedBy == "" {
		tag.CreatedBy = usernameFromContext(c)
	}

	manager := s.db.ComplianceTagManager()
	if manager == nil {
		manager = velocity.NewComplianceTagManager(s.db)
		s.db.SetComplianceTagManager(manager)
	}
	if tag.ResourceRef != nil {
		if err := manager.TagResource(c.Context(), *tag.ResourceRef, &tag); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
	} else if err := manager.TagPath(c.Context(), &tag); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(tag)
}

func (s *HTTPServer) handleComplianceAuditTrail(c fiber.Ctx) error {
	start, err := parseOptionalTime(c.Query("start", ""))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid start time"})
	}
	end, err := parseOptionalTime(c.Query("end", ""))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid end time"})
	}

	records, err := s.db.GetAuditTrail(start, end, c.Query("operation", ""))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	limit, _ := strconv.Atoi(c.Query("limit", "100"))
	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}
	return c.JSON(fiber.Map{"records": records, "count": len(records)})
}

func (s *HTTPServer) handleComplianceListRetentionPolicies(c fiber.Ctx) error {
	manager := velocity.NewRetentionManager(s.db)
	policies, err := manager.ListPolicies(c.Context())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"policies": policies, "count": len(policies)})
}

func (s *HTTPServer) handleComplianceCreateRetentionPolicy(c fiber.Ctx) error {
	var req struct {
		PolicyID        string               `json:"policy_id"`
		DataType        string               `json:"data_type"`
		RetentionPeriod flexibleDuration     `json:"retention_period"`
		RetentionDays   int                  `json:"retention_days"`
		LegalHolds      []velocity.LegalHold `json:"legal_holds"`
		DeletionMethod  string               `json:"deletion_method"`
		ReviewInterval  flexibleDuration     `json:"review_interval"`
		LastReview      time.Time            `json:"last_review"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON"})
	}
	period := time.Duration(req.RetentionPeriod)
	if period == 0 && req.RetentionDays > 0 {
		period = time.Duration(req.RetentionDays) * 24 * time.Hour
	}
	if req.DataType == "" || period == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "data_type and retention_period are required"})
	}

	policy := velocity.RetentionPolicy{
		PolicyID:        req.PolicyID,
		DataType:        req.DataType,
		RetentionPeriod: period,
		LegalHolds:      req.LegalHolds,
		DeletionMethod:  req.DeletionMethod,
		ReviewInterval:  time.Duration(req.ReviewInterval),
		LastReview:      req.LastReview,
	}
	if policy.DeletionMethod == "" {
		policy.DeletionMethod = "secure_erase"
	}
	if err := velocity.NewRetentionManager(s.db).AddPolicy(c.Context(), policy); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(policy)
}

func (s *HTTPServer) handleComplianceAddLegalHold(c fiber.Ctx) error {
	var hold velocity.LegalHold
	if err := c.Bind().Body(&hold); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON"})
	}
	if hold.Reason == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "reason is required"})
	}
	if hold.PlacedBy == "" {
		hold.PlacedBy = usernameFromContext(c)
	}
	if err := velocity.NewRetentionManager(s.db).AddLegalHold(c.Context(), c.Params("id"), hold); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"status": "created"})
}

func (s *HTTPServer) handleComplianceReleaseLegalHold(c fiber.Ctx) error {
	if err := velocity.NewRetentionManager(s.db).ReleaseLegalHold(c.Context(), c.Params("id"), c.Params("hold_id")); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"status": "released"})
}

func parseOptionalTime(raw string) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", raw)
}

type flexibleDuration time.Duration

func (d *flexibleDuration) UnmarshalJSON(data []byte) error {
	raw := strings.Trim(string(data), `"`)
	if raw == "" || raw == "null" {
		*d = 0
		return nil
	}
	if value, err := strconv.ParseInt(raw, 10, 64); err == nil {
		*d = flexibleDuration(time.Duration(value))
		return nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return err
	}
	*d = flexibleDuration(parsed)
	return nil
}
