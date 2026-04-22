package web

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/velocity"
)

// MetricsRenderer renders metrics in Prometheus exposition format.
type MetricsRenderer interface {
	RenderMetrics() (string, error)
}

// NotificationService manages bucket event notifications.
type NotificationService interface {
	PutBucketNotification(bucket string, config any) error
	GetBucketNotification(bucket string) (any, error)
	DeleteBucketNotification(bucket string) error
}

// LifecycleService manages bucket lifecycle rules.
type LifecycleService interface {
	PutBucketLifecycle(bucket string, config any) error
	GetBucketLifecycle(bucket string) (any, error)
	DeleteBucketLifecycle(bucket string) error
}

// EnterpriseAPI provides enterprise-grade HTTP endpoints for IAM, auth,
// STS, metrics, notifications, lifecycle, integrity, and cluster management.
type EnterpriseAPI struct {
	iam           *velocity.IAMPolicyEngine
	oidc          *velocity.OIDCProvider
	ldap          *velocity.LDAPProvider
	sts           *velocity.STSService
	metrics       MetricsRenderer
	notifications NotificationService
	lifecycle     LifecycleService
	integrity     *velocity.IntegrityManager
	cluster       *velocity.ClusterManager
}

// NewEnterpriseAPI creates a new EnterpriseAPI with all enterprise subsystems.
func NewEnterpriseAPI(
	iam *velocity.IAMPolicyEngine,
	oidc *velocity.OIDCProvider,
	ldap *velocity.LDAPProvider,
	sts *velocity.STSService,
	metrics MetricsRenderer,
	notifications NotificationService,
	lifecycle LifecycleService,
	integrity *velocity.IntegrityManager,
	cluster *velocity.ClusterManager,
) *EnterpriseAPI {
	return &EnterpriseAPI{
		iam:           iam,
		oidc:          oidc,
		ldap:          ldap,
		sts:           sts,
		metrics:       metrics,
		notifications: notifications,
		lifecycle:     lifecycle,
		integrity:     integrity,
		cluster:       cluster,
	}
}

// RegisterRoutes registers all enterprise API routes under /api/v1/.
func (e *EnterpriseAPI) RegisterRoutes(app *fiber.App) {
	v1 := app.Group("/api/v1")

	// IAM policy management
	v1.Post("/iam/policies", e.handleCreatePolicy)
	v1.Get("/iam/policies", e.handleListPolicies)
	v1.Get("/iam/policies/:name", e.handleGetPolicy)
	v1.Delete("/iam/policies/:name", e.handleDeletePolicy)
	v1.Post("/iam/attach", e.handleAttachPolicy)
	v1.Post("/iam/detach", e.handleDetachPolicy)
	v1.Post("/iam/evaluate", e.handleEvaluateAccess)

	// Auth - OIDC
	v1.Get("/auth/oidc/login", e.handleOIDCLogin)
	v1.Get("/auth/oidc/callback", e.handleOIDCCallback)

	// Auth - LDAP
	v1.Post("/auth/ldap/login", e.handleLDAPLogin)

	// STS - temporary credentials
	v1.Post("/sts/assume-role", e.handleAssumeRole)
	v1.Post("/sts/web-identity", e.handleAssumeRoleWithWebIdentity)

	// Metrics
	v1.Get("/metrics", e.handleMetrics)

	// Bucket-level notifications
	v1.Put("/buckets/:bucket/notifications", e.handlePutNotification)
	v1.Get("/buckets/:bucket/notifications", e.handleGetNotification)
	v1.Delete("/buckets/:bucket/notifications", e.handleDeleteNotification)

	// Bucket-level lifecycle
	v1.Put("/buckets/:bucket/lifecycle", e.handlePutLifecycle)
	v1.Get("/buckets/:bucket/lifecycle", e.handleGetLifecycle)
	v1.Delete("/buckets/:bucket/lifecycle", e.handleDeleteLifecycle)

	// Integrity
	v1.Get("/integrity/status", e.handleIntegrityStatus)
	v1.Get("/integrity/object", e.handleObjectIntegrity)

	// Cluster
	v1.Get("/cluster/status", e.handleClusterStatus)
	v1.Get("/cluster/nodes", e.handleClusterNodes)
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

func jsonOK(c fiber.Ctx, data any) error {
	return c.Status(fiber.StatusOK).JSON(data)
}

func jsonCreated(c fiber.Ctx, data any) error {
	return c.Status(fiber.StatusCreated).JSON(data)
}

func jsonError(c fiber.Ctx, status int, msg string) error {
	return c.Status(status).JSON(fiber.Map{"error": msg})
}

// ---------------------------------------------------------------------------
// IAM handlers
// ---------------------------------------------------------------------------

func (e *EnterpriseAPI) handleCreatePolicy(c fiber.Ctx) error {
	if e.iam == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "IAM engine not configured")
	}

	var policy velocity.IAMPolicy
	if err := c.Bind().Body(&policy); err != nil {
		return jsonError(c, fiber.StatusBadRequest, "invalid request body")
	}
	if policy.Name == "" {
		return jsonError(c, fiber.StatusBadRequest, "policy name is required")
	}

	if err := e.iam.CreatePolicy(&policy); err != nil {
		return jsonError(c, fiber.StatusInternalServerError, err.Error())
	}

	return jsonCreated(c, fiber.Map{
		"message": "policy created",
		"policy":  policy,
	})
}

func (e *EnterpriseAPI) handleGetPolicy(c fiber.Ctx) error {
	if e.iam == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "IAM engine not configured")
	}

	name := c.Params("name")
	if name == "" {
		return jsonError(c, fiber.StatusBadRequest, "policy name is required")
	}

	policy, err := e.iam.GetPolicy(name)
	if err != nil {
		return jsonError(c, fiber.StatusNotFound, err.Error())
	}

	return jsonOK(c, policy)
}

func (e *EnterpriseAPI) handleListPolicies(c fiber.Ctx) error {
	if e.iam == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "IAM engine not configured")
	}

	policies, err := e.iam.ListPolicies()
	if err != nil {
		return jsonError(c, fiber.StatusInternalServerError, err.Error())
	}

	return jsonOK(c, fiber.Map{
		"policies": policies,
		"count":    len(policies),
	})
}

func (e *EnterpriseAPI) handleDeletePolicy(c fiber.Ctx) error {
	if e.iam == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "IAM engine not configured")
	}

	name := c.Params("name")
	if name == "" {
		return jsonError(c, fiber.StatusBadRequest, "policy name is required")
	}

	if err := e.iam.DeletePolicy(name); err != nil {
		return jsonError(c, fiber.StatusInternalServerError, err.Error())
	}

	return jsonOK(c, fiber.Map{"message": "policy deleted"})
}

func (e *EnterpriseAPI) handleAttachPolicy(c fiber.Ctx) error {
	if e.iam == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "IAM engine not configured")
	}

	var req struct {
		Type       string `json:"type"`        // "user" or "group"
		ID         string `json:"id"`          // user ID or group ID
		PolicyName string `json:"policy_name"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return jsonError(c, fiber.StatusBadRequest, "invalid request body")
	}
	if req.ID == "" || req.PolicyName == "" {
		return jsonError(c, fiber.StatusBadRequest, "id and policy_name are required")
	}

	var err error
	switch req.Type {
	case "group":
		err = e.iam.AttachGroupPolicy(req.ID, req.PolicyName)
	default:
		err = e.iam.AttachUserPolicy(req.ID, req.PolicyName)
	}

	if err != nil {
		return jsonError(c, fiber.StatusInternalServerError, err.Error())
	}

	return jsonOK(c, fiber.Map{"message": "policy attached"})
}

func (e *EnterpriseAPI) handleDetachPolicy(c fiber.Ctx) error {
	if e.iam == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "IAM engine not configured")
	}

	var req struct {
		Type       string `json:"type"`
		ID         string `json:"id"`
		PolicyName string `json:"policy_name"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return jsonError(c, fiber.StatusBadRequest, "invalid request body")
	}
	if req.ID == "" || req.PolicyName == "" {
		return jsonError(c, fiber.StatusBadRequest, "id and policy_name are required")
	}

	var err error
	switch req.Type {
	case "group":
		err = e.iam.DetachGroupPolicy(req.ID, req.PolicyName)
	default:
		err = e.iam.DetachUserPolicy(req.ID, req.PolicyName)
	}

	if err != nil {
		return jsonError(c, fiber.StatusInternalServerError, err.Error())
	}

	return jsonOK(c, fiber.Map{"message": "policy detached"})
}

func (e *EnterpriseAPI) handleEvaluateAccess(c fiber.Ctx) error {
	if e.iam == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "IAM engine not configured")
	}

	var req velocity.IAMEvalRequest
	if err := c.Bind().Body(&req); err != nil {
		return jsonError(c, fiber.StatusBadRequest, "invalid request body")
	}
	if req.Principal == "" || req.Action == "" || req.Resource == "" {
		return jsonError(c, fiber.StatusBadRequest, "principal, action, and resource are required")
	}

	result := e.iam.EvaluateAccess(&req)
	return jsonOK(c, result)
}

// ---------------------------------------------------------------------------
// OIDC handlers
// ---------------------------------------------------------------------------

func (e *EnterpriseAPI) handleOIDCLogin(c fiber.Ctx) error {
	if e.oidc == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "OIDC provider not configured")
	}

	state, err := randomHex(16)
	if err != nil {
		return jsonError(c, fiber.StatusInternalServerError, "failed to generate state")
	}
	nonce, err := randomHex(16)
	if err != nil {
		return jsonError(c, fiber.StatusInternalServerError, "failed to generate nonce")
	}

	authURL, err := e.oidc.GetAuthorizationURL(state, nonce)
	if err != nil {
		return jsonError(c, fiber.StatusInternalServerError, err.Error())
	}

	return jsonOK(c, fiber.Map{
		"authorization_url": authURL,
		"state":             state,
		"nonce":             nonce,
	})
}

func (e *EnterpriseAPI) handleOIDCCallback(c fiber.Ctx) error {
	if e.oidc == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "OIDC provider not configured")
	}

	code := c.Query("code")
	if code == "" {
		return jsonError(c, fiber.StatusBadRequest, "authorization code is required")
	}

	// Check for error from the provider
	if errCode := c.Query("error"); errCode != "" {
		desc := c.Query("error_description", errCode)
		return jsonError(c, fiber.StatusBadRequest, "OIDC error: "+desc)
	}

	tokenResp, err := e.oidc.ExchangeCode(code)
	if err != nil {
		return jsonError(c, fiber.StatusBadGateway, err.Error())
	}

	claims, err := e.oidc.ValidateToken(tokenResp.IDToken)
	if err != nil {
		return jsonError(c, fiber.StatusUnauthorized, err.Error())
	}

	user := e.oidc.MapClaimsToUser(claims)

	return jsonOK(c, fiber.Map{
		"access_token": tokenResp.AccessToken,
		"id_token":     tokenResp.IDToken,
		"expires_in":   tokenResp.ExpiresIn,
		"user":         user,
	})
}

// ---------------------------------------------------------------------------
// LDAP handler
// ---------------------------------------------------------------------------

func (e *EnterpriseAPI) handleLDAPLogin(c fiber.Ctx) error {
	if e.ldap == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "LDAP provider not configured")
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return jsonError(c, fiber.StatusBadRequest, "invalid request body")
	}
	if req.Username == "" || req.Password == "" {
		return jsonError(c, fiber.StatusBadRequest, "username and password are required")
	}

	ldapUser, err := e.ldap.Authenticate(req.Username, req.Password)
	if err != nil {
		return jsonError(c, fiber.StatusUnauthorized, err.Error())
	}

	return jsonOK(c, fiber.Map{
		"message": "authentication successful",
		"user":    ldapUser,
	})
}

// ---------------------------------------------------------------------------
// STS handlers
// ---------------------------------------------------------------------------

func (e *EnterpriseAPI) handleAssumeRole(c fiber.Ctx) error {
	if e.sts == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "STS service not configured")
	}

	var req struct {
		UserID string                  `json:"user_id"`
		Input  velocity.AssumeRoleInput `json:"input"`
	}
	if err := c.Bind().Body(&req); err != nil {
		return jsonError(c, fiber.StatusBadRequest, "invalid request body")
	}
	if req.UserID == "" {
		return jsonError(c, fiber.StatusBadRequest, "user_id is required")
	}

	output, err := e.sts.AssumeRole(req.UserID, &req.Input)
	if err != nil {
		return jsonError(c, fiber.StatusBadRequest, err.Error())
	}

	return jsonOK(c, output)
}

func (e *EnterpriseAPI) handleAssumeRoleWithWebIdentity(c fiber.Ctx) error {
	if e.sts == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "STS service not configured")
	}

	var input velocity.AssumeRoleWithWebIdentityInput
	if err := c.Bind().Body(&input); err != nil {
		return jsonError(c, fiber.StatusBadRequest, "invalid request body")
	}
	if input.WebIdentityToken == "" {
		return jsonError(c, fiber.StatusBadRequest, "web_identity_token is required")
	}

	output, err := e.sts.AssumeRoleWithWebIdentity(&input)
	if err != nil {
		return jsonError(c, fiber.StatusBadRequest, err.Error())
	}

	return jsonOK(c, output)
}

// ---------------------------------------------------------------------------
// Metrics handler
// ---------------------------------------------------------------------------

func (e *EnterpriseAPI) handleMetrics(c fiber.Ctx) error {
	if e.metrics == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "metrics collector not configured")
	}

	output, err := e.metrics.RenderMetrics()
	if err != nil {
		return jsonError(c, fiber.StatusInternalServerError, err.Error())
	}

	c.Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	return c.Status(fiber.StatusOK).SendString(output)
}

// ---------------------------------------------------------------------------
// Notification handlers
// ---------------------------------------------------------------------------

func (e *EnterpriseAPI) handlePutNotification(c fiber.Ctx) error {
	if e.notifications == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "notification service not configured")
	}

	bucket := c.Params("bucket")
	if bucket == "" {
		return jsonError(c, fiber.StatusBadRequest, "bucket name is required")
	}

	var config any
	if err := c.Bind().Body(&config); err != nil {
		return jsonError(c, fiber.StatusBadRequest, "invalid request body")
	}

	if err := e.notifications.PutBucketNotification(bucket, config); err != nil {
		return jsonError(c, fiber.StatusInternalServerError, err.Error())
	}

	return jsonOK(c, fiber.Map{"message": "notification configuration saved", "bucket": bucket})
}

func (e *EnterpriseAPI) handleGetNotification(c fiber.Ctx) error {
	if e.notifications == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "notification service not configured")
	}

	bucket := c.Params("bucket")
	if bucket == "" {
		return jsonError(c, fiber.StatusBadRequest, "bucket name is required")
	}

	config, err := e.notifications.GetBucketNotification(bucket)
	if err != nil {
		return jsonError(c, fiber.StatusNotFound, err.Error())
	}

	return jsonOK(c, fiber.Map{"bucket": bucket, "notification_configuration": config})
}

func (e *EnterpriseAPI) handleDeleteNotification(c fiber.Ctx) error {
	if e.notifications == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "notification service not configured")
	}

	bucket := c.Params("bucket")
	if bucket == "" {
		return jsonError(c, fiber.StatusBadRequest, "bucket name is required")
	}

	if err := e.notifications.DeleteBucketNotification(bucket); err != nil {
		return jsonError(c, fiber.StatusInternalServerError, err.Error())
	}

	return jsonOK(c, fiber.Map{"message": "notification configuration deleted", "bucket": bucket})
}

// ---------------------------------------------------------------------------
// Lifecycle handlers
// ---------------------------------------------------------------------------

func (e *EnterpriseAPI) handlePutLifecycle(c fiber.Ctx) error {
	if e.lifecycle == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "lifecycle service not configured")
	}

	bucket := c.Params("bucket")
	if bucket == "" {
		return jsonError(c, fiber.StatusBadRequest, "bucket name is required")
	}

	var config any
	if err := c.Bind().Body(&config); err != nil {
		return jsonError(c, fiber.StatusBadRequest, "invalid request body")
	}

	if err := e.lifecycle.PutBucketLifecycle(bucket, config); err != nil {
		return jsonError(c, fiber.StatusInternalServerError, err.Error())
	}

	return jsonOK(c, fiber.Map{"message": "lifecycle configuration saved", "bucket": bucket})
}

func (e *EnterpriseAPI) handleGetLifecycle(c fiber.Ctx) error {
	if e.lifecycle == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "lifecycle service not configured")
	}

	bucket := c.Params("bucket")
	if bucket == "" {
		return jsonError(c, fiber.StatusBadRequest, "bucket name is required")
	}

	config, err := e.lifecycle.GetBucketLifecycle(bucket)
	if err != nil {
		return jsonError(c, fiber.StatusNotFound, err.Error())
	}

	return jsonOK(c, fiber.Map{"bucket": bucket, "lifecycle_configuration": config})
}

func (e *EnterpriseAPI) handleDeleteLifecycle(c fiber.Ctx) error {
	if e.lifecycle == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "lifecycle service not configured")
	}

	bucket := c.Params("bucket")
	if bucket == "" {
		return jsonError(c, fiber.StatusBadRequest, "bucket name is required")
	}

	if err := e.lifecycle.DeleteBucketLifecycle(bucket); err != nil {
		return jsonError(c, fiber.StatusInternalServerError, err.Error())
	}

	return jsonOK(c, fiber.Map{"message": "lifecycle configuration deleted", "bucket": bucket})
}

// ---------------------------------------------------------------------------
// Integrity handlers
// ---------------------------------------------------------------------------

func (e *EnterpriseAPI) handleIntegrityStatus(c fiber.Ctx) error {
	if e.integrity == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "integrity manager not configured")
	}

	status := e.integrity.Status()
	return jsonOK(c, status)
}

func (e *EnterpriseAPI) handleObjectIntegrity(c fiber.Ctx) error {
	if e.integrity == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "integrity manager not configured")
	}

	path := c.Query("path")
	if path == "" {
		return jsonError(c, fiber.StatusBadRequest, "path query parameter is required")
	}

	info, err := e.integrity.GetObjectIntegrity(path)
	if err != nil {
		return jsonError(c, fiber.StatusInternalServerError, err.Error())
	}

	return jsonOK(c, info)
}

// ---------------------------------------------------------------------------
// Cluster handlers
// ---------------------------------------------------------------------------

func (e *EnterpriseAPI) handleClusterStatus(c fiber.Ctx) error {
	if e.cluster == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "cluster manager not configured")
	}

	local := e.cluster.GetLocalNode()
	nodeCount := e.cluster.NodeCount()
	healthy := e.cluster.IsHealthy()

	return jsonOK(c, fiber.Map{
		"healthy":      healthy,
		"node_count":   nodeCount,
		"local_node":   local,
		"timestamp":    time.Now().UTC(),
	})
}

func (e *EnterpriseAPI) handleClusterNodes(c fiber.Ctx) error {
	if e.cluster == nil {
		return jsonError(c, fiber.StatusServiceUnavailable, "cluster manager not configured")
	}

	nodes := e.cluster.GetNodes()

	return jsonOK(c, fiber.Map{
		"nodes": nodes,
		"count": len(nodes),
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
