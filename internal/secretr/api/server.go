// Package api provides the REST API server.
package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/authz"
	"github.com/oarkflow/velocity/internal/secretr/core/access"
	"github.com/oarkflow/velocity/internal/secretr/core/alerts"
	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/core/cicd"
	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/core/files"
	"github.com/oarkflow/velocity/internal/secretr/core/identity"
	"github.com/oarkflow/velocity/internal/secretr/core/monitoring"
	"github.com/oarkflow/velocity/internal/secretr/core/policy"
	"github.com/oarkflow/velocity/internal/secretr/core/secrets"
	"github.com/oarkflow/velocity/internal/secretr/core/share"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrUnauthorized = errors.New("api: unauthorized")
	ErrForbidden    = errors.New("api: forbidden")
	ErrNotFound     = errors.New("api: not found")
	ErrRateLimited  = errors.New("api: rate limited")
	ErrInvalidInput = errors.New("api: invalid input")
)

// Server provides the REST API
type Server struct {
	identity    *identity.Manager
	secrets     *secrets.Vault
	audit       *audit.Engine
	cicd        *cicd.Manager
	files       *files.Vault
	crypto      *crypto.Engine
	mux         *http.ServeMux
	server      *http.Server
	rateLimiter *RateLimiter
	monitoring  *monitoring.Engine
	alerts      *alerts.Engine
	access      *access.Manager
	policy      *policy.Engine
	share       *share.Manager
	authorizer  *authz.Authorizer
	resolver    authz.ResourceResolver
	routeSpecs  []authz.APIRouteAuthSpec
	routeSet    []RouteMethod
	mu          sync.RWMutex
	certFile    string
	keyFile     string
}

// ServeHTTP allows in-process testing without binding a TCP port.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// Config configures the API server
type Config struct {
	Address          string
	IdentityMgr      *identity.Manager
	SecretVault      *secrets.Vault
	FileVault        *files.Vault
	AuditEngine      *audit.Engine
	CICDManager      *cicd.Manager
	MonitoringEngine *monitoring.Engine
	AlertEngine      *alerts.Engine
	AccessManager    *access.Manager
	PolicyEngine     *policy.Engine
	ShareManager     *share.Manager
	PolicyChecker    authz.PolicyChecker
	Entitlements     authz.EntitlementProvider
	UsageCounter     authz.UsageCounter
	ResourceResolver authz.ResourceResolver
	RateLimitRPS     int
	RateLimitBurst   int
	CertFile         string
	KeyFile          string
}

// NewServer creates a new API server
func NewServer(cfg Config) *Server {
	s := &Server{
		identity:    cfg.IdentityMgr,
		secrets:     cfg.SecretVault,
		files:       cfg.FileVault,
		audit:       cfg.AuditEngine,
		cicd:        cfg.CICDManager,
		monitoring:  cfg.MonitoringEngine,
		alerts:      cfg.AlertEngine,
		access:      cfg.AccessManager,
		policy:      cfg.PolicyEngine,
		share:       cfg.ShareManager,
		crypto:      crypto.NewEngine(""),
		mux:         http.NewServeMux(),
		rateLimiter: NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst),
		certFile:    cfg.CertFile,
		keyFile:     cfg.KeyFile,
		resolver:    cfg.ResourceResolver,
	}
	if s.resolver == nil {
		s.resolver = authz.NewDefaultResourceResolver()
	}
	entProvider := cfg.Entitlements
	if entProvider == nil {
		entProvider = authz.NewEnvEntitlementProvider()
	}
	s.authorizer = authz.NewAuthorizerWithCounter(entProvider, s.access, &authz.AuditAdapter{Engine: s.audit}, cfg.UsageCounter)
	s.authorizer.SetPolicyChecker(cfg.PolicyChecker)

	s.setupRoutes()

	s.server = &http.Server{
		Addr:         cfg.Address,
		Handler:      s.mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// setupRoutes configures API routes
func (s *Server) setupRoutes() {
	addSpec := func(method, pattern string, scopes []types.Scope, resourceType string, requireACL, allowUnauth bool) {
		s.routeSpecs = append(s.routeSpecs, authz.APIRouteAuthSpec{
			Method:         method,
			Pattern:        pattern,
			RequiredScopes: scopes,
			ResourceType:   resourceType,
			RequireACL:     requireACL,
			AllowUnauth:    allowUnauth,
		})
	}
	// Health check
	s.registerRoute("/health", []string{http.MethodGet}, true, s.handleHealth)
	s.registerRoute("/ready", []string{http.MethodGet}, true, s.handleReady)
	addSpec(http.MethodGet, "/health", nil, "", false, true)
	addSpec(http.MethodGet, "/ready", nil, "", false, true)

	// Auth endpoints
	s.registerRoute("/api/v1/auth/login", []string{http.MethodPost}, true, s.handleLogin)
	s.registerRoute("/api/v1/auth/logout", []string{http.MethodPost}, true, s.handleLogout)
	s.registerRoute("/api/v1/auth/refresh", []string{http.MethodPost}, true, s.handleRefresh)
	addSpec(http.MethodPost, "/api/v1/auth/login", nil, "", false, true)
	addSpec(http.MethodPost, "/api/v1/auth/logout", []types.Scope{types.ScopeAuthLogout}, "", false, false)
	addSpec(http.MethodPost, "/api/v1/auth/refresh", []types.Scope{types.ScopeAuthLogin}, "", false, false)

	// Secret endpoints
	s.registerRoute("/api/v1/secrets", []string{http.MethodGet, http.MethodPost}, true, s.handleSecrets)
	s.registerRoute("/api/v1/secrets/", []string{http.MethodGet, http.MethodPut, http.MethodDelete}, true, s.handleSecret)
	addSpec(http.MethodGet, "/api/v1/secrets", []types.Scope{types.ScopeSecretList}, "secret", true, false)
	addSpec(http.MethodPost, "/api/v1/secrets", []types.Scope{types.ScopeSecretCreate}, "secret", true, false)
	addSpec(http.MethodGet, "/api/v1/secrets/", []types.Scope{types.ScopeSecretRead}, "secret", true, false)
	addSpec(http.MethodPut, "/api/v1/secrets/", []types.Scope{types.ScopeSecretUpdate}, "secret", true, false)
	addSpec(http.MethodDelete, "/api/v1/secrets/", []types.Scope{types.ScopeSecretDelete}, "secret", true, false)

	// Identity endpoints
	s.registerRoute("/api/v1/identities", []string{http.MethodGet}, true, s.handleIdentities)
	s.registerRoute("/api/v1/identities/", []string{http.MethodGet}, true, s.handleIdentity)
	addSpec(http.MethodGet, "/api/v1/identities", []types.Scope{types.ScopeIdentityRead}, "identity", true, false)
	addSpec(http.MethodGet, "/api/v1/identities/", []types.Scope{types.ScopeIdentityRead}, "identity", true, false)

	// Audit endpoints
	s.registerRoute("/api/v1/audit", []string{http.MethodGet}, true, s.handleAuditQuery)
	s.registerRoute("/api/v1/audit/export", []string{http.MethodGet}, true, s.handleAuditExport)
	addSpec(http.MethodGet, "/api/v1/audit", []types.Scope{types.ScopeAuditQuery}, "audit", true, false)
	addSpec(http.MethodGet, "/api/v1/audit/export", []types.Scope{types.ScopeAuditExport}, "audit", true, false)

	// CICD endpoints
	s.registerRoute("/api/v1/cicd/auth", []string{http.MethodPost}, true, s.handlePipelineAuth)
	addSpec(http.MethodPost, "/api/v1/cicd/auth", []types.Scope{types.ScopePipelineAuth}, "", false, true)

	// File endpoints
	s.registerRoute("/api/v1/files", []string{http.MethodGet, http.MethodPost}, true, s.handleFiles)
	s.registerRoute("/api/v1/files/", []string{http.MethodGet, http.MethodDelete}, true, s.handleFile)
	addSpec(http.MethodGet, "/api/v1/files", []types.Scope{types.ScopeFileList}, "file", true, false)
	addSpec(http.MethodPost, "/api/v1/files", []types.Scope{types.ScopeFileUpload}, "file", true, false)
	addSpec(http.MethodGet, "/api/v1/files/", []types.Scope{types.ScopeFileDownload}, "file", true, false)
	addSpec(http.MethodDelete, "/api/v1/files/", []types.Scope{types.ScopeFileDelete}, "file", true, false)

	// Access endpoints
	s.registerRoute("/api/v1/access/grants", []string{http.MethodGet, http.MethodPost}, true, s.handleAccessGrants)
	s.registerRoute("/api/v1/access/grants/", []string{http.MethodDelete}, true, s.handleAccessGrant)
	s.registerRoute("/api/v1/access/requests", []string{http.MethodPost}, true, s.handleAccessRequests)
	s.registerRoute("/api/v1/access/requests/", []string{http.MethodPost}, true, s.handleAccessRequestAction)
	addSpec(http.MethodGet, "/api/v1/access/grants", []types.Scope{types.ScopeAccessRead}, "access", true, false)
	addSpec(http.MethodPost, "/api/v1/access/grants", []types.Scope{types.ScopeAccessGrant}, "access", true, false)
	addSpec(http.MethodDelete, "/api/v1/access/grants/", []types.Scope{types.ScopeAccessRevoke}, "access", true, false)
	addSpec(http.MethodPost, "/api/v1/access/requests", []types.Scope{types.ScopeAccessRequest}, "access", true, false)
	addSpec(http.MethodPost, "/api/v1/access/requests/", []types.Scope{types.ScopeAccessApprove}, "access", true, false)

	// Policy endpoints
	s.registerRoute("/api/v1/policies", []string{http.MethodGet, http.MethodPost}, true, s.handlePolicies)
	s.registerRoute("/api/v1/policies/bind", []string{http.MethodPost}, true, s.handlePolicyBind)
	s.registerRoute("/api/v1/policies/simulate", []string{http.MethodPost}, true, s.handlePolicySimulate)
	s.registerRoute("/api/v1/policies/freeze", []string{http.MethodPost}, true, s.handlePolicyFreeze)
	addSpec(http.MethodGet, "/api/v1/policies", []types.Scope{types.ScopePolicyRead}, "policy", true, false)
	addSpec(http.MethodPost, "/api/v1/policies", []types.Scope{types.ScopePolicyCreate}, "policy", true, false)
	addSpec(http.MethodPost, "/api/v1/policies/bind", []types.Scope{types.ScopePolicyBind}, "policy", true, false)
	addSpec(http.MethodPost, "/api/v1/policies/simulate", []types.Scope{types.ScopePolicySimulate}, "policy", true, false)
	addSpec(http.MethodPost, "/api/v1/policies/freeze", []types.Scope{types.ScopePolicyFreeze, types.ScopeAdminAll}, "policy", true, false)

	// Share endpoints
	s.registerRoute("/api/v1/shares", []string{http.MethodGet, http.MethodPost}, true, s.handleShares)
	s.registerRoute("/api/v1/shares/accept/", []string{http.MethodPost}, true, s.handleShareAccept)
	s.registerRoute("/api/v1/shares/revoke/", []string{http.MethodPost}, true, s.handleShareRevoke)
	s.registerRoute("/api/v1/shares/export/", []string{http.MethodGet}, true, s.handleShareExport)
	s.registerRoute("/api/v1/shares/import", []string{http.MethodPost}, true, s.handleShareImport)
	addSpec(http.MethodGet, "/api/v1/shares", []types.Scope{types.ScopeShareRead}, "share", true, false)
	addSpec(http.MethodPost, "/api/v1/shares", []types.Scope{types.ScopeShareCreate}, "share", true, false)
	addSpec(http.MethodPost, "/api/v1/shares/accept/", []types.Scope{types.ScopeShareAccept}, "share", true, false)
	addSpec(http.MethodPost, "/api/v1/shares/revoke/", []types.Scope{types.ScopeShareRevoke}, "share", true, false)
	addSpec(http.MethodGet, "/api/v1/shares/export/", []types.Scope{types.ScopeShareExport}, "share", true, false)
	addSpec(http.MethodPost, "/api/v1/shares/import", []types.Scope{types.ScopeShareAccept}, "share", true, false)

	// Monitoring endpoints
	s.registerRoute("/api/v1/monitoring/dashboard", []string{http.MethodGet, http.MethodPost}, true, s.handleDashboard)
	s.registerRoute("/api/v1/monitoring/events", []string{http.MethodGet}, true, s.handleMonitoringEvents)
	s.registerRoute("/api/v1/monitoring/stream", []string{http.MethodGet}, true, s.handleMonitoringStream)
	addSpec(http.MethodGet, "/api/v1/monitoring/dashboard", []types.Scope{types.ScopeAuditRead}, "audit", true, false)
	addSpec(http.MethodPost, "/api/v1/monitoring/dashboard", []types.Scope{types.ScopeAuditRead}, "audit", true, false)
	addSpec(http.MethodGet, "/api/v1/monitoring/events", []types.Scope{types.ScopeAuditRead}, "audit", true, false)
	addSpec(http.MethodGet, "/api/v1/monitoring/stream", []types.Scope{types.ScopeAuditRead}, "audit", true, false)

	// Alert endpoints
	s.registerRoute("/api/v1/alerts", []string{http.MethodGet}, true, s.handleAlerts)
	s.registerRoute("/api/v1/alerts/", []string{http.MethodGet, http.MethodPost}, true, s.handleAlert)
	s.registerRoute("/api/v1/alerts/rules", []string{http.MethodGet, http.MethodPost}, true, s.handleAlertRules)
	s.registerRoute("/api/v1/alerts/notifiers", []string{http.MethodGet}, true, s.handleAlertNotifiers)
	addSpec(http.MethodGet, "/api/v1/alerts", []types.Scope{types.ScopeAuditRead}, "audit", true, false)
	addSpec(http.MethodGet, "/api/v1/alerts/", []types.Scope{types.ScopeAuditRead}, "audit", true, false)
	addSpec(http.MethodPost, "/api/v1/alerts/", []types.Scope{types.ScopeAuditRead}, "audit", true, false)
	addSpec(http.MethodGet, "/api/v1/alerts/rules", []types.Scope{types.ScopeAuditRead}, "audit", true, false)
	addSpec(http.MethodPost, "/api/v1/alerts/rules", []types.Scope{types.ScopeAuditRead}, "audit", true, false)
	addSpec(http.MethodGet, "/api/v1/alerts/notifiers", []types.Scope{types.ScopeAuditRead}, "audit", true, false)

	// Generic command-dispatch endpoint for CLI/API parity.
	s.registerRoute("/api/v1/commands/", []string{http.MethodPost}, true, s.handleCommandDispatch)
	// Include both auth and non-auth dispatch forms in route inventory.
	s.routeSet = append(s.routeSet, RouteMethod{Method: http.MethodPost, Path: "/api/v1/commands/auth/login"})
	addSpec(http.MethodPost, "/api/v1/commands/auth/", nil, "", false, true)
	addSpec(http.MethodPost, "/api/v1/commands/", []types.Scope{types.ScopeAdminAll}, "", false, false)

	sort.Slice(s.routeSpecs, func(i, j int) bool {
		if len(s.routeSpecs[i].Pattern) == len(s.routeSpecs[j].Pattern) {
			if s.routeSpecs[i].Method == s.routeSpecs[j].Method {
				return s.routeSpecs[i].Pattern < s.routeSpecs[j].Pattern
			}
			return s.routeSpecs[i].Method < s.routeSpecs[j].Method
		}
		return len(s.routeSpecs[i].Pattern) > len(s.routeSpecs[j].Pattern)
	})
}

func (s *Server) registerRoute(path string, methods []string, guarded bool, handler http.HandlerFunc) {
	h := handler
	if guarded {
		h = s.withMiddleware(handler)
	}
	s.mux.HandleFunc(path, h)
	for _, m := range methods {
		s.routeSet = append(s.routeSet, RouteMethod{Method: m, Path: methodProbePath(path, m)})
	}
}

func methodProbePath(path, method string) string {
	switch path {
	case "/api/v1/secrets/":
		return "/api/v1/secrets/name"
	case "/api/v1/identities/":
		return "/api/v1/identities/id"
	case "/api/v1/files/":
		return "/api/v1/files/name"
	case "/api/v1/access/grants/":
		return "/api/v1/access/grants/id"
	case "/api/v1/access/requests/":
		return "/api/v1/access/requests/id/approve"
	case "/api/v1/shares/accept/":
		return "/api/v1/shares/accept/id"
	case "/api/v1/shares/revoke/":
		return "/api/v1/shares/revoke/id"
	case "/api/v1/shares/export/":
		return "/api/v1/shares/export/id"
	case "/api/v1/alerts/":
		if method == http.MethodGet {
			return "/api/v1/alerts/id"
		}
		return "/api/v1/alerts/id/acknowledge"
	case "/api/v1/commands/":
		return "/api/v1/commands/secret/list"
	default:
		return path
	}
}

// RouteMethods returns the concrete method/path contract registered by setupRoutes.
func (s *Server) RouteMethods() []RouteMethod {
	out := make([]RouteMethod, len(s.routeSet))
	copy(out, s.routeSet)
	return out
}

// RouteAuthSpecs returns the registered API auth specs.
func (s *Server) RouteAuthSpecs() []authz.APIRouteAuthSpec {
	out := make([]authz.APIRouteAuthSpec, len(s.routeSpecs))
	copy(out, s.routeSpecs)
	return out
}

// withMiddleware wraps handlers with common middleware
func (s *Server) withMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startedAt := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		// CORS
		sw.Header().Set("Access-Control-Allow-Origin", "*")
		sw.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		sw.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")

		if r.Method == "OPTIONS" {
			sw.WriteHeader(http.StatusNoContent)
			s.logAPIRequestAudit(r.Context(), r, sw.status, time.Since(startedAt))
			return
		}

		// Rate limiting
		clientIP := getClientIP(r)
		if !s.rateLimiter.Allow(clientIP) {
			s.jsonError(sw, http.StatusTooManyRequests, "rate_limited", "Too many requests")
			s.logAPIRequestAudit(r.Context(), r, sw.status, time.Since(startedAt))
			return
		}

		// Security headers
		sw.Header().Set("X-Content-Type-Options", "nosniff")
		sw.Header().Set("X-Frame-Options", "DENY")
		sw.Header().Set("X-XSS-Protection", "1; mode=block")
		sw.Header().Set("Content-Security-Policy", "default-src 'self'")
		sw.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		if !s.authorizeRoute(sw, r) {
			s.logAPIRequestAudit(r.Context(), r, sw.status, time.Since(startedAt))
			return
		}

		handler(sw, r)
		s.logAPIRequestAudit(r.Context(), r, sw.status, time.Since(startedAt))
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	// Implicitly set status to 200 if caller only writes body.
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *Server) logAPIRequestAudit(ctx context.Context, r *http.Request, status int, duration time.Duration) {
	if s.audit == nil || r == nil {
		return
	}
	actorID := types.ID("")
	if session := s.getSession(r); session != nil {
		actorID = session.IdentityID
	}
	success := status < 400
	_ = s.audit.Log(ctx, audit.AuditEventInput{
		Type:      "api",
		Action:    "request",
		ActorID:   actorID,
		ActorType: "identity",
		Success:   success,
		Details: map[string]any{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status_code": status,
			"client_ip":   getClientIP(r),
			"duration_ms": duration.Milliseconds(),
		},
	})
}

func (s *Server) authorizeRoute(w http.ResponseWriter, r *http.Request) bool {
	if s.authorizer == nil {
		return true
	}
	spec, ok := authz.ResolveAPIRouteSpec(r.Method, r.URL.Path, s.routeSpecs)
	if !ok {
		s.authorizer.AuditSpecDenied(r.Context(), authz.Request{
			Session:   nil,
			Operation: "api:" + r.Method + ":" + r.URL.Path,
			Metadata:  map[string]any{"method": r.Method, "path": r.URL.Path},
		}, "authorization spec missing for route")
		s.jsonError(w, http.StatusForbidden, types.ErrCodeAuthzSpecMissing, "authorization spec missing for route")
		return false
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/commands/") {
		cmdPath := authz.CommandPathFromDispatchURL(r.URL.Path)
		cspec, err := authz.ResolveCommandDispatchAuth(cmdPath)
		if err != nil {
			s.authorizer.AuditSpecDenied(r.Context(), authz.Request{
				Session:   nil,
				Operation: "api:" + r.Method + ":" + r.URL.Path,
				Metadata:  map[string]any{"method": r.Method, "path": r.URL.Path, "command_path": cmdPath},
			}, "authorization spec missing for command dispatch")
			s.jsonError(w, http.StatusForbidden, types.ErrCodeAuthzSpecMissing, err.Error())
			return false
		}
		spec.RequiredScopes = cspec.RequiredScopes
		spec.AllowUnauth = cspec.AllowUnauth
		spec.RequireACL = cspec.RequireACL
		spec.ResourceType = cspec.ResourceType
	}

	session := s.getSession(r)
	resourceType, resourceID, usageCtx, metadata := s.resolver.ResolveAPI(r, session, spec)
	req := authz.Request{
		Session:        session,
		ActorID:        resolveActorID(session),
		Operation:      "api:" + r.Method + ":" + r.URL.Path,
		RequiredScopes: spec.RequiredScopes,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		UsageContext:   usageCtx,
		AllowUnauth:    spec.AllowUnauth,
		RequireACL:     spec.RequireACL,
		Metadata:       metadata,
	}
	if _, err := s.authorizer.Authorize(r.Context(), req); err != nil {
		var te *types.Error
		if errors.As(err, &te) {
			status := http.StatusForbidden
			if te.Code == types.ErrCodeUnauthorized {
				status = http.StatusUnauthorized
			}
			s.jsonError(w, status, te.Code, te.Message)
			return false
		}
		s.jsonError(w, http.StatusForbidden, "forbidden", err.Error())
		return false
	}
	return true
}

// Start starts the API server
func (s *Server) Start() error {
	if s.audit != nil {
		s.audit.Start(context.Background())
	}
	if s.alerts != nil {
		s.alerts.StartEventProcessor(context.Background())
	}

	if s.certFile != "" && s.keyFile != "" {
		return s.server.ListenAndServeTLS(s.certFile, s.keyFile)
	}

	return s.server.ListenAndServe()
}

// Close gracefully closes the server's components
func (s *Server) Close() error {
	if s.audit != nil {
		s.audit.Close()
	}
	if s.monitoring != nil {
		s.monitoring.Close()
	}
	if s.alerts != nil {
		_ = s.alerts.Close()
	}
	if s.files != nil {
		s.files.Close()
	}
	if s.cicd != nil {
		s.cicd.Close()
	}
	return s.crypto.Close()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// Health and readiness handlers

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, map[string]string{
		"status": "healthy",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	// Check dependencies
	ready := true
	checks := make(map[string]string)

	checks["server"] = "ok"
	if s.identity == nil {
		checks["identity"] = "not configured"
		ready = false
	} else {
		checks["identity"] = "ok"
	}

	if s.secrets == nil {
		checks["secrets"] = "not configured"
		ready = false
	} else {
		checks["secrets"] = "ok"
	}

	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}

	s.jsonResponse(w, status, map[string]any{
		"ready":  ready,
		"checks": checks,
	})
}

// Auth handlers

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid request body")
		return
	}

	if s.identity == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Identity service not available")
		return
	}

	// Authenticate
	session, err := s.identity.Authenticate(r.Context(), req.Email, req.Password, types.ID(req.DeviceID))
	if err != nil {
		s.logAuditEvent(r.Context(), "auth", "login_failed", types.ID(req.Email), false, map[string]any{
			"error": err.Error(),
			"ip":    getClientIP(r),
		})
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Invalid credentials")
		return
	}

	s.logAuditEvent(r.Context(), "auth", "login", session.IdentityID, true, map[string]any{
		"session_id": session.ID,
		"ip":         getClientIP(r),
	})

	s.jsonResponse(w, http.StatusOK, LoginResponse{
		SessionID: string(session.ID),
		ExpiresAt: session.ExpiresAt.Time(),
		Scopes:    session.ScopeList,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	session, ok := s.requireSession(w, r, "Not authenticated")
	if !ok {
		return
	}

	if s.identity != nil {
		s.identity.RevokeSession(r.Context(), session.ID)
	}

	s.logAuditEvent(r.Context(), "auth", "logout", session.IdentityID, true, nil)

	s.jsonResponse(w, http.StatusOK, map[string]string{
		"status": "logged_out",
	})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	session, ok := s.requireSession(w, r, "Not authenticated")
	if !ok {
		return
	}

	if s.identity != nil {
		s.identity.RefreshSession(r.Context(), session.ID)
	}

	s.jsonResponse(w, http.StatusOK, map[string]string{
		"status":    "refreshed",
		"sessionId": string(session.ID),
	})
}

// Secret handlers

func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r, "Not authenticated")
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.listSecrets(w, r, session)
	case http.MethodPost:
		s.createSecret(w, r, session)
	default:
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) handleSecret(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r, "Not authenticated")
	if !ok {
		return
	}

	// Extract secret name from path
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/")
	if name == "" {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Secret name required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getSecret(w, r, session, name)
	case http.MethodPut:
		s.updateSecret(w, r, session, name)
	case http.MethodDelete:
		s.deleteSecret(w, r, session, name)
	default:
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request, session *types.Session) {
	if s.secrets == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Secret service not available")
		return
	}

	env := r.URL.Query().Get("environment")
	prefix := r.URL.Query().Get("prefix")

	secretsList, err := s.secrets.List(r.Context(), secrets.ListSecretsOptions{
		Prefix:      prefix,
		Environment: env,
	})
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to list secrets")
		return
	}

	s.jsonResponse(w, http.StatusOK, secretsList)
}

func (s *Server) createSecret(w http.ResponseWriter, r *http.Request, session *types.Session) {
	if s.secrets == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Secret service not available")
		return
	}

	var req CreateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid request body")
		return
	}

	secret, err := s.secrets.Create(r.Context(), secrets.CreateSecretOptions{
		Name:        req.Name,
		Type:        types.SecretType(req.Type),
		Value:       []byte(req.Value),
		Environment: req.Environment,
		ReadOnce:    req.ReadOnce,
		Immutable:   req.Immutable,
		Metadata:    req.Metadata,
		CreatorID:   session.IdentityID,
	})
	if err != nil {
		s.logAuditEvent(r.Context(), "secret", "create_failed", session.IdentityID, false, map[string]any{
			"name":  req.Name,
			"error": err.Error(),
		})
		s.jsonError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	s.logAuditEvent(r.Context(), "secret", "create", session.IdentityID, true, map[string]any{
		"name": req.Name,
	})

	s.jsonResponse(w, http.StatusCreated, secret)
}

func (s *Server) getSecret(w http.ResponseWriter, r *http.Request, session *types.Session, name string) {
	if s.secrets == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Secret service not available")
		return
	}

	metadataOnly := r.URL.Query().Get("metadata") == "true"

	if metadataOnly {
		meta, err := s.secrets.GetMetadata(r.Context(), name)
		if err != nil {
			s.jsonError(w, http.StatusNotFound, "not_found", "Secret not found")
			return
		}
		s.jsonResponse(w, http.StatusOK, meta)
		return
	}

	// Enforce CICD policy for pipelines
	if session.Type == "pipeline" && s.cicd != nil {
		if err := s.cicd.ValidateSecretAccess(r.Context(), session.IdentityID, []types.ID{types.ID(name)}); err != nil {
			s.jsonError(w, http.StatusForbidden, "forbidden", err.Error())
			return
		}
	}

	value, err := s.secrets.Get(r.Context(), name, session.IdentityID, session.MFAVerified)
	if err != nil {
		s.logAuditEvent(r.Context(), "secret", "read_failed", session.IdentityID, false, map[string]any{
			"name":  name,
			"error": err.Error(),
		})
		s.jsonError(w, http.StatusNotFound, "not_found", "Secret not found or access denied")
		return
	}

	s.logAuditEvent(r.Context(), "secret", "read", session.IdentityID, true, map[string]any{
		"name": name,
	})

	s.jsonResponse(w, http.StatusOK, map[string]string{
		"name":  name,
		"value": string(value),
	})
}

func (s *Server) updateSecret(w http.ResponseWriter, r *http.Request, session *types.Session, name string) {
	if s.secrets == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Secret service not available")
		return
	}

	var req UpdateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid request body")
		return
	}

	secret, err := s.secrets.Update(r.Context(), name, []byte(req.Value), session.IdentityID)
	if err != nil {
		s.logAuditEvent(r.Context(), "secret", "update_failed", session.IdentityID, false, map[string]any{
			"name":  name,
			"error": err.Error(),
		})
		s.jsonError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	s.logAuditEvent(r.Context(), "secret", "update", session.IdentityID, true, map[string]any{
		"name":    name,
		"version": secret.Version,
	})

	s.jsonResponse(w, http.StatusOK, secret)
}

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request, session *types.Session, name string) {
	if s.secrets == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Secret service not available")
		return
	}

	if err := s.secrets.Delete(r.Context(), name, session.IdentityID); err != nil {
		s.logAuditEvent(r.Context(), "secret", "delete_failed", session.IdentityID, false, map[string]any{
			"name":  name,
			"error": err.Error(),
		})
		s.jsonError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	s.logAuditEvent(r.Context(), "secret", "delete", session.IdentityID, true, map[string]any{
		"name": name,
	})

	s.jsonResponse(w, http.StatusNoContent, nil)
}

// Identity handlers

func (s *Server) handleIdentities(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r, "Not authenticated")
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.listIdentities(w, r, session)
	default:
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) handleIdentity(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r, "Not authenticated")
	if !ok {
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/identities/")
	if id == "" {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Identity ID required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getIdentity(w, r, session, types.ID(id))
	default:
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) listIdentities(w http.ResponseWriter, r *http.Request, session *types.Session) {
	if s.identity == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Identity service not available")
		return
	}

	identities, err := s.identity.ListIdentities(r.Context(), identity.ListOptions{})
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to list identities")
		return
	}

	s.jsonResponse(w, http.StatusOK, identities)
}

func (s *Server) getIdentity(w http.ResponseWriter, r *http.Request, session *types.Session, id types.ID) {
	if s.identity == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Identity service not available")
		return
	}

	ident, err := s.identity.GetIdentity(r.Context(), id)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, "not_found", "Identity not found")
		return
	}

	s.jsonResponse(w, http.StatusOK, ident)
}

// Audit handlers

func (s *Server) handleAuditQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	_, ok := s.requireSession(w, r, "Not authenticated")
	if !ok {
		return
	}

	if s.audit == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Audit service not available")
		return
	}

	// Parse query params
	actorID := r.URL.Query().Get("actor_id")
	resourceID := r.URL.Query().Get("resource_id")
	action := r.URL.Query().Get("action")
	start, err := parseOptionalTime(r.URL.Query().Get("start"))
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid start timestamp, expected RFC3339")
		return
	}
	end, err := parseOptionalTime(r.URL.Query().Get("end"))
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid end timestamp, expected RFC3339")
		return
	}
	limit := parseOptionalInt(r.URL.Query().Get("limit"), 100)

	events, err := s.audit.Query(r.Context(), audit.QueryOptions{
		ActorID:    types.ID(actorID),
		ResourceID: types.ID(resourceID),
		Action:     action,
		StartTime:  start,
		EndTime:    end,
		Limit:      limit,
	})
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to query audit log")
		return
	}

	s.jsonResponse(w, http.StatusOK, events)
}

func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	session, ok := s.requireSession(w, r, "Not authenticated")
	if !ok {
		return
	}

	if s.audit == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Audit service not available")
		return
	}

	start, err := parseOptionalTime(r.URL.Query().Get("start"))
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid start timestamp, expected RFC3339")
		return
	}
	end, err := parseOptionalTime(r.URL.Query().Get("end"))
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid end timestamp, expected RFC3339")
		return
	}
	limit := parseOptionalInt(r.URL.Query().Get("limit"), 10000)

	export, err := s.audit.Export(r.Context(), audit.ExportOptions{
		StartTime:  start,
		EndTime:    end,
		Limit:      limit,
		ExporterID: session.IdentityID,
	})
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "internal_error", "Failed to export audit log")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=audit-%s.json", time.Now().Format("20060102-150405")))
	io.Writer.Write(w, export)
}

// Helper methods

func (s *Server) getSession(r *http.Request) *types.Session {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil
	}

	// Expect "Bearer <session_id>"
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil
	}

	sessionID := types.ID(parts[1])

	if s.identity == nil {
		return nil
	}

	session, err := s.identity.GetSession(r.Context(), sessionID)
	if err != nil {
		return nil
	}

	if !session.IsActive() {
		return nil
	}

	// Rebuild scopes from list
	if session.Scopes == nil {
		session.Scopes = types.NewScopeSet(session.ScopeList...)
	}

	return session
}

func (s *Server) requireSession(w http.ResponseWriter, r *http.Request, msg string) (*types.Session, bool) {
	session := s.getSession(r)
	if session != nil {
		return session, true
	}
	if strings.TrimSpace(msg) == "" {
		msg = "Not authenticated"
	}
	s.jsonError(w, http.StatusUnauthorized, "unauthorized", msg)
	return nil, false
}

func (s *Server) logAuditEvent(ctx context.Context, eventType, action string, actorID types.ID, success bool, details map[string]any) {
	if s.audit == nil {
		return
	}

	s.audit.Log(ctx, audit.AuditEventInput{
		Type:      eventType,
		Action:    action,
		ActorID:   actorID,
		ActorType: "identity",
		Success:   success,
		Details:   details,
	})
}

func (s *Server) jsonResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

func (s *Server) jsonError(w http.ResponseWriter, status int, code, message string) {
	s.jsonResponse(w, status, map[string]string{
		"error":   code,
		"message": message,
	})
}

func getClientIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		return strings.Split(ip, ",")[0]
	}
	ip = r.Header.Get("X-Real-IP")
	if ip != "" {
		return ip
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

func resolveActorID(session *types.Session) types.ID {
	if session == nil {
		return ""
	}
	return session.IdentityID
}

func parseOptionalTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, value)
}

func parseOptionalInt(value string, defaultValue int) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return defaultValue
	}
	return parsed
}

// Request/Response types

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	DeviceID string `json:"device_id"`
}

type LoginResponse struct {
	SessionID string        `json:"session_id"`
	ExpiresAt time.Time     `json:"expires_at"`
	Scopes    []types.Scope `json:"scopes"`
}

type CreateSecretRequest struct {
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	Value       string         `json:"value"`
	Environment string         `json:"environment,omitempty"`
	ReadOnce    bool           `json:"read_once,omitempty"`
	Immutable   bool           `json:"immutable,omitempty"`
	Metadata    types.Metadata `json:"metadata,omitempty"`
}

type UpdateSecretRequest struct {
	Value string `json:"value"`
}

type AccessGrantCreateRequest struct {
	GranteeID    string        `json:"grantee_id"`
	ResourceID   string        `json:"resource_id"`
	ResourceType string        `json:"resource_type"`
	Scopes       []string      `json:"scopes"`
	ExpiresIn    time.Duration `json:"expires_in"`
	Resharing    bool          `json:"resharing"`
}

type AccessRequestCreateRequest struct {
	ResourceID    string   `json:"resource_id"`
	ResourceType  string   `json:"resource_type"`
	Justification string   `json:"justification"`
	Duration      string   `json:"duration"`
	Permissions   []string `json:"permissions"`
	Role          string   `json:"role"`
	MinApprovals  int      `json:"min_approvals"`
}

type AccessRequestApproveRequest struct {
	Notes string `json:"notes"`
}

type PolicyRulePayload struct {
	ID         string         `json:"id"`
	Effect     string         `json:"effect"`
	Actions    []string       `json:"actions"`
	Resources  []string       `json:"resources"`
	Conditions types.Metadata `json:"conditions"`
	Priority   int            `json:"priority"`
}

type PolicyCreateRequest struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Type        string              `json:"type"`
	Rules       []PolicyRulePayload `json:"rules"`
}

type PolicyBindRequest struct {
	PolicyID     string `json:"policy_id"`
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
}

type PolicySimulateRequest struct {
	PolicyID     string         `json:"policy_id"`
	Action       string         `json:"action"`
	ResourceID   string         `json:"resource_id"`
	ResourceType string         `json:"resource_type"`
	Context      map[string]any `json:"context"`
}

type ShareCreateRequest struct {
	Type            string        `json:"type"`
	ResourceID      string        `json:"resource_id"`
	RecipientID     string        `json:"recipient_id"`
	RecipientPubKey string        `json:"recipient_pub_key"`
	ExpiresIn       time.Duration `json:"expires_in"`
	MaxAccess       int           `json:"max_access"`
	OneTime         bool          `json:"one_time"`
}

type ShareImportRequest struct {
	PackageB64  string `json:"package_b64"`
	PackageJSON string `json:"package_json"`
	Password    string `json:"password"`
}

// RateLimiter provides simple token bucket rate limiting
type RateLimiter struct {
	mu      sync.Mutex
	rate    int
	burst   int
	buckets map[string]*bucket
}

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rps, burst int) *RateLimiter {
	if rps == 0 {
		rps = 100
	}
	if burst == 0 {
		burst = 200
	}
	return &RateLimiter{
		rate:    rps,
		burst:   burst,
		buckets: make(map[string]*bucket),
	}
}

// Allow checks if request should be allowed
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, exists := rl.buckets[key]
	if !exists {
		b = &bucket{
			tokens:    float64(rl.burst),
			lastCheck: time.Now(),
		}
		rl.buckets[key] = b
	}

	// Refill tokens
	elapsed := time.Since(b.lastCheck).Seconds()
	b.tokens += elapsed * float64(rl.rate)
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastCheck = time.Now()

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// errorResponse sends an error response
func (s *Server) errorResponse(w http.ResponseWriter, status int, err error) {
	var e *types.Error
	if errors.As(err, &e) {
		s.jsonError(w, status, e.Code, e.Message)
		return
	}
	s.jsonError(w, status, "error", err.Error())
}

// PipelineAuthRequest represents a pipeline auth request
type PipelineAuthRequest struct {
	Token    string `json:"token"`
	Provider string `json:"provider"`
}

// PipelineAuthResponse represents a pipeline auth response
type PipelineAuthResponse struct {
	SessionID string `json:"session_id"`
	ExpiresAt string `json:"expires_at"`
}

// handlePipelineAuth handles pipeline authentication via OIDC
func (s *Server) handlePipelineAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req PipelineAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.errorResponse(w, http.StatusBadRequest, ErrInvalidInput)
		return
	}

	if s.cicd == nil {
		s.errorResponse(w, http.StatusServiceUnavailable, errors.New("cicd: service not available"))
		return
	}

	pipeline, err := s.cicd.AuthenticatePipelineOIDC(r.Context(), req.Token, types.PipelineProvider(req.Provider))
	if err != nil {
		s.errorResponse(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	// Create session for pipeline
	session, err := s.identity.CreateSession(r.Context(), identity.CreateSessionOptions{
		IdentityID: pipeline.ID,
		Type:       "pipeline",
		Scopes:     []types.Scope{types.ScopeSecretRead},
	})
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	s.jsonResponse(w, http.StatusOK, PipelineAuthResponse{
		SessionID: string(session.ID),
		ExpiresAt: time.Unix(0, int64(session.ExpiresAt)).Format(time.RFC3339),
	})
}

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r, "Not authenticated")
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.listFiles(w, r, session)
	case http.MethodPost:
		s.handleFileUpload(w, r, session)
	default:
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) handleFile(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r, "Not authenticated")
	if !ok {
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/api/v1/files/")
	if name == "" {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "File name required")
		return
	}

	// Check for sub-actions
	if strings.HasSuffix(name, "/kill") {
		if r.Method != http.MethodPost {
			s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		s.handleFileKill(w, r, session, strings.TrimSuffix(name, "/kill"))
		return
	}
	if strings.HasSuffix(name, "/revive") {
		if r.Method != http.MethodPost {
			s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		s.handleFileRevive(w, r, session, strings.TrimSuffix(name, "/revive"))
		return
	}
	if strings.HasSuffix(name, "/protect") {
		if r.Method != http.MethodPost {
			s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		s.handleFileProtect(w, r, session, strings.TrimSuffix(name, "/protect"))
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleFileDownload(w, r, session, name)
	case http.MethodDelete:
		s.handleFileDelete(w, r, session, name)
	default:
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) listFiles(w http.ResponseWriter, r *http.Request, session *types.Session) {
	if s.files == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "File service not available")
		return
	}

	prefix := r.URL.Query().Get("prefix")
	includeDeleted := r.URL.Query().Get("include_deleted") == "true"

	fileList, err := s.files.List(r.Context(), files.ListOptions{
		Prefix:         prefix,
		IncludeDeleted: includeDeleted,
	})
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	s.jsonResponse(w, http.StatusOK, fileList)
}

func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request, session *types.Session) {
	if s.files == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "File service not available")
		return
	}

	err := r.ParseMultipartForm(100 * 1024 * 1024) // 100MB max
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid_request", "Multipart form required")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid_request", "File component missing")
		return
	}
	defer file.Close()

	name := r.FormValue("name")
	if name == "" {
		name = header.Filename
	}

	expiresIn, _ := time.ParseDuration(r.FormValue("expires_in"))
	overwrite := r.FormValue("overwrite") == "true"

	f, err := s.files.Upload(r.Context(), files.UploadOptions{
		Name:         name,
		OriginalName: header.Filename,
		ContentType:  header.Header.Get("Content-Type"),
		Reader:       file,
		ExpiresIn:    expiresIn,
		Overwrite:    overwrite,
		UploaderID:   session.IdentityID,
	})
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	s.jsonResponse(w, http.StatusCreated, f)
}

func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request, session *types.Session, name string) {
	if s.files == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "File service not available")
		return
	}

	meta, err := s.files.GetMetadata(r.Context(), name)
	if err != nil {
		s.errorResponse(w, http.StatusNotFound, err)
		return
	}

	// We set headers after Download succeeds? No, Download streams.
	// But we can set them now and if Download fails it might be too late to change Status.
	// However, we want the Status code to be 403 if ValidateAccess fails inside Download.
	// So we can set headers BUT if the first thing Download does is ValidateAccess and it fails,
	// we haven't written to 'w' yet, so we can still set Status.

	w.Header().Set("Content-Type", meta.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", meta.OriginalName))

	err = s.files.Download(r.Context(), name, files.DownloadOptions{
		AccessorID:  session.IdentityID,
		IPAddress:   getClientIP(r),
		MFAVerified: session.MFAVerified,
	}, w)

	if err != nil {
		// If headers weren't sent yet, this will work.
		// If they were (unlikely if Download failed at validation), this will be ignored but good to have.
		s.errorResponse(w, http.StatusForbidden, err)
		return
	}
}

func (s *Server) handleFileDelete(w http.ResponseWriter, r *http.Request, session *types.Session, name string) {
	err := s.files.Delete(r.Context(), name, session.IdentityID)
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleFileProtect(w http.ResponseWriter, r *http.Request, session *types.Session, name string) {
	var req files.FileProtectionPolicy
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid policy data")
		return
	}

	meta, err := s.files.GetMetadata(r.Context(), name)
	if err != nil {
		s.errorResponse(w, http.StatusNotFound, err)
		return
	}
	req.FileID = meta.ID

	if err := s.files.SetProtectionPolicy(r.Context(), &req); err != nil {
		s.errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]string{"status": "policy_applied"})
}

func (s *Server) handleFileKill(w http.ResponseWriter, r *http.Request, session *types.Session, name string) {
	var req struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if err := s.files.KillFile(r.Context(), name, session.IdentityID, req.Reason); err != nil {
		s.errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]string{"status": "killed"})
}

func (s *Server) handleFileRevive(w http.ResponseWriter, r *http.Request, session *types.Session, name string) {
	if err := s.files.ReviveFile(r.Context(), name); err != nil {
		s.errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]string{"status": "revived"})
}

// Monitoring handlers

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	_, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}

	if s.monitoring == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Monitoring service not available")
		return
	}

	var period *time.Duration
	if p := strings.TrimSpace(r.URL.Query().Get("period")); p != "" {
		d, err := time.ParseDuration(p)
		if err != nil {
			s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid period duration")
			return
		}
		period = &d
	}

	data, err := s.monitoring.GetDashboardData(r.Context(), "", monitoring.DashboardOptions{Period: period})
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	s.jsonResponse(w, http.StatusOK, data)
}

func (s *Server) handleMonitoringEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	_, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}

	if s.monitoring == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Monitoring service not available")
		return
	}

	var eventTypes []monitoring.EventType
	if rawTypes := strings.TrimSpace(r.URL.Query().Get("type")); rawTypes != "" {
		for _, t := range strings.Split(rawTypes, ",") {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			eventTypes = append(eventTypes, monitoring.EventType(t))
		}
	}
	actorID := types.ID(strings.TrimSpace(r.URL.Query().Get("actor")))
	start, err := parseOptionalTime(r.URL.Query().Get("start"))
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid start timestamp, expected RFC3339")
		return
	}
	end, err := parseOptionalTime(r.URL.Query().Get("end"))
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid end timestamp, expected RFC3339")
		return
	}
	limit := parseOptionalInt(r.URL.Query().Get("limit"), 100)

	events, err := s.monitoring.Query(r.Context(), monitoring.QueryOptions{
		Types:     eventTypes,
		OrgID:     "",
		ActorID:   actorID,
		StartTime: start,
		EndTime:   end,
		Limit:     limit,
	})
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	s.jsonResponse(w, http.StatusOK, events)
}

func (s *Server) handleMonitoringStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	session, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}

	if s.monitoring == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Monitoring service not available")
		return
	}

	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "error", "Streaming not supported")
		return
	}

	subID := fmt.Sprintf("stream-%s-%d", session.IdentityID, time.Now().UnixNano())
	eventCh := s.monitoring.Subscribe(subID, monitoring.EventFilter{
		OrgID: "",
	})
	defer s.monitoring.Unsubscribe(subID)

	// Send initial comment to keep connection open
	fmt.Fprintf(w, ": ok\n\n")
	flusher.Flush()

	for {
		select {
		case event := <-eventCh:
			if event == nil {
				return
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// Alert handlers

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	_, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.alerts == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Alert service not available")
		return
	}

	switch r.Method {
	case http.MethodGet:
		opts := alerts.ListAlertsOptions{
			Status:   alerts.AlertStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
			Severity: alerts.AlertSeverity(strings.TrimSpace(r.URL.Query().Get("severity"))),
		}
		alerts, err := s.alerts.ListAlerts(r.Context(), opts)
		if err != nil {
			s.errorResponse(w, http.StatusInternalServerError, err)
			return
		}
		s.jsonResponse(w, http.StatusOK, alerts)
	default:
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.alerts == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Alert service not available")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/alerts/")
	if path == "" {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Alert ID required")
		return
	}

	switch {
	case strings.HasSuffix(path, "/acknowledge"):
		if r.Method != http.MethodPost {
			s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		id := types.ID(strings.TrimSuffix(path, "/acknowledge"))
		if err := s.alerts.AcknowledgeAlert(r.Context(), id, session.IdentityID); err != nil {
			s.errorResponse(w, http.StatusInternalServerError, err)
			return
		}
		s.jsonResponse(w, http.StatusOK, map[string]string{"status": "acknowledged"})
		return
	case strings.HasSuffix(path, "/resolve"):
		if r.Method != http.MethodPost {
			s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		id := types.ID(strings.TrimSuffix(path, "/resolve"))
		if err := s.alerts.ResolveAlert(r.Context(), id, session.IdentityID); err != nil {
			s.errorResponse(w, http.StatusInternalServerError, err)
			return
		}
		s.jsonResponse(w, http.StatusOK, map[string]string{"status": "resolved"})
		return
	default:
		if r.Method != http.MethodGet {
			s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		alert, err := s.alerts.GetAlert(r.Context(), types.ID(path))
		if err != nil {
			s.errorResponse(w, http.StatusNotFound, err)
			return
		}
		s.jsonResponse(w, http.StatusOK, alert)
	}
}

func (s *Server) handleAlertRules(w http.ResponseWriter, r *http.Request) {
	_, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.alerts == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Alert service not available")
		return
	}

	switch r.Method {
	case http.MethodGet:
		rules, err := s.alerts.ListRules(r.Context())
		if err != nil {
			s.errorResponse(w, http.StatusInternalServerError, err)
			return
		}
		s.jsonResponse(w, http.StatusOK, rules)
	case http.MethodPost:
		var rule alerts.Rule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			s.jsonError(w, http.StatusBadRequest, "invalid_input", err.Error())
			return
		}
		if err := s.alerts.CreateRule(r.Context(), &rule); err != nil {
			s.errorResponse(w, http.StatusInternalServerError, err)
			return
		}
		s.jsonResponse(w, http.StatusCreated, rule)
	default:
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) handleAlertNotifiers(w http.ResponseWriter, r *http.Request) {
	_, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.alerts == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Alert service not available")
		return
	}

	switch r.Method {
	case http.MethodGet:
		notifiers, err := s.alerts.ListNotifiers(r.Context())
		if err != nil {
			s.errorResponse(w, http.StatusInternalServerError, err)
			return
		}
		s.jsonResponse(w, http.StatusOK, notifiers)
	default:
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) handleAccessGrants(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.access == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Access service not available")
		return
	}

	switch r.Method {
	case http.MethodGet:
		grantee := strings.TrimSpace(r.URL.Query().Get("grantee"))
		resource := strings.TrimSpace(r.URL.Query().Get("resource"))
		includeRevoked := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("include_revoked")), "true")
		grants, err := s.access.ListGrants(r.Context(), access.ListGrantsOptions{
			GranteeID:      types.ID(grantee),
			ResourceID:     types.ID(resource),
			IncludeRevoked: includeRevoked,
		})
		if err != nil {
			s.errorResponse(w, http.StatusInternalServerError, err)
			return
		}
		s.jsonResponse(w, http.StatusOK, grants)
	case http.MethodPost:
		var req AccessGrantCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid request body")
			return
		}
		scopes := make([]types.Scope, 0, len(req.Scopes))
		for _, sc := range req.Scopes {
			sc = strings.TrimSpace(sc)
			if sc == "" {
				continue
			}
			scopes = append(scopes, types.Scope(sc))
		}
		grant, err := s.access.Grant(r.Context(), access.GrantOptions{
			GrantorID:      session.IdentityID,
			GranteeID:      types.ID(strings.TrimSpace(req.GranteeID)),
			ResourceID:     types.ID(strings.TrimSpace(req.ResourceID)),
			ResourceType:   strings.TrimSpace(req.ResourceType),
			Scopes:         scopes,
			ExpiresIn:      req.ExpiresIn,
			AllowResharing: req.Resharing,
		})
		if err != nil {
			s.errorResponse(w, http.StatusBadRequest, err)
			return
		}
		s.jsonResponse(w, http.StatusCreated, grant)
	default:
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) handleAccessGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	_, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.access == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Access service not available")
		return
	}
	id := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/access/grants/"))
	if id == "" {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Grant ID required")
		return
	}
	if err := s.access.Revoke(r.Context(), types.ID(id)); err != nil {
		s.errorResponse(w, http.StatusBadRequest, err)
		return
	}
	s.jsonResponse(w, http.StatusNoContent, nil)
}

func (s *Server) handleAccessRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	session, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.access == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Access service not available")
		return
	}
	var req AccessRequestCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid request body")
		return
	}
	accessReq, err := s.access.CreateAccessRequest(r.Context(), access.CreateAccessRequestOptions{
		RequestorID:   session.IdentityID,
		ResourceID:    types.ID(strings.TrimSpace(req.ResourceID)),
		ResourceType:  strings.TrimSpace(req.ResourceType),
		Justification: strings.TrimSpace(req.Justification),
		Duration:      strings.TrimSpace(req.Duration),
		Permissions:   req.Permissions,
		Role:          strings.TrimSpace(req.Role),
		MinApprovals:  req.MinApprovals,
	})
	if err != nil {
		s.errorResponse(w, http.StatusBadRequest, err)
		return
	}
	s.jsonResponse(w, http.StatusCreated, accessReq)
}

func (s *Server) handleAccessRequestAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	session, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.access == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Access service not available")
		return
	}
	suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/access/requests/")
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	if len(parts) != 2 || parts[1] != "approve" || strings.TrimSpace(parts[0]) == "" {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Expected /api/v1/access/requests/{id}/approve")
		return
	}
	var req AccessRequestApproveRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	approved, err := s.access.ApproveAccessRequest(r.Context(), types.ID(parts[0]), session.IdentityID, strings.TrimSpace(req.Notes))
	if err != nil {
		s.errorResponse(w, http.StatusBadRequest, err)
		return
	}
	s.jsonResponse(w, http.StatusOK, approved)
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.policy == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Policy service not available")
		return
	}
	switch r.Method {
	case http.MethodGet:
		policies, err := s.policy.List(r.Context())
		if err != nil {
			s.errorResponse(w, http.StatusInternalServerError, err)
			return
		}
		s.jsonResponse(w, http.StatusOK, policies)
	case http.MethodPost:
		var req PolicyCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid request body")
			return
		}
		rules := make([]types.PolicyRule, 0, len(req.Rules))
		for _, rule := range req.Rules {
			rules = append(rules, types.PolicyRule{
				ID:         types.ID(strings.TrimSpace(rule.ID)),
				Effect:     strings.TrimSpace(rule.Effect),
				Actions:    rule.Actions,
				Resources:  rule.Resources,
				Conditions: rule.Conditions,
				Priority:   rule.Priority,
			})
		}
		created, err := s.policy.Create(r.Context(), policy.CreatePolicyOptions{
			Name:        strings.TrimSpace(req.Name),
			Description: strings.TrimSpace(req.Description),
			Type:        types.PolicyType(strings.TrimSpace(req.Type)),
			Rules:       rules,
			SignerID:    session.IdentityID,
		})
		if err != nil {
			s.errorResponse(w, http.StatusBadRequest, err)
			return
		}
		s.jsonResponse(w, http.StatusCreated, created)
	default:
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) handlePolicyBind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	session, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.policy == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Policy service not available")
		return
	}
	var req PolicyBindRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid request body")
		return
	}
	if strings.TrimSpace(req.ResourceType) == "" {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "resource_type is required")
		return
	}
	if err := s.policy.Bind(r.Context(), types.ID(strings.TrimSpace(req.PolicyID)), types.ID(strings.TrimSpace(req.ResourceID)), strings.TrimSpace(req.ResourceType), session.IdentityID); err != nil {
		s.errorResponse(w, http.StatusBadRequest, err)
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]string{"status": "bound"})
}

func (s *Server) handlePolicySimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	session, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.policy == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Policy service not available")
		return
	}
	var req PolicySimulateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid request body")
		return
	}
	if strings.TrimSpace(req.PolicyID) != "" {
		if _, err := s.policy.Get(r.Context(), types.ID(strings.TrimSpace(req.PolicyID))); err != nil {
			s.errorResponse(w, http.StatusNotFound, err)
			return
		}
	}
	result, err := s.policy.Simulate(r.Context(), policy.EvaluationRequest{
		ActorID:      session.IdentityID,
		ResourceID:   types.ID(strings.TrimSpace(req.ResourceID)),
		ResourceType: strings.TrimSpace(req.ResourceType),
		Action:       strings.TrimSpace(req.Action),
		Context:      req.Context,
	})
	if err != nil {
		s.errorResponse(w, http.StatusBadRequest, err)
		return
	}
	s.jsonResponse(w, http.StatusOK, result)
}

func (s *Server) handlePolicyFreeze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	_, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.policy == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Policy service not available")
		return
	}
	s.policy.Freeze()
	s.jsonResponse(w, http.StatusOK, map[string]string{"status": "frozen"})
}

func (s *Server) handleShares(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.share == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Share service not available")
		return
	}
	switch r.Method {
	case http.MethodGet:
		list, err := s.share.ListShares(r.Context(), share.ListSharesOptions{
			CreatorID:      session.IdentityID,
			RecipientID:    types.ID(strings.TrimSpace(r.URL.Query().Get("recipient_id"))),
			ResourceID:     types.ID(strings.TrimSpace(r.URL.Query().Get("resource_id"))),
			IncludeExpired: strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("include_expired")), "true"),
		})
		if err != nil {
			s.errorResponse(w, http.StatusInternalServerError, err)
			return
		}
		s.jsonResponse(w, http.StatusOK, list)
	case http.MethodPost:
		var req ShareCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid request body")
			return
		}
		typ := strings.ToLower(strings.TrimSpace(req.Type))
		resourceID := strings.TrimSpace(req.ResourceID)
		if err := s.validateShareResourceForAPI(r.Context(), session, typ, resourceID); err != nil {
			s.errorResponse(w, http.StatusBadRequest, err)
			return
		}
		var recipientID *types.ID
		if rid := strings.TrimSpace(req.RecipientID); rid != "" {
			id := types.ID(rid)
			recipientID = &id
		}
		recipientPubKey, err := s.resolveRecipientPubKeyForShareAPI(r.Context(), recipientID, strings.TrimSpace(req.RecipientPubKey))
		if err != nil {
			s.errorResponse(w, http.StatusBadRequest, err)
			return
		}
		created, err := s.share.CreateShare(r.Context(), share.CreateShareOptions{
			Type:            typ,
			ResourceID:      types.ID(resourceID),
			CreatorID:       session.IdentityID,
			RecipientID:     recipientID,
			RecipientPubKey: recipientPubKey,
			ExpiresIn:       req.ExpiresIn,
			MaxAccess:       req.MaxAccess,
			OneTime:         req.OneTime,
		})
		if err != nil {
			s.errorResponse(w, http.StatusBadRequest, err)
			return
		}
		s.jsonResponse(w, http.StatusCreated, created)
	default:
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) handleShareAccept(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	session, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.share == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Share service not available")
		return
	}
	id := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/shares/accept/"))
	if id == "" {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Share ID required")
		return
	}
	result, err := s.share.AccessShare(r.Context(), types.ID(id), session.IdentityID)
	if err != nil {
		s.errorResponse(w, http.StatusBadRequest, err)
		return
	}
	s.jsonResponse(w, http.StatusOK, result)
}

func (s *Server) handleShareRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	session, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.share == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Share service not available")
		return
	}
	id := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/shares/revoke/"))
	if id == "" {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Share ID required")
		return
	}
	if err := s.share.RevokeShare(r.Context(), types.ID(id), session.IdentityID); err != nil {
		s.errorResponse(w, http.StatusBadRequest, err)
		return
	}
	s.jsonResponse(w, http.StatusNoContent, nil)
}

func (s *Server) handleShareExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	session, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.share == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Share service not available")
		return
	}
	id := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/shares/export/"))
	if id == "" {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Share ID required")
		return
	}
	shareRec, err := s.share.GetShare(r.Context(), types.ID(id))
	if err != nil {
		s.errorResponse(w, http.StatusNotFound, err)
		return
	}
	if shareRec.CreatorID != session.IdentityID {
		s.jsonError(w, http.StatusForbidden, types.ErrCodeACLDenied, "only share creator can export this share")
		return
	}
	if len(shareRec.RecipientKey) == 0 {
		recipientPubKey, err := s.resolveRecipientPubKeyForShareAPI(r.Context(), shareRec.RecipientID, "")
		if err != nil {
			s.errorResponse(w, http.StatusBadRequest, err)
			return
		}
		shareRec.RecipientKey = recipientPubKey
	}
	resourceData, err := s.resolveShareResourceDataForAPI(r.Context(), session, shareRec)
	if err != nil {
		s.errorResponse(w, http.StatusBadRequest, err)
		return
	}

	pkg, err := s.share.CreateOfflinePackage(r.Context(), share.OfflinePackageOptions{
		ShareID:         shareRec.ID,
		ResourceData:    resourceData,
		RecipientPubKey: shareRec.RecipientKey,
	})
	if err != nil {
		s.errorResponse(w, http.StatusBadRequest, err)
		return
	}
	exported, err := s.share.ExportOfflinePackage(r.Context(), pkg.ID)
	if err != nil {
		s.errorResponse(w, http.StatusBadRequest, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=share-%s.json", id))
	_, _ = w.Write(exported)
}

func (s *Server) handleShareImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	session, ok := s.requireSession(w, r, "Authentication required")
	if !ok {
		return
	}
	if s.share == nil || s.identity == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "service_unavailable", "Share/identity service not available")
		return
	}
	var req ShareImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid request body")
		return
	}
	var packageData []byte
	if strings.TrimSpace(req.PackageB64) != "" {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PackageB64))
		if err != nil {
			s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid package_b64")
			return
		}
		packageData = decoded
	} else if strings.TrimSpace(req.PackageJSON) != "" {
		packageData = []byte(strings.TrimSpace(req.PackageJSON))
	} else {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "package_b64 or package_json is required")
		return
	}
	if strings.TrimSpace(req.Password) == "" {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "password is required")
		return
	}
	priv, err := s.identity.GetEncryptionPrivateKey(r.Context(), session.IdentityID, req.Password)
	if err != nil {
		s.errorResponse(w, http.StatusBadRequest, err)
		return
	}
	imported, err := s.share.ImportOfflinePackage(r.Context(), packageData, priv)
	if err != nil {
		s.errorResponse(w, http.StatusBadRequest, err)
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]any{
		"share_id":    imported.ShareID,
		"verified":    imported.Verified,
		"imported_at": imported.ImportedAt,
		"data_b64":    base64.StdEncoding.EncodeToString(imported.Data),
	})
}

func (s *Server) resolveRecipientPubKeyForShareAPI(ctx context.Context, recipientID *types.ID, explicitB64 string) ([]byte, error) {
	if strings.TrimSpace(explicitB64) != "" {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(explicitB64))
		if err != nil {
			return nil, fmt.Errorf("invalid recipient_pub_key")
		}
		return decoded, nil
	}
	if recipientID == nil || *recipientID == "" {
		return nil, nil
	}
	if s.identity == nil {
		return nil, fmt.Errorf("identity service not available")
	}
	identity, err := s.identity.GetIdentity(ctx, *recipientID)
	if err != nil {
		return nil, fmt.Errorf("failed to load recipient identity: %w", err)
	}
	pub := identity.PublicKey
	if len(pub) == 0 {
		if encPubStr, ok := identity.Metadata["encryption_public_key"].(string); ok && strings.TrimSpace(encPubStr) != "" {
			decoded, err := base64.StdEncoding.DecodeString(encPubStr)
			if err == nil {
				pub = decoded
			}
		}
	}
	if len(pub) == 0 {
		return nil, fmt.Errorf("recipient public key is required")
	}
	return pub, nil
}

func (s *Server) validateShareResourceForAPI(ctx context.Context, session *types.Session, typ, resourceID string) error {
	if resourceID == "" {
		return fmt.Errorf("resource_id is required")
	}
	switch typ {
	case "secret":
		if s.secrets == nil {
			return fmt.Errorf("secret service not available")
		}
		if _, err := s.secrets.GetMetadata(ctx, resourceID); err != nil {
			return fmt.Errorf("secret resource not found: %s", resourceID)
		}
		return nil
	case "file", "object", "envelope":
		if s.files == nil {
			return fmt.Errorf("file service not available")
		}
		if _, err := s.files.GetMetadata(ctx, resourceID); err != nil {
			return fmt.Errorf("file/object resource not found: %s", resourceID)
		}
		return nil
	case "folder":
		if s.files == nil {
			return fmt.Errorf("file service not available")
		}
		list, err := s.files.List(ctx, files.ListOptions{Prefix: resourceID})
		if err != nil {
			return fmt.Errorf("folder resource not found: %s", resourceID)
		}
		if len(list) == 0 {
			return fmt.Errorf("folder resource not found: %s", resourceID)
		}
		return nil
	default:
		return fmt.Errorf("unsupported share type %q", typ)
	}
}

func (s *Server) resolveShareResourceDataForAPI(ctx context.Context, session *types.Session, shr *types.Share) ([]byte, error) {
	if shr == nil {
		return nil, fmt.Errorf("share is required")
	}
	switch strings.ToLower(strings.TrimSpace(shr.Type)) {
	case "secret":
		if s.secrets == nil {
			return nil, fmt.Errorf("secret service not available")
		}
		mfa := session != nil && session.MFAVerified
		return s.secrets.Get(ctx, string(shr.ResourceID), session.IdentityID, mfa)
	case "file", "object", "envelope":
		if s.files == nil {
			return nil, fmt.Errorf("file service not available")
		}
		var buf bytes.Buffer
		if err := s.files.Download(ctx, string(shr.ResourceID), files.DownloadOptions{
			AccessorID:  session.IdentityID,
			MFAVerified: session != nil && session.MFAVerified,
		}, &buf); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "folder":
		if s.files == nil {
			return nil, fmt.Errorf("file service not available")
		}
		return s.buildFolderArchiveFromFileVault(ctx, session, string(shr.ResourceID))
	default:
		return nil, fmt.Errorf("share export does not support type %q via API yet", shr.Type)
	}
}

func (s *Server) buildFolderArchiveFromFileVault(ctx context.Context, session *types.Session, folder string) ([]byte, error) {
	filesList, err := s.files.List(ctx, files.ListOptions{Prefix: folder})
	if err != nil {
		return nil, err
	}
	if len(filesList) == 0 {
		return nil, fmt.Errorf("folder not found: %s", folder)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	base := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(folder)), "/")
	if base != "" && !strings.HasSuffix(base, "/") {
		base += "/"
	}
	for _, fileMeta := range filesList {
		if fileMeta == nil {
			continue
		}
		var dataBuf bytes.Buffer
		if err := s.files.Download(ctx, fileMeta.Name, files.DownloadOptions{
			AccessorID:  session.IdentityID,
			MFAVerified: session != nil && session.MFAVerified,
		}, &dataBuf); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
		name := filepath.ToSlash(fileMeta.Name)
		name = strings.TrimPrefix(name, base)
		name = strings.TrimPrefix(name, "/")
		if name == "" {
			name = filepath.Base(fileMeta.Name)
		}
		hdr := &tar.Header{Name: name, Mode: 0600, Size: int64(dataBuf.Len())}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
		if _, err := io.Copy(tw, &dataBuf); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *Server) handleCommandDispatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	commandPath := strings.TrimPrefix(r.URL.Path, "/api/v1/commands/")
	commandPath = strings.Trim(commandPath, "/")
	if commandPath == "" {
		s.jsonError(w, http.StatusBadRequest, "invalid_input", "Command path required")
		return
	}

	var payload map[string]any
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			s.jsonError(w, http.StatusBadRequest, "invalid_input", "Invalid request body")
			return
		}
	}

	// Command-specific execution can be expanded incrementally.
	s.jsonResponse(w, http.StatusNotImplemented, map[string]any{
		"status":       "not_implemented",
		"command_path": commandPath,
		"payload":      payload,
	})
}
