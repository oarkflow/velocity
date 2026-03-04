// Package api provides the REST API server.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/alerts"
	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/core/cicd"
	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/core/files"
	"github.com/oarkflow/velocity/internal/secretr/core/identity"
	"github.com/oarkflow/velocity/internal/secretr/core/monitoring"
	"github.com/oarkflow/velocity/internal/secretr/core/secrets"
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
		crypto:      crypto.NewEngine(""),
		mux:         http.NewServeMux(),
		rateLimiter: NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst),
		certFile:    cfg.CertFile,
		keyFile:     cfg.KeyFile,
	}

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
	// Health check
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/ready", s.handleReady)

	// Auth endpoints
	s.mux.HandleFunc("/api/v1/auth/login", s.withMiddleware(s.handleLogin))
	s.mux.HandleFunc("/api/v1/auth/logout", s.withMiddleware(s.handleLogout))
	s.mux.HandleFunc("/api/v1/auth/refresh", s.withMiddleware(s.handleRefresh))

	// Secret endpoints
	s.mux.HandleFunc("/api/v1/secrets", s.withMiddleware(s.handleSecrets))
	s.mux.HandleFunc("/api/v1/secrets/", s.withMiddleware(s.handleSecret))

	// Identity endpoints
	s.mux.HandleFunc("/api/v1/identities", s.withMiddleware(s.handleIdentities))
	s.mux.HandleFunc("/api/v1/identities/", s.withMiddleware(s.handleIdentity))

	// Audit endpoints
	s.mux.HandleFunc("/api/v1/audit", s.withMiddleware(s.handleAuditQuery))
	s.mux.HandleFunc("/api/v1/audit/export", s.withMiddleware(s.handleAuditExport))

	// CICD endpoints
	s.mux.HandleFunc("/api/v1/cicd/auth", s.handlePipelineAuth)

	// File endpoints
	s.mux.HandleFunc("/api/v1/files", s.withMiddleware(s.handleFiles))
	s.mux.HandleFunc("/api/v1/files/", s.withMiddleware(s.handleFile))

	// Monitoring endpoints
	s.mux.HandleFunc("/api/v1/monitoring/dashboard", s.withMiddleware(s.handleDashboard))
	s.mux.HandleFunc("/api/v1/monitoring/events", s.withMiddleware(s.handleMonitoringEvents))
	s.mux.HandleFunc("/api/v1/monitoring/stream", s.withMiddleware(s.handleMonitoringStream))

	// Alert endpoints
	s.mux.HandleFunc("/api/v1/alerts", s.withMiddleware(s.handleAlerts))
	s.mux.HandleFunc("/api/v1/alerts/", s.withMiddleware(s.handleAlert))
	s.mux.HandleFunc("/api/v1/alerts/rules", s.withMiddleware(s.handleAlertRules))
	s.mux.HandleFunc("/api/v1/alerts/notifiers", s.withMiddleware(s.handleAlertNotifiers))

	// Generic command-dispatch endpoint for CLI/API parity.
	s.mux.HandleFunc("/api/v1/commands/", s.withMiddleware(s.handleCommandDispatch))
}

// withMiddleware wraps handlers with common middleware
func (s *Server) withMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// CORS
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Rate limiting
		clientIP := getClientIP(r)
		if !s.rateLimiter.Allow(clientIP) {
			s.jsonError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests")
			return
		}

		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		handler(w, r)
	}
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

	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Not authenticated")
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

	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Not authenticated")
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
	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Not authenticated")
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
	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Not authenticated")
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

	if !session.Scopes.Has(types.ScopeSecretList) {
		s.jsonError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
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

	if !session.Scopes.Has(types.ScopeSecretCreate) {
		s.jsonError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
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

	if !session.Scopes.Has(types.ScopeSecretRead) {
		s.jsonError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
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

	if !session.Scopes.Has(types.ScopeSecretUpdate) {
		s.jsonError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
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

	if !session.Scopes.Has(types.ScopeSecretDelete) {
		s.jsonError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
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
	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Not authenticated")
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
	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Not authenticated")
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
	if !session.Scopes.Has(types.ScopeIdentityRead) {
		s.jsonError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
		return
	}

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
	if !session.Scopes.Has(types.ScopeIdentityRead) {
		s.jsonError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
		return
	}

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

	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Not authenticated")
		return
	}

	if !session.Scopes.Has(types.ScopeAuditQuery) {
		s.jsonError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
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

	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Not authenticated")
		return
	}

	if !session.Scopes.Has(types.ScopeAuditExport) {
		s.jsonError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
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
	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Not authenticated")
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
	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Not authenticated")
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

	if !session.Scopes.Has(types.ScopeFileList) {
		s.jsonError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
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

	if !session.Scopes.Has(types.ScopeFileUpload) {
		s.jsonError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
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

	if !session.Scopes.Has(types.ScopeFileDownload) {
		s.jsonError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
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
	if !session.Scopes.Has(types.ScopeFileDelete) {
		s.jsonError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
		return
	}

	err := s.files.Delete(r.Context(), name, session.IdentityID)
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, err)
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleFileProtect(w http.ResponseWriter, r *http.Request, session *types.Session, name string) {
	if !session.Scopes.Has(types.ScopeFileSeal) {
		s.jsonError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
		return
	}

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
	if !session.Scopes.Has(types.ScopeFileDelete) {
		s.jsonError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
		return
	}

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
	if !session.Scopes.Has(types.ScopeFileDelete) {
		s.jsonError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
		return
	}

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

	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
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

	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
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

	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
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
	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
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
	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
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
	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
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
	session := s.getSession(r)
	if session == nil {
		s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
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

	// Keep auth commands callable without a session to mirror CLI behavior.
	if !strings.HasPrefix(commandPath, "auth/") {
		if session := s.getSession(r); session == nil {
			s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Not authenticated")
			return
		}
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
