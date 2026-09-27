// Package web implements the Velocity v2 "web" plugin: an HTTP API
// gateway exposing KVService and ObjectService over HTTP, plus a
// Prometheus-compatible /metrics endpoint when a metrics plugin is
// present. It uses only the Go standard library's net/http with Go
// 1.22+'s method+wildcard ServeMux patterns (e.g. "GET /api/kv/{key}")
// rather than a third-party router — this keeps the gateway
// dependency-free and, per the plugin's own routeTable (see routes.go),
// makes duplicate route registration a hard error instead of the silent
// bug v1's Fiber-based pkg/web/http_server.go shipped with (POST
// /api/put, GET /api/get/:key, and DELETE /api/delete/:key were each
// registered twice there).
package web

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

	"github.com/oarkflow/velocity/v2/api"
	authsts "github.com/oarkflow/velocity/v2/plugins/auth-sts"
	"github.com/oarkflow/velocity/v2/plugins/s3auth"
)

// Plugin is the web gateway. Auth is optional and looked up
// non-panickingly: a deployment with no auth plugin enabled still boots
// this gateway (for local/dev use), but Start logs a clear one-time
// warning that the API is unauthenticated rather than silently looking
// secure.
type Plugin struct {
	kvDep     string
	objectDep string
	authDep   string

	addr string

	kv      api.KVService
	object  api.ObjectService
	auth    api.AuthProvider   // nil if authDep isn't registered
	metrics api.MetricsSink    // nil if "metrics" isn't registered
	tracer  api.TracingService // nil if "tracing" isn't registered — no span creation, purely additive
	logger  api.Logger

	// s3AccessKey/s3SecretKey enable an alternate AWS4-HMAC-SHA256
	// Authorization scheme alongside the Bearer/JWT path, verified via
	// plugins/s3auth. Both empty (the default) means SigV4 requests are
	// simply rejected — there is no fallback "accept anything" mode.
	s3AccessKey string
	s3SecretKey string

	// tlsCertFile/tlsKeyFile enable TLS when both are set (stdlib
	// crypto/tls only, cross-platform). Both empty (the default) means
	// plain HTTP, unchanged from before TLS support existed. Setting only
	// one is a configuration error, caught at Init.
	tlsCertFile string
	tlsKeyFile  string

	// --- enterprise.go dependencies, all OPTIONAL: nil means the
	// corresponding route group responds 501 Not Implemented rather than
	// panicking or hanging. See OptionalDependencies for why each of
	// these is also listed there (boot-order determinism), and
	// enterprise.go for the routes that use them.
	oidcAuth      api.Authenticator       // "auth.oidc", used by /api/auth/login/oidc
	ldapAuth      api.Authenticator       // "auth.ldap", used by /api/auth/login/ldap
	tokenIssuer   api.TokenIssuer         // "auth.jwt" if it also implements TokenIssuer, used to mint a Bearer token after an OIDC/LDAP login
	sts           *authsts.Plugin         // "auth.sts", concrete type — AssumeRole isn't part of api.AuthProvider, so this is a direct dependency on plugins/auth-sts rather than a registry-interface lookup; a documented, deliberate exception to the usual interface-only pattern
	mfa           api.MFAProvider         // "mfa"
	notifications api.NotificationService // "notifications"
	compliance    api.ComplianceService   // "compliance"
	breakGlass    api.BreakGlassService   // same "compliance" service, type-asserted separately since BreakGlassService is a distinct interface plugins/compliance also happens to implement
	graph         api.GraphStore          // "search.graph"
	iam           api.IAMService          // "iam" — real, persisted policy storage/evaluation (plugins/iam), replacing the earlier in-memory map

	srv        *http.Server
	startedMu  sync.Mutex
	authWarned bool
	startTime  time.Time // set in Start; used by the /admin dashboard's uptime display

	// rateLimiter is nil (disabled) unless "rate_limit_rps" > 0 in config
	// — purely additive, zero behavior change for existing manifests.
	rateLimiter *perClientLimiter
}

// principalContextKey stores the api.Principal produced by a successful
// Bearer/JWT authentication on the request context, so downstream
// enterprise handlers (e.g. break-glass, which requires the caller's own
// identity as the approver) can retrieve it without re-authenticating.
// Only the Bearer path populates this — a SigV4-authenticated request has
// no Principal (SigV4 verifies a request signature, not an identity), so
// routes requiring a Principal correctly treat a SigV4 caller as
// unauthenticated for their purposes.
type principalContextKey struct{}

func principalFromContext(ctx context.Context) (api.Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(api.Principal)
	return p, ok
}

// NewPlugin constructs the web plugin. Empty strings fall back to the
// documented defaults ("kv", "object", "auth.jwt").
func NewPlugin(kvDep, objectDep, authDep string) *Plugin {
	if kvDep == "" {
		kvDep = "kv"
	}
	if objectDep == "" {
		objectDep = "object"
	}
	if authDep == "" {
		authDep = "auth.jwt"
	}
	return &Plugin{kvDep: kvDep, objectDep: objectDep, authDep: authDep}
}

func (p *Plugin) Name() string    { return "web" }
func (p *Plugin) Version() string { return "0.1.0" }

// Dependencies intentionally does NOT include an auth plugin: auth is
// optional and looked up with a non-panicking Lookup in Init, so a
// deployment without any auth plugin enabled still boots this gateway.
// See OptionalDependencies for how boot order with auth plugins is still
// made deterministic when one IS enabled.
func (p *Plugin) Dependencies() []string {
	return []string{p.kvDep, p.objectDep}
}

// OptionalDependencies lists every known auth plugin Name() (not the
// "auth.*" service names used for Registry.Lookup — see
// docs/ARCHITECTURE.md on why those are two different namespaces). The
// kernel Inits any of these first if they happen to be enabled in the
// manifest, and silently skips the rest — this is what makes Init's
// Registry.Lookup(p.authDep) below reliable instead of a boot-order race:
// without this, whether the configured auth plugin has already Provide'd
// its service by the time web's Init runs would depend on Go's
// unspecified map-iteration order over the enabled plugin set.
func (p *Plugin) OptionalDependencies() []string {
	return []string{
		"auth-jwt", "auth-ldap", "auth-oidc", "auth-sts", "metrics",
		// Added for enterprise.go's optional dependencies — same
		// determinism rationale as the entries above: these plugin Names
		// (not the "search.graph"/"compliance"/etc. SERVICE names used
		// for Registry.Lookup below) get boot priority when enabled, and
		// are silently skipped when not.
		"mfa", "notifications", "compliance", "search", "iam", "tracing",
	}
}

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.logger = k.Logger()

	kvSvc, ok := k.Registry().Lookup(p.kvDep)
	if !ok {
		return fmt.Errorf("web: required service %q (kv) not registered", p.kvDep)
	}
	p.kv, ok = kvSvc.(api.KVService)
	if !ok {
		return fmt.Errorf("web: service %q does not implement api.KVService", p.kvDep)
	}

	objSvc, ok := k.Registry().Lookup(p.objectDep)
	if !ok {
		return fmt.Errorf("web: required service %q (object) not registered", p.objectDep)
	}
	p.object, ok = objSvc.(api.ObjectService)
	if !ok {
		return fmt.Errorf("web: service %q does not implement api.ObjectService", p.objectDep)
	}

	if authSvc, ok := k.Registry().Lookup(p.authDep); ok {
		if ap, ok := authSvc.(api.AuthProvider); ok {
			p.auth = ap
		} else {
			p.logger.Warn("web: service registered under auth dependency name does not implement api.AuthProvider, ignoring", "name", p.authDep)
		}
	}

	if mSvc, ok := k.Registry().Lookup("metrics"); ok {
		if ms, ok := mSvc.(api.MetricsSink); ok {
			p.metrics = ms
		}
	}
	if tSvc, ok := k.Registry().Lookup("tracing"); ok {
		if tr, ok := tSvc.(api.TracingService); ok {
			p.tracer = tr
		}
	}

	p.addr = k.Config().Scoped("web").String("addr", ":8090")
	p.s3AccessKey = k.Config().Scoped("web").String("s3_access_key", "")
	p.s3SecretKey = k.Config().Scoped("web").String("s3_secret_key", "")

	p.tlsCertFile = k.Config().Scoped("web").String("tls_cert_file", "")
	p.tlsKeyFile = k.Config().Scoped("web").String("tls_key_file", "")
	if (p.tlsCertFile == "") != (p.tlsKeyFile == "") {
		return fmt.Errorf("web: both tls_cert_file and tls_key_file must be set together (or both left empty for plain HTTP), got cert=%q key=%q", p.tlsCertFile, p.tlsKeyFile)
	}

	// rate_limit_rps == 0 (the default) disables rate limiting entirely —
	// purely additive, zero behavior change for existing manifests.
	if rps := k.Config().Scoped("web").Int("rate_limit_rps", 0); rps > 0 {
		burst := k.Config().Scoped("web").Int("rate_limit_burst", 0)
		if burst <= 0 {
			burst = rps
		}
		p.rateLimiter = newPerClientLimiter(float64(rps), float64(burst))
	}

	if svc, ok := k.Registry().Lookup("auth.oidc"); ok {
		if a, ok := svc.(api.Authenticator); ok {
			p.oidcAuth = a
		}
	}
	if svc, ok := k.Registry().Lookup("auth.ldap"); ok {
		if a, ok := svc.(api.Authenticator); ok {
			p.ldapAuth = a
		}
	}
	if svc, ok := k.Registry().Lookup("auth.jwt"); ok {
		if ti, ok := svc.(api.TokenIssuer); ok {
			p.tokenIssuer = ti
		}
	}
	if svc, ok := k.Registry().Lookup("auth.sts"); ok {
		if s, ok := svc.(*authsts.Plugin); ok {
			p.sts = s
		} else {
			p.logger.Warn("web: service registered under \"auth.sts\" is not *auth-sts.Plugin, AssumeRole route disabled")
		}
	}
	if svc, ok := k.Registry().Lookup("mfa"); ok {
		if m, ok := svc.(api.MFAProvider); ok {
			p.mfa = m
		}
	}
	if svc, ok := k.Registry().Lookup("notifications"); ok {
		if n, ok := svc.(api.NotificationService); ok {
			p.notifications = n
		}
	}
	if svc, ok := k.Registry().Lookup("compliance"); ok {
		if c, ok := svc.(api.ComplianceService); ok {
			p.compliance = c
		}
		if bg, ok := svc.(api.BreakGlassService); ok {
			p.breakGlass = bg
		}
	}
	if svc, ok := k.Registry().Lookup("search.graph"); ok {
		if g, ok := svc.(api.GraphStore); ok {
			p.graph = g
		}
	}
	if svc, ok := k.Registry().Lookup("iam"); ok {
		if i, ok := svc.(api.IAMService); ok {
			p.iam = i
		}
	}

	return nil
}

func (p *Plugin) buildMux() (*routeTable, error) {
	t := newRouteTable()

	t.handle("PUT /api/kv/{key}", p.wrap("PUT", "/api/kv/{key}", p.handleKVPut))
	t.handle("GET /api/kv/{key}", p.wrap("GET", "/api/kv/{key}", p.handleKVGet))
	t.handle("DELETE /api/kv/{key}", p.wrap("DELETE", "/api/kv/{key}", p.handleKVDelete))

	t.handle("PUT /api/buckets/{bucket}", p.wrap("PUT", "/api/buckets/{bucket}", p.handleBucketCreate))
	t.handle("PUT /api/buckets/{bucket}/objects/{key}", p.wrap("PUT", "/api/buckets/{bucket}/objects/{key}", p.handleObjectPut))
	t.handle("GET /api/buckets/{bucket}/objects/{key}", p.wrap("GET", "/api/buckets/{bucket}/objects/{key}", p.handleObjectGet))
	t.handle("HEAD /api/buckets/{bucket}/objects/{key}", p.wrap("HEAD", "/api/buckets/{bucket}/objects/{key}", p.handleObjectHead))
	t.handle("DELETE /api/buckets/{bucket}/objects/{key}", p.wrap("DELETE", "/api/buckets/{bucket}/objects/{key}", p.handleObjectDelete))
	t.handle("GET /api/buckets/{bucket}/objects", p.wrap("GET", "/api/buckets/{bucket}/objects", p.handleObjectList))
	t.handle("PUT /api/buckets/{bucket}/objects/{key}/copy", p.wrap("PUT", "/api/buckets/{bucket}/objects/{key}/copy", p.handleObjectCopy))

	t.handle("POST /api/buckets/{bucket}/objects/{key}/uploads", p.wrap("POST", "/api/buckets/{bucket}/objects/{key}/uploads", p.handleMultipartInitiate))
	t.handle("PUT /api/buckets/{bucket}/objects/{key}/uploads/{uploadID}/{partNumber}", p.wrap("PUT", "/api/buckets/{bucket}/objects/{key}/uploads/{uploadID}/{partNumber}", p.handleMultipartUploadPart))
	t.handle("POST /api/buckets/{bucket}/objects/{key}/uploads/{uploadID}/complete", p.wrap("POST", "/api/buckets/{bucket}/objects/{key}/uploads/{uploadID}/complete", p.handleMultipartComplete))
	t.handle("DELETE /api/buckets/{bucket}/objects/{key}/uploads/{uploadID}", p.wrap("DELETE", "/api/buckets/{bucket}/objects/{key}/uploads/{uploadID}", p.handleMultipartAbort))

	t.handle("GET /api/watch", p.wrap("GET", "/api/watch", p.handleWatch))

	// --- enterprise.go routes (auth login/STS/MFA, IAM, lifecycle,
	// notifications, compliance, break-glass, KG) ---
	t.handle("POST /api/auth/login/oidc", p.wrap("POST", "/api/auth/login/oidc", p.handleLoginOIDC))
	t.handle("POST /api/auth/login/ldap", p.wrap("POST", "/api/auth/login/ldap", p.handleLoginLDAP))
	t.handle("POST /api/auth/sts/assume-role", p.wrap("POST", "/api/auth/sts/assume-role", p.handleSTSAssumeRole))
	t.handle("POST /api/auth/mfa/enroll", p.wrap("POST", "/api/auth/mfa/enroll", p.handleMFAEnroll))
	t.handle("POST /api/auth/mfa/validate", p.wrap("POST", "/api/auth/mfa/validate", p.handleMFAValidate))

	t.handle("GET /api/iam/policies/{name}", p.wrap("GET", "/api/iam/policies/{name}", p.handleIAMPolicyGet))
	t.handle("PUT /api/iam/policies/{name}", p.wrap("PUT", "/api/iam/policies/{name}", p.handleIAMPolicyPut))
	t.handle("DELETE /api/iam/policies/{name}", p.wrap("DELETE", "/api/iam/policies/{name}", p.handleIAMPolicyDelete))
	t.handle("GET /api/iam/policies", p.wrap("GET", "/api/iam/policies", p.handleIAMPolicyList))
	t.handle("POST /api/iam/policies/{name}/attach", p.wrap("POST", "/api/iam/policies/{name}/attach", p.handleIAMAttach))
	t.handle("POST /api/iam/policies/{name}/detach", p.wrap("POST", "/api/iam/policies/{name}/detach", p.handleIAMDetach))
	t.handle("POST /api/iam/evaluate", p.wrap("POST", "/api/iam/evaluate", p.handleIAMEvaluate))

	t.handle("PUT /api/buckets/{bucket}/lifecycle", p.wrap("PUT", "/api/buckets/{bucket}/lifecycle", p.handleBucketLifecycle))

	t.handle("POST /api/notifications/rules", p.wrap("POST", "/api/notifications/rules", p.handleNotificationRuleCreate))
	t.handle("GET /api/notifications/rules", p.wrap("GET", "/api/notifications/rules", p.handleNotificationRuleList))
	t.handle("DELETE /api/notifications/rules/{id}", p.wrap("DELETE", "/api/notifications/rules/{id}", p.handleNotificationRuleDelete))

	t.handle("GET /api/compliance/classification/{resource}", p.wrap("GET", "/api/compliance/classification/{resource}", p.handleClassificationGet))
	t.handle("PUT /api/compliance/classification/{resource}", p.wrap("PUT", "/api/compliance/classification/{resource}", p.handleClassificationPut))
	t.handle("GET /api/compliance/violations", p.wrap("GET", "/api/compliance/violations", p.handleViolationsList))
	t.handle("POST /api/compliance/rulepacks", p.wrap("POST", "/api/compliance/rulepacks", p.handleRulePackImport))

	t.handle("POST /api/breakglass/grant", p.wrap("POST", "/api/breakglass/grant", p.handleBreakGlassGrant))
	t.handle("POST /api/breakglass/revoke/{id}", p.wrap("POST", "/api/breakglass/revoke/{id}", p.handleBreakGlassRevoke))

	t.handle("POST /api/kg/entities", p.wrap("POST", "/api/kg/entities", p.handleKGEntity))
	t.handle("POST /api/kg/relations", p.wrap("POST", "/api/kg/relations", p.handleKGRelation))
	t.handle("GET /api/kg/traverse/{start}", p.wrap("GET", "/api/kg/traverse/{start}", p.handleKGTraverse))

	// /metrics is intentionally never wrapped in the JWT auth middleware —
	// scrapers don't carry bearer tokens. It has no [meaningful] secrets of
	// its own; deployments needing this locked down should front it with a
	// network-level ACL, same as most Prometheus deployments do.
	t.handle("GET /metrics", p.handleMetrics)

	// /healthz and /readyz are intentionally never wrapped in auth or rate
	// limiting — orchestrator liveness/readiness probes must not depend on
	// a bearer token or be starved by unrelated traffic exhausting a rate
	// limit; deployments needing these locked down should front them with
	// a network-level ACL, same as /metrics above.
	t.handle("GET /healthz", p.handleHealthz)
	t.handle("GET /readyz", p.handleReadyz)

	// /admin IS wrapped with p.wrap (auth + rate-limit, same as every
	// /api/* route) — unlike /metrics/healthz/readyz, this is an
	// operational dashboard that can reveal plugin configuration details,
	// so it must not be accidentally exposed unauthenticated just because
	// the rest of the gateway happens to be locked down.
	t.handle("GET /admin", p.wrap("GET", "/admin", p.handleAdmin))
	t.handle("GET /admin/", p.wrap("GET", "/admin/", p.handleAdminRedirect))

	if err := t.err(); err != nil {
		return nil, err
	}
	return t, nil
}

func (p *Plugin) Start(ctx context.Context) error {
	t, err := p.buildMux()
	if err != nil {
		return err
	}

	if p.auth == nil && !p.authWarned {
		p.authWarned = true
		p.logger.Warn("web: no auth provider registered, /api routes are UNAUTHENTICATED — this is not secure for anything but local/dev use")
	}

	p.startTime = time.Now()

	p.startedMu.Lock()
	p.srv = &http.Server{Addr: p.addr, Handler: t.mux}
	srv := p.srv
	p.startedMu.Unlock()

	errCh := make(chan error, 1)
	go func() {
		var err error
		if p.tlsCertFile != "" {
			err = srv.ListenAndServeTLS(p.tlsCertFile, p.tlsKeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("web: listen: %w", err)
	case <-time.After(50 * time.Millisecond):
		return nil
	}
}

func (p *Plugin) Stop(ctx context.Context) error {
	p.startedMu.Lock()
	srv := p.srv
	p.startedMu.Unlock()
	if srv == nil {
		return nil
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func (p *Plugin) Health() api.Health {
	if p.srv == nil {
		return api.Health{Status: "down", Detail: "not started"}
	}
	return api.Health{Status: "ok"}
}

var _ api.Plugin = (*Plugin)(nil)

// --- auth + metrics middleware ---

// wrap applies (outermost to innermost) tracing, the rate limiter, the
// metrics-recording wrapper, and, if an AuthProvider is registered, the
// bearer-token auth check, around a route handler. Tracing is outermost so
// a single span covers the whole request — including a rate-limit
// rejection or an auth failure, both of which are useful to see in a
// trace, not just successful requests. route is the raw pattern (for
// metrics/span labels), not the request path.
func (p *Plugin) wrap(method, route string, h http.HandlerFunc) http.HandlerFunc {
	handler := h
	if p.auth != nil {
		handler = p.requireAuth(handler)
	}
	handler = p.recordMetrics(method, route, handler)
	if p.rateLimiter != nil {
		handler = p.rateLimitMiddleware(handler)
	}
	if p.tracer != nil {
		handler = p.traceRequest(method, route, handler)
	}
	return handler
}

// traceRequest starts a span named "method route" for the whole request,
// tags it with method/route/status attributes, and records an error on
// the span if the handler responded with a non-2xx status — so a slow or
// failing request is visible in a trace, not just a log line. A nil
// p.tracer means this middleware is never applied (see wrap), so this is
// purely additive when no "tracing" plugin is enabled.
func (p *Plugin) traceRequest(method, route string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, end := p.tracer.StartSpan(r.Context(), method+" "+route)
		defer end()
		p.tracer.SetAttribute(ctx, "http.method", method)
		p.tracer.SetAttribute(ctx, "http.route", route)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next(rec, r.WithContext(ctx))

		p.tracer.SetAttribute(ctx, "http.status_code", rec.status)
		if rec.status >= 400 {
			p.tracer.RecordError(ctx, fmt.Errorf("web: %s %s responded %d", method, route, rec.status))
		}
	}
}

// requireAuth accepts EITHER a Bearer/JWT token (checked via the
// registered AuthProvider) OR, if s3_access_key/s3_secret_key are
// configured, an AWS4-HMAC-SHA256 Authorization header or presigned-URL
// query string (checked via plugins/s3auth) — one request can use either
// scheme, they are not mutually exclusive across the gateway. A SigV4
// request is rejected outright if no S3 keys are configured; it never
// silently falls through as unauthenticated.
func (p *Plugin) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		isSigV4 := strings.HasPrefix(authz, "AWS4-HMAC-SHA256 ") || r.URL.Query().Get("X-Amz-Algorithm") != ""
		if isSigV4 {
			if p.s3AccessKey == "" || p.s3SecretKey == "" {
				http.Error(w, "SigV4 authentication is not configured on this gateway", http.StatusUnauthorized)
				return
			}
			if err := s3auth.Verify(r, p.s3AccessKey, p.s3SecretKey); err != nil {
				http.Error(w, "invalid SigV4 signature: "+err.Error(), http.StatusUnauthorized)
				return
			}
			next(w, r)
			return
		}

		const prefix = "Bearer "
		if !strings.HasPrefix(authz, prefix) {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authz, prefix)
		principal, err := p.auth.Authenticate(r.Context(), token)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next(w, r.WithContext(ctx))
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (p *Plugin) recordMetrics(method, route string, next http.HandlerFunc) http.HandlerFunc {
	if p.metrics == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next(rec, r)
		labels := map[string]string{"method": method, "route": route, "status": strconv.Itoa(rec.status)}
		p.metrics.Counter("http_requests_total", labels).Inc()
		p.metrics.Histogram("http_request_duration_seconds", map[string]string{"route": route}).Observe(time.Since(start).Seconds())
	}
}

// --- handlers ---

func (p *Plugin) handleKVPut(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := p.kv.Put(r.Context(), key, body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *Plugin) handleKVGet(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	val, ok, err := p.kv.Get(r.Context(), key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Write(val)
}

func (p *Plugin) handleKVDelete(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if err := p.kv.Delete(r.Context(), key); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *Plugin) handleBucketCreate(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	if err := p.object.CreateBucket(r.Context(), bucket); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (p *Plugin) handleObjectPut(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	key := r.PathValue("key")
	meta := api.ObjectMeta{Bucket: bucket, Key: key, ContentType: r.Header.Get("Content-Type")}
	out, err := p.object.PutObject(r.Context(), bucket, key, r.Body, meta)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("ETag", out.ETag)
	w.Header().Set("X-Version-Id", out.VersionID)
	w.WriteHeader(http.StatusCreated)
}

func (p *Plugin) handleObjectGet(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	key := r.PathValue("key")
	versionID := r.URL.Query().Get("versionId")

	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		start, end, ok := parseByteRange(rangeHeader)
		if !ok {
			http.Error(w, "invalid Range header", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		body, meta, err := p.object.GetObjectRange(r.Context(), bucket, key, versionID, start, end)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestedRangeNotSatisfiable)
			return
		}
		defer body.Close()
		if meta.ContentType != "" {
			w.Header().Set("Content-Type", meta.ContentType)
		}
		w.Header().Set("ETag", meta.ETag)
		endStr := "*"
		if end != -1 {
			endStr = strconv.FormatInt(end, 10)
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%s/%d", start, endStr, meta.Size))
		w.WriteHeader(http.StatusPartialContent)
		io.Copy(w, body)
		return
	}

	body, meta, err := p.object.GetObject(r.Context(), bucket, key, versionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	defer body.Close()
	if meta.ContentType != "" {
		w.Header().Set("Content-Type", meta.ContentType)
	}
	w.Header().Set("ETag", meta.ETag)
	io.Copy(w, body)
}

// parseByteRange parses a single-range "bytes=start-end" Range header.
// end == -1 in the return means "to EOF" (an open-ended range like
// "bytes=100-"). Multi-range requests ("bytes=0-10,20-30") are not
// supported and report ok == false.
func parseByteRange(header string) (start, end int64, ok bool) {
	const prefix = "bytes="
	if !strings.HasPrefix(header, prefix) {
		return 0, 0, false
	}
	spec := strings.TrimPrefix(header, prefix)
	if strings.Contains(spec, ",") {
		return 0, 0, false
	}
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	s, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	if parts[1] == "" {
		return s, -1, true
	}
	e, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return s, e, true
}

func (p *Plugin) handleObjectHead(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	key := r.PathValue("key")
	versionID := r.URL.Query().Get("versionId")
	meta, err := p.object.HeadObject(r.Context(), bucket, key, versionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if meta.ContentType != "" {
		w.Header().Set("Content-Type", meta.ContentType)
	}
	w.Header().Set("ETag", meta.ETag)
	w.Header().Set("X-Version-Id", meta.VersionID)
	w.Header().Set("Content-Length", strconv.FormatInt(meta.Size, 10))
}

// handleObjectCopy expects an "X-Copy-Source: <bucket>/<key>" header
// (optionally "?versionId=..." appended), mirroring S3's
// x-amz-copy-source convention.
func (p *Plugin) handleObjectCopy(w http.ResponseWriter, r *http.Request) {
	dstBucket := r.PathValue("bucket")
	dstKey := r.PathValue("key")

	src := r.Header.Get("X-Copy-Source")
	if src == "" {
		http.Error(w, "missing X-Copy-Source header", http.StatusBadRequest)
		return
	}
	srcBucket, srcKeyAndVersion, found := strings.Cut(strings.TrimPrefix(src, "/"), "/")
	if !found {
		http.Error(w, "X-Copy-Source must be \"<bucket>/<key>\"", http.StatusBadRequest)
		return
	}
	srcKey, srcVersionID, _ := strings.Cut(srcKeyAndVersion, "?versionId=")

	meta, err := p.object.CopyObject(r.Context(), srcBucket, srcKey, srcVersionID, dstBucket, dstKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("ETag", meta.ETag)
	w.Header().Set("X-Version-Id", meta.VersionID)
	w.WriteHeader(http.StatusOK)
}

func (p *Plugin) handleMultipartInitiate(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	key := r.PathValue("key")
	uploadID, err := p.object.InitiateMultipart(r.Context(), bucket, key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"uploadId": uploadID})
}

func (p *Plugin) handleMultipartUploadPart(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	key := r.PathValue("key")
	uploadID := r.PathValue("uploadID")
	partNumber, err := strconv.Atoi(r.PathValue("partNumber"))
	if err != nil {
		http.Error(w, "invalid part number", http.StatusBadRequest)
		return
	}
	etag, err := p.object.UploadPart(r.Context(), bucket, key, uploadID, partNumber, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("ETag", etag)
}

func (p *Plugin) handleMultipartComplete(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	key := r.PathValue("key")
	uploadID := r.PathValue("uploadID")

	var body struct {
		Parts []api.PartInfo `json:"parts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	meta, err := p.object.CompleteMultipart(r.Context(), bucket, key, uploadID, body.Parts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", meta.ETag)
	w.Header().Set("X-Version-Id", meta.VersionID)
	json.NewEncoder(w).Encode(meta)
}

func (p *Plugin) handleMultipartAbort(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	key := r.PathValue("key")
	uploadID := r.PathValue("uploadID")
	if err := p.object.AbortMultipart(r.Context(), bucket, key, uploadID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *Plugin) handleObjectDelete(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	key := r.PathValue("key")
	versionID := r.URL.Query().Get("versionId")
	bypass := r.URL.Query().Get("bypassGovernance") == "true"
	if err := p.object.DeleteObject(r.Context(), bucket, key, versionID, bypass); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *Plugin) handleObjectList(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	prefix := r.URL.Query().Get("prefix")
	items, err := p.object.ListObjects(r.Context(), bucket, prefix)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

// handleWatch streams api.ChangeEvents from either the "kv" or "object"
// service as Server-Sent Events, selected via ?source=kv|object (default
// "kv") and filtered by ?prefix=<prefix> (default ""). It requires the
// looked-up service to implement api.Watchable; if it doesn't, that's
// reported as a 501 rather than the request hanging forever.
func (p *Plugin) handleWatch(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	if source == "" {
		source = "kv"
	}
	prefix := r.URL.Query().Get("prefix")

	var watchable api.Watchable
	switch source {
	case "kv":
		if wk, ok := p.kv.(api.Watchable); ok {
			watchable = wk
		}
	case "object":
		if wo, ok := p.object.(api.Watchable); ok {
			watchable = wo
		}
	default:
		http.Error(w, `source must be "kv" or "object"`, http.StatusBadRequest)
		return
	}
	if watchable == nil {
		http.Error(w, fmt.Sprintf("source %q does not support watching", source), http.StatusNotImplemented)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	ch, handle, err := watchable.Watch(ctx, prefix)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer handle.Close()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			body, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", body)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (p *Plugin) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if p.metrics == nil {
		http.Error(w, "metrics plugin not registered", http.StatusNotFound)
		return
	}
	body, contentType := p.metrics.Expose()
	w.Header().Set("Content-Type", contentType)
	w.Write(body)
}
