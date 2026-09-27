// This file implements the "enterprise" HTTP surface v1's pkg/web/
// enterprise_api.go had: OIDC/LDAP login, STS assume-role, MFA, a minimal
// IAM policy store, bucket lifecycle configuration, notification-rule
// management, compliance (classification/violations/rule-packs), and
// break-glass grant/revoke. Every dependency here is OPTIONAL — a
// deployment that hasn't enabled the corresponding plugin gets a clear
// 501 Not Implemented on that route group instead of a panic or a hang.
package web

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	authldap "github.com/oarkflow/velocity/v2/plugins/auth-ldap"
	authoidc "github.com/oarkflow/velocity/v2/plugins/auth-oidc"
	authsts "github.com/oarkflow/velocity/v2/plugins/auth-sts"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, v)
}

// --- auth login / STS / MFA ---

type loginRequest struct {
	// OIDC: either an authorization code to exchange or a raw ID token to
	// verify directly (the auth-oidc plugin's Authenticate distinguishes
	// these by which field is set). LDAP: username/password.
	Code     string `json:"code,omitempty"`
	IDToken  string `json:"idToken,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type loginResponse struct {
	Token     string        `json:"token,omitempty"`
	Principal api.Principal `json:"principal"`
}

// handleLoginOIDC authenticates via the looked-up "auth.oidc" provider,
// then — if "auth.jwt" is registered and also implements api.TokenIssuer
// — mints a Bearer token for the resulting Principal so the caller can
// immediately use it against this gateway's other /api/* routes. If no
// TokenIssuer is available, the bare Principal is still returned rather
// than failing the whole request: issuing a follow-on token is a
// convenience bridge, not a requirement of a successful login.
//
// api.Authenticator.Authenticate takes `credential any` and each provider
// type-asserts it to ITS OWN concrete credential type (authoidc.Credential
// here) — there is no generic credential shape in v2/api, so building the
// right one requires importing that concrete type. This is a narrow,
// deliberate exception to the interface-only dependency pattern used
// everywhere else in this gateway (same rationale as the auth-sts import
// above): it only reaches into these packages for a plain data struct,
// never their lifecycle/internals.
func (p *Plugin) handleLoginOIDC(w http.ResponseWriter, r *http.Request) {
	if p.oidcAuth == nil {
		http.Error(w, "auth.oidc is not configured on this gateway", http.StatusNotImplemented)
		return
	}
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	cred := authoidc.Credential{Code: req.Code, IDToken: req.IDToken}
	principal, err := p.oidcAuth.Authenticate(r.Context(), cred)
	if err != nil {
		http.Error(w, "authentication failed: "+err.Error(), http.StatusUnauthorized)
		return
	}
	p.respondLogin(w, r, principal)
}

// handleLoginLDAP mirrors handleLoginOIDC for the "auth.ldap" provider.
func (p *Plugin) handleLoginLDAP(w http.ResponseWriter, r *http.Request) {
	if p.ldapAuth == nil {
		http.Error(w, "auth.ldap is not configured on this gateway", http.StatusNotImplemented)
		return
	}
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	cred := authldap.Credential{Username: req.Username, Password: req.Password}
	principal, err := p.ldapAuth.Authenticate(r.Context(), cred)
	if err != nil {
		http.Error(w, "authentication failed: "+err.Error(), http.StatusUnauthorized)
		return
	}
	p.respondLogin(w, r, principal)
}

func (p *Plugin) respondLogin(w http.ResponseWriter, r *http.Request, principal api.Principal) {
	resp := loginResponse{Principal: principal}
	if p.tokenIssuer != nil {
		token, err := p.tokenIssuer.IssueToken(r.Context(), principal.Subject, principal.Roles, 1*time.Hour)
		if err == nil {
			resp.Token = token
		} else {
			p.logger.Warn("web: login succeeded but token issuance failed, returning principal only", "err", err)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSTSAssumeRole is a direct dependency on the concrete
// *auth-sts.Plugin type (imported from plugins/auth-sts), not a
// registry-interface lookup — AssumeRole isn't part of api.AuthProvider
// (assuming a role is an administrative action on an already-established
// or federated identity, not "authenticate a credential"), so there is no
// interface in v2/api to look it up through. This is a deliberate,
// documented exception to the usual interface-only dependency pattern
// used everywhere else in this gateway.
func (p *Plugin) handleSTSAssumeRole(w http.ResponseWriter, r *http.Request) {
	if p.sts == nil {
		http.Error(w, "auth.sts is not configured on this gateway", http.StatusNotImplemented)
		return
	}
	var req authsts.AssumeRoleRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	result, err := p.sts.AssumeRole(r.Context(), req)
	if err != nil {
		http.Error(w, "assume-role failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (p *Plugin) handleMFAEnroll(w http.ResponseWriter, r *http.Request) {
	if p.mfa == nil {
		http.Error(w, "mfa is not configured on this gateway", http.StatusNotImplemented)
		return
	}
	var req struct {
		Subject string `json:"subject"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Subject == "" {
		http.Error(w, "request body must be {\"subject\": \"...\"}", http.StatusBadRequest)
		return
	}
	secret, err := p.mfa.GenerateSecret(r.Context(), req.Subject)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret})
}

func (p *Plugin) handleMFAValidate(w http.ResponseWriter, r *http.Request) {
	if p.mfa == nil {
		http.Error(w, "mfa is not configured on this gateway", http.StatusNotImplemented)
		return
	}
	var req struct {
		Subject string `json:"subject"`
		Code    string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Subject == "" || req.Code == "" {
		http.Error(w, "request body must be {\"subject\": \"...\", \"code\": \"...\"}", http.StatusBadRequest)
		return
	}
	ok, err := p.mfa.ValidateCode(r.Context(), req.Subject, req.Code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"valid": ok})
}

// --- IAM (real, persisted — plugins/iam, looked up as "iam") ---

func (p *Plugin) handleIAMPolicyGet(w http.ResponseWriter, r *http.Request) {
	if p.iam == nil {
		http.Error(w, "iam plugin not configured", http.StatusNotImplemented)
		return
	}
	name := r.PathValue("name")
	pol, err := p.iam.GetPolicy(r.Context(), name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, pol)
}

func (p *Plugin) handleIAMPolicyPut(w http.ResponseWriter, r *http.Request) {
	if p.iam == nil {
		http.Error(w, "iam plugin not configured", http.StatusNotImplemented)
		return
	}
	name := r.PathValue("name")
	var pol api.IAMPolicy
	if err := decodeJSON(r, &pol); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := p.iam.PutPolicy(r.Context(), name, pol); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *Plugin) handleIAMPolicyDelete(w http.ResponseWriter, r *http.Request) {
	if p.iam == nil {
		http.Error(w, "iam plugin not configured", http.StatusNotImplemented)
		return
	}
	if err := p.iam.DeletePolicy(r.Context(), r.PathValue("name")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *Plugin) handleIAMPolicyList(w http.ResponseWriter, r *http.Request) {
	if p.iam == nil {
		http.Error(w, "iam plugin not configured", http.StatusNotImplemented)
		return
	}
	names, err := p.iam.ListPolicies(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, names)
}

type iamAttachRequest struct {
	Subject string `json:"subject"`
}

func (p *Plugin) handleIAMAttach(w http.ResponseWriter, r *http.Request) {
	if p.iam == nil {
		http.Error(w, "iam plugin not configured", http.StatusNotImplemented)
		return
	}
	var req iamAttachRequest
	if err := decodeJSON(r, &req); err != nil || req.Subject == "" {
		http.Error(w, `request body must be {"subject": "..."}`, http.StatusBadRequest)
		return
	}
	if err := p.iam.AttachPolicy(r.Context(), req.Subject, r.PathValue("name")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *Plugin) handleIAMDetach(w http.ResponseWriter, r *http.Request) {
	if p.iam == nil {
		http.Error(w, "iam plugin not configured", http.StatusNotImplemented)
		return
	}
	var req iamAttachRequest
	if err := decodeJSON(r, &req); err != nil || req.Subject == "" {
		http.Error(w, `request body must be {"subject": "..."}`, http.StatusBadRequest)
		return
	}
	if err := p.iam.DetachPolicy(r.Context(), req.Subject, r.PathValue("name")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type iamEvaluateRequest struct {
	Subject  string `json:"subject"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

type iamEvaluateResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

func (p *Plugin) handleIAMEvaluate(w http.ResponseWriter, r *http.Request) {
	if p.iam == nil {
		http.Error(w, "iam plugin not configured", http.StatusNotImplemented)
		return
	}
	var req iamEvaluateRequest
	if err := decodeJSON(r, &req); err != nil || req.Subject == "" || req.Action == "" {
		http.Error(w, `request body must be {"subject": "...", "action": "...", "resource": "..."}`, http.StatusBadRequest)
		return
	}
	allowed, reason, err := p.iam.Evaluate(r.Context(), req.Subject, req.Action, req.Resource)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, iamEvaluateResponse{Allowed: allowed, Reason: reason})
}

// --- lifecycle ---

func (p *Plugin) handleBucketLifecycle(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	var rules []api.LifecycleRule
	if err := decodeJSON(r, &rules); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := p.object.SetLifecycle(r.Context(), bucket, rules); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- notifications ---

func (p *Plugin) handleNotificationRuleCreate(w http.ResponseWriter, r *http.Request) {
	if p.notifications == nil {
		http.Error(w, "notifications is not configured on this gateway", http.StatusNotImplemented)
		return
	}
	var rule api.NotificationRule
	if err := decodeJSON(r, &rule); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := p.notifications.AddRule(r.Context(), rule); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (p *Plugin) handleNotificationRuleList(w http.ResponseWriter, r *http.Request) {
	if p.notifications == nil {
		http.Error(w, "notifications is not configured on this gateway", http.StatusNotImplemented)
		return
	}
	rules, err := p.notifications.ListRules(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

func (p *Plugin) handleNotificationRuleDelete(w http.ResponseWriter, r *http.Request) {
	if p.notifications == nil {
		http.Error(w, "notifications is not configured on this gateway", http.StatusNotImplemented)
		return
	}
	id := r.PathValue("id")
	if err := p.notifications.RemoveRule(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- compliance ---

func (p *Plugin) handleClassificationGet(w http.ResponseWriter, r *http.Request) {
	if p.compliance == nil {
		http.Error(w, "compliance is not configured on this gateway", http.StatusNotImplemented)
		return
	}
	resource := r.PathValue("resource")
	rec, err := p.compliance.GetClassification(r.Context(), resource)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (p *Plugin) handleClassificationPut(w http.ResponseWriter, r *http.Request) {
	if p.compliance == nil {
		http.Error(w, "compliance is not configured on this gateway", http.StatusNotImplemented)
		return
	}
	resource := r.PathValue("resource")
	var body struct {
		Level string `json:"level"`
	}
	if err := decodeJSON(r, &body); err != nil || body.Level == "" {
		http.Error(w, "request body must be {\"level\": \"...\"}", http.StatusBadRequest)
		return
	}
	if err := p.compliance.SetClassification(r.Context(), resource, body.Level); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *Plugin) handleViolationsList(w http.ResponseWriter, r *http.Request) {
	if p.compliance == nil {
		http.Error(w, "compliance is not configured on this gateway", http.StatusNotImplemented)
		return
	}
	resource := r.URL.Query().Get("resource")
	violations, err := p.compliance.ListViolations(r.Context(), resource)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, violations)
}

func (p *Plugin) handleRulePackImport(w http.ResponseWriter, r *http.Request) {
	if p.compliance == nil {
		http.Error(w, "compliance is not configured on this gateway", http.StatusNotImplemented)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := p.compliance.ImportRulePack(r.Context(), body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- break-glass ---

func (p *Plugin) handleBreakGlassGrant(w http.ResponseWriter, r *http.Request) {
	if p.breakGlass == nil {
		http.Error(w, "break-glass is not configured on this gateway (requires the compliance plugin)", http.StatusNotImplemented)
		return
	}
	approver, ok := principalFromContext(r.Context())
	if !ok {
		http.Error(w, "break-glass grant requires an authenticated Bearer-token caller as approver", http.StatusUnauthorized)
		return
	}
	if !hasRole(approver, "admin") {
		http.Error(w, "break-glass grant requires the caller to have role \"admin\"", http.StatusForbidden)
		return
	}
	var req api.BreakGlassRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	grant, err := p.breakGlass.BreakGlassGrant(r.Context(), req, approver)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, grant)
}

func (p *Plugin) handleBreakGlassRevoke(w http.ResponseWriter, r *http.Request) {
	if p.breakGlass == nil {
		http.Error(w, "break-glass is not configured on this gateway (requires the compliance plugin)", http.StatusNotImplemented)
		return
	}
	approver, ok := principalFromContext(r.Context())
	if !ok || !hasRole(approver, "admin") {
		http.Error(w, "break-glass revoke requires an authenticated caller with role \"admin\"", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	if err := p.breakGlass.BreakGlassRevoke(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func hasRole(p api.Principal, role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// --- knowledge graph ---

func (p *Plugin) handleKGEntity(w http.ResponseWriter, r *http.Request) {
	if p.graph == nil {
		http.Error(w, "search.graph is not configured on this gateway", http.StatusNotImplemented)
		return
	}
	var req struct {
		ID    string         `json:"id"`
		Attrs map[string]any `json:"attrs"`
	}
	if err := decodeJSON(r, &req); err != nil || req.ID == "" {
		http.Error(w, "request body must be {\"id\": \"...\", \"attrs\": {...}}", http.StatusBadRequest)
		return
	}
	if err := p.graph.AddEntity(r.Context(), req.ID, req.Attrs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (p *Plugin) handleKGRelation(w http.ResponseWriter, r *http.Request) {
	if p.graph == nil {
		http.Error(w, "search.graph is not configured on this gateway", http.StatusNotImplemented)
		return
	}
	var req struct {
		From  string         `json:"from"`
		To    string         `json:"to"`
		Type  string         `json:"type"`
		Attrs map[string]any `json:"attrs"`
	}
	if err := decodeJSON(r, &req); err != nil || req.From == "" || req.To == "" || req.Type == "" {
		http.Error(w, "request body must be {\"from\":\"...\",\"to\":\"...\",\"type\":\"...\",\"attrs\":{...}}", http.StatusBadRequest)
		return
	}
	if err := p.graph.AddRelation(r.Context(), req.From, req.To, req.Type, req.Attrs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (p *Plugin) handleKGTraverse(w http.ResponseWriter, r *http.Request) {
	if p.graph == nil {
		http.Error(w, "search.graph is not configured on this gateway", http.StatusNotImplemented)
		return
	}
	start := r.PathValue("start")
	depth := 1
	if d := r.URL.Query().Get("depth"); d != "" {
		if parsed, err := parseDepth(d); err == nil {
			depth = parsed
		}
	}
	ids, err := p.graph.Traverse(r.Context(), start, depth)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, ids)
}

func parseDepth(s string) (int, error) {
	return strconv.Atoi(s)
}
