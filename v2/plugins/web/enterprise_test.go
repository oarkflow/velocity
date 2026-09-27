package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	authsts "github.com/oarkflow/velocity/v2/plugins/auth-sts"
	"github.com/oarkflow/velocity/v2/plugins/iam"
)

// --- minimal in-memory StorageBackend, used to boot a REAL plugins/iam
// instance for the IAM route tests below (not a stub of api.IAMService —
// the actual plugin, exercising real persistence + evaluation logic
// through the HTTP layer). ---

type memBackend struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemBackend() *memBackend { return &memBackend{data: map[string][]byte{}} }

func (m *memBackend) Get(ctx context.Context, key []byte) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[string(key)]
	return v, ok, nil
}
func (m *memBackend) Put(ctx context.Context, e api.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[string(e.Key)] = e.Value
	return nil
}
func (m *memBackend) Delete(ctx context.Context, key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, string(key))
	return nil
}
func (m *memBackend) Batch(ctx context.Context, ops []api.BatchOp) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, op := range ops {
		if op.Delete {
			delete(m.data, string(op.Entry.Key))
		} else {
			m.data[string(op.Entry.Key)] = op.Entry.Value
		}
	}
	return nil
}
func (m *memBackend) Scan(ctx context.Context, prefix []byte) (api.Iterator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for k := range m.data {
		if strings.HasPrefix(k, string(prefix)) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return &memIterator{backend: m, keys: keys, idx: -1}, nil
}
func (m *memBackend) Snapshot(ctx context.Context) (api.Snapshot, error) { return nil, nil }
func (m *memBackend) Close() error                                       { return nil }

type memIterator struct {
	backend *memBackend
	keys    []string
	idx     int
}

func (it *memIterator) Next() bool  { it.idx++; return it.idx < len(it.keys) }
func (it *memIterator) Key() []byte { return []byte(it.keys[it.idx]) }
func (it *memIterator) Value() []byte {
	it.backend.mu.Lock()
	defer it.backend.mu.Unlock()
	return it.backend.data[it.keys[it.idx]]
}
func (it *memIterator) Err() error   { return nil }
func (it *memIterator) Close() error { return nil }

// realIAMPlugin boots a genuine plugins/iam.Plugin against an in-memory
// StorageBackend via the same fakeKernel harness newTestPlugin uses, so
// the IAM route tests exercise the real persistence/evaluation logic, not
// a hand-written stub.
func realIAMPlugin(t *testing.T) *iam.Plugin {
	t.Helper()
	reg := newFakeRegistry()
	reg.Provide("storage", newMemBackend())
	k := &fakeKernel{reg: reg, cfg: &fakeConfig{data: map[string]any{}}, log: noopLogger{t: t}}
	p := iam.NewPlugin("storage-lsm")
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("iam.Init: %v", err)
	}
	return p
}

// --- fakes specific to the enterprise routes ---

type fakeAuthenticator struct {
	name      string
	principal api.Principal
	err       error
}

func (f *fakeAuthenticator) Name() string { return f.name }
func (f *fakeAuthenticator) Authenticate(ctx context.Context, credential any) (api.Principal, error) {
	if f.err != nil {
		return api.Principal{}, f.err
	}
	return f.principal, nil
}

type fakeTokenIssuer struct{ token string }

func (f *fakeTokenIssuer) IssueToken(ctx context.Context, subject string, roles []string, ttl time.Duration) (string, error) {
	return f.token, nil
}

type fakeMFA struct {
	secret string
	valid  bool
}

func (f *fakeMFA) GenerateSecret(ctx context.Context, subject string) (string, error) {
	return f.secret, nil
}
func (f *fakeMFA) ValidateCode(ctx context.Context, subject, code string) (bool, error) {
	return f.valid, nil
}

type fakeNotifications struct {
	rules []api.NotificationRule
}

func (f *fakeNotifications) AddRule(ctx context.Context, r api.NotificationRule) error {
	f.rules = append(f.rules, r)
	return nil
}
func (f *fakeNotifications) RemoveRule(ctx context.Context, id string) error {
	out := f.rules[:0]
	for _, r := range f.rules {
		if r.ID != id {
			out = append(out, r)
		}
	}
	f.rules = out
	return nil
}
func (f *fakeNotifications) ListRules(ctx context.Context) ([]api.NotificationRule, error) {
	return f.rules, nil
}

type fakeCompliance struct {
	classifications map[string]api.ClassificationRecord
	violations      []api.Violation
	grantErr        error
}

func (f *fakeCompliance) Record(ctx context.Context, ev api.AuditEvent) error { return nil }
func (f *fakeCompliance) VerifyChain(ctx context.Context) error               { return nil }
func (f *fakeCompliance) Evaluate(ctx context.Context, s api.Principal, action, resource, classification string) (api.PolicyDecision, error) {
	return api.PolicyDecision{Allowed: true}, nil
}
func (f *fakeCompliance) ApplyRetention(ctx context.Context, resource string) error { return nil }
func (f *fakeCompliance) RecordConsent(ctx context.Context, subject, purpose string, granted bool) error {
	return nil
}
func (f *fakeCompliance) Anonymize(ctx context.Context, resource string) error { return nil }
func (f *fakeCompliance) SetClassification(ctx context.Context, resource, level string) error {
	if f.classifications == nil {
		f.classifications = map[string]api.ClassificationRecord{}
	}
	f.classifications[resource] = api.ClassificationRecord{Resource: resource, Level: level}
	return nil
}
func (f *fakeCompliance) GetClassification(ctx context.Context, resource string) (api.ClassificationRecord, error) {
	rec, ok := f.classifications[resource]
	if !ok {
		return api.ClassificationRecord{}, errNotFound
	}
	return rec, nil
}
func (f *fakeCompliance) SetResidencyRule(ctx context.Context, rule api.ResidencyRule) error {
	return nil
}
func (f *fakeCompliance) CheckResidency(ctx context.Context, resource, currentRegion string) (bool, string, error) {
	return true, "", nil
}
func (f *fakeCompliance) RecordLineage(ctx context.Context, ev api.LineageEvent) error { return nil }
func (f *fakeCompliance) GetLineage(ctx context.Context, resource string) ([]api.LineageEvent, error) {
	return nil, nil
}
func (f *fakeCompliance) MaskWithStrategy(ctx context.Context, resource string, strategy api.MaskStrategy) error {
	return nil
}
func (f *fakeCompliance) ImportRulePack(ctx context.Context, packJSON []byte) error { return nil }
func (f *fakeCompliance) ListViolations(ctx context.Context, resource string) ([]api.Violation, error) {
	return f.violations, nil
}

var errNotFound = &notFoundErr{}

type notFoundErr struct{}

func (*notFoundErr) Error() string { return "not found" }

var _ api.ComplianceService = (*fakeCompliance)(nil)

type fakeBreakGlass struct {
	grantErr error
}

func (f *fakeBreakGlass) BreakGlassGrant(ctx context.Context, req api.BreakGlassRequest, approver api.Principal) (api.BreakGlassGrant, error) {
	if f.grantErr != nil {
		return api.BreakGlassGrant{}, f.grantErr
	}
	return api.BreakGlassGrant{ID: "grant-1", ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (f *fakeBreakGlass) BreakGlassRevoke(ctx context.Context, grantID string) error { return nil }

type fakeGraph struct {
	entities  []string
	relations int
}

func (f *fakeGraph) AddEntity(ctx context.Context, id string, attrs map[string]any) error {
	f.entities = append(f.entities, id)
	return nil
}
func (f *fakeGraph) AddRelation(ctx context.Context, from, to, relType string, attrs map[string]any) error {
	f.relations++
	return nil
}
func (f *fakeGraph) Traverse(ctx context.Context, start string, depth int) ([]string, error) {
	return []string{start}, nil
}

// enterpriseTestPlugin builds a Plugin with the base kv/object/auth wiring
// (reusing newTestPlugin) plus directly-set enterprise fields — these are
// same-package direct field assignments rather than registry lookups
// where a concrete (non-interface) dependency (like *authsts.Plugin) or a
// deliberately minimal fake makes that simpler than a full kernel boot.
func enterpriseTestPlugin(t *testing.T) *Plugin {
	t.Helper()
	p, _, _ := newTestPlugin(t, true, false)
	return p
}

func doRequest(t *testing.T, p *Plugin, method, path string, body any, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	rt, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	rt.mux.ServeHTTP(rec, req)
	return rec
}

func TestLoginOIDC_Success(t *testing.T) {
	p := enterpriseTestPlugin(t)
	p.oidcAuth = &fakeAuthenticator{name: "auth-oidc", principal: api.Principal{Subject: "alice", Roles: []string{"user"}}}
	p.tokenIssuer = &fakeTokenIssuer{token: "minted-token"}

	rec := doRequest(t, p, "POST", "/api/auth/login/oidc", map[string]string{"idToken": "abc"}, "good-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Token != "minted-token" || resp.Principal.Subject != "alice" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestLoginOIDC_NotConfigured(t *testing.T) {
	p := enterpriseTestPlugin(t)
	rec := doRequest(t, p, "POST", "/api/auth/login/oidc", map[string]string{"idToken": "abc"}, "good-token")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

func TestLoginLDAP_FallsBackToPrincipalWithoutTokenIssuer(t *testing.T) {
	p := enterpriseTestPlugin(t)
	p.ldapAuth = &fakeAuthenticator{name: "auth-ldap", principal: api.Principal{Subject: "bob"}}
	// no tokenIssuer configured

	rec := doRequest(t, p, "POST", "/api/auth/login/ldap", map[string]string{"username": "bob", "password": "x"}, "good-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token != "" {
		t.Fatalf("expected no token without a TokenIssuer, got %q", resp.Token)
	}
	if resp.Principal.Subject != "bob" {
		t.Fatalf("unexpected principal: %+v", resp.Principal)
	}
}

func TestSTSAssumeRole_DirectSucceedsAndNotConfiguredIs501(t *testing.T) {
	p := enterpriseTestPlugin(t)

	// not configured yet
	rec := doRequest(t, p, "POST", "/api/auth/sts/assume-role", authsts.AssumeRoleRequest{}, "good-token")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}

	// wire a real, minimal auth-sts plugin
	sts := authsts.New()
	k := &fakeKernel{reg: newFakeRegistry(), cfg: &fakeConfig{data: map[string]any{}}, log: noopLogger{t: t}}
	if err := sts.Init(context.Background(), k); err != nil {
		t.Fatalf("sts Init: %v", err)
	}
	p.sts = sts

	req := authsts.AssumeRoleRequest{RoleARN: "arn:test:role", RoleSessionName: "session1", UserID: "alice"}
	rec = doRequest(t, p, "POST", "/api/auth/sts/assume-role", req, "good-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var result authsts.AssumeRoleResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Credentials == (authsts.Credentials{}) {
		t.Fatalf("expected non-zero credentials, got %+v", result)
	}
}

func TestMFAEnrollAndValidate(t *testing.T) {
	p := enterpriseTestPlugin(t)
	p.mfa = &fakeMFA{secret: "JBSWY3DPEHPK3PXP", valid: true}

	rec := doRequest(t, p, "POST", "/api/auth/mfa/enroll", map[string]string{"subject": "alice"}, "good-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doRequest(t, p, "POST", "/api/auth/mfa/validate", map[string]string{"subject": "alice", "code": "123456"}, "good-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("validate status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]bool
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp["valid"] {
		t.Fatalf("expected valid=true, got %+v", resp)
	}
}

func TestMFA_NotConfiguredIs501(t *testing.T) {
	p := enterpriseTestPlugin(t)
	rec := doRequest(t, p, "POST", "/api/auth/mfa/enroll", map[string]string{"subject": "alice"}, "good-token")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

func TestIAM_NotConfiguredIs501(t *testing.T) {
	p := enterpriseTestPlugin(t)
	rec := doRequest(t, p, "PUT", "/api/iam/policies/reader", api.IAMPolicy{}, "good-token")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

func TestIAMPolicyPutAndGet(t *testing.T) {
	p := enterpriseTestPlugin(t)
	p.iam = realIAMPlugin(t)

	policy := api.IAMPolicy{Statements: []api.IAMStatement{
		{Effect: "Allow", Actions: []string{"kv:Get"}, Resources: []string{"*"}},
	}}
	rec := doRequest(t, p, "PUT", "/api/iam/policies/reader", policy, "good-token")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("put status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = doRequest(t, p, "GET", "/api/iam/policies/reader", nil, "good-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got api.IAMPolicy
	json.Unmarshal(rec.Body.Bytes(), &got)
	if len(got.Statements) != 1 || got.Statements[0].Effect != "Allow" {
		t.Fatalf("unexpected policy: %+v", got)
	}

	rec = doRequest(t, p, "GET", "/api/iam/policies", nil, "good-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	var names []string
	json.Unmarshal(rec.Body.Bytes(), &names)
	if len(names) != 1 || names[0] != "reader" {
		t.Fatalf("unexpected list: %+v", names)
	}

	rec = doRequest(t, p, "DELETE", "/api/iam/policies/reader", nil, "good-token")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = doRequest(t, p, "GET", "/api/iam/policies/reader", nil, "good-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get-after-delete status = %d, want 404", rec.Code)
	}
}

// TestIAMEvaluate_ExplicitDenyWinsOverAllow and
// TestIAMEvaluate_ImplicitDenyByDefault exercise the same security-critical
// IAM correctness properties as plugins/iam's own tests, but through the
// HTTP layer end to end — proving the wiring, not just the underlying
// plugin, gets this right.
func TestIAMEvaluate_ExplicitDenyWinsOverAllow(t *testing.T) {
	p := enterpriseTestPlugin(t)
	p.iam = realIAMPlugin(t)
	ctx := context.Background()

	p.iam.PutPolicy(ctx, "allow-all", api.IAMPolicy{Statements: []api.IAMStatement{{Effect: "Allow", Actions: []string{"*"}, Resources: []string{"*"}}}})
	p.iam.PutPolicy(ctx, "deny-delete", api.IAMPolicy{Statements: []api.IAMStatement{{Effect: "Deny", Actions: []string{"object:Delete"}, Resources: []string{"*"}}}})
	p.iam.AttachPolicy(ctx, "carol", "allow-all")
	p.iam.AttachPolicy(ctx, "carol", "deny-delete")

	rec := doRequest(t, p, "POST", "/api/iam/evaluate", iamEvaluateRequest{Subject: "carol", Action: "object:Delete", Resource: "res"}, "good-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp iamEvaluateResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatalf("expected denied (explicit Deny must win), got %+v", resp)
	}
}

func TestIAMEvaluate_ImplicitDenyByDefault(t *testing.T) {
	p := enterpriseTestPlugin(t)
	p.iam = realIAMPlugin(t)

	rec := doRequest(t, p, "POST", "/api/iam/evaluate", iamEvaluateRequest{Subject: "nobody", Action: "kv:Get", Resource: "x"}, "good-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp iamEvaluateResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatalf("a principal with zero attached policies must be denied, got %+v", resp)
	}
}

func TestIAMAttachDetach(t *testing.T) {
	p := enterpriseTestPlugin(t)
	p.iam = realIAMPlugin(t)
	ctx := context.Background()
	p.iam.PutPolicy(ctx, "reader", api.IAMPolicy{Statements: []api.IAMStatement{{Effect: "Allow", Actions: []string{"kv:Get"}, Resources: []string{"*"}}}})

	rec := doRequest(t, p, "POST", "/api/iam/policies/reader/attach", iamAttachRequest{Subject: "erin"}, "good-token")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("attach status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = doRequest(t, p, "POST", "/api/iam/evaluate", iamEvaluateRequest{Subject: "erin", Action: "kv:Get", Resource: "x"}, "good-token")
	var resp iamEvaluateResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Allowed {
		t.Fatalf("expected allowed after attach, got %+v", resp)
	}

	rec = doRequest(t, p, "POST", "/api/iam/policies/reader/detach", iamAttachRequest{Subject: "erin"}, "good-token")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("detach status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = doRequest(t, p, "POST", "/api/iam/evaluate", iamEvaluateRequest{Subject: "erin", Action: "kv:Get", Resource: "x"}, "good-token")
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatalf("expected denied after detach, got %+v", resp)
	}
}

func TestBucketLifecycle(t *testing.T) {
	p := enterpriseTestPlugin(t)
	rules := []api.LifecycleRule{{Prefix: "logs/", ExpireAfter: 24 * time.Hour}}
	rec := doRequest(t, p, "PUT", "/api/buckets/mybucket/lifecycle", rules, "good-token")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestNotificationRules_CreateListDelete(t *testing.T) {
	p := enterpriseTestPlugin(t)
	fn := &fakeNotifications{}
	p.notifications = fn

	rec := doRequest(t, p, "POST", "/api/notifications/rules", api.NotificationRule{ID: "r1", Topic: "object.put", WebhookURL: "http://x", Enabled: true}, "good-token")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doRequest(t, p, "GET", "/api/notifications/rules", nil, "good-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	var rules []api.NotificationRule
	json.Unmarshal(rec.Body.Bytes(), &rules)
	if len(rules) != 1 || rules[0].ID != "r1" {
		t.Fatalf("unexpected rules: %+v", rules)
	}

	rec = doRequest(t, p, "DELETE", "/api/notifications/rules/r1", nil, "good-token")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", rec.Code)
	}
	if len(fn.rules) != 0 {
		t.Fatalf("expected rule removed, got %+v", fn.rules)
	}
}

func TestNotifications_NotConfiguredIs501(t *testing.T) {
	p := enterpriseTestPlugin(t)
	rec := doRequest(t, p, "GET", "/api/notifications/rules", nil, "good-token")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

func TestComplianceClassificationAndViolations(t *testing.T) {
	p := enterpriseTestPlugin(t)
	fc := &fakeCompliance{violations: []api.Violation{{ID: "v1", Rule: "r", Resource: "res1", Severity: "high"}}}
	p.compliance = fc

	rec := doRequest(t, p, "PUT", "/api/compliance/classification/res1", map[string]string{"level": "restricted"}, "good-token")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("put status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doRequest(t, p, "GET", "/api/compliance/classification/res1", nil, "good-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var rec2 api.ClassificationRecord
	json.Unmarshal(rec.Body.Bytes(), &rec2)
	if rec2.Level != "restricted" {
		t.Fatalf("unexpected classification: %+v", rec2)
	}

	rec = doRequest(t, p, "GET", "/api/compliance/violations", nil, "good-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("violations status = %d", rec.Code)
	}
	var violations []api.Violation
	json.Unmarshal(rec.Body.Bytes(), &violations)
	if len(violations) != 1 || violations[0].ID != "v1" {
		t.Fatalf("unexpected violations: %+v", violations)
	}
}

func TestCompliance_NotConfiguredIs501(t *testing.T) {
	p := enterpriseTestPlugin(t)
	rec := doRequest(t, p, "GET", "/api/compliance/violations", nil, "good-token")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

func TestBreakGlassGrant_RequiresAdminRoleApprover(t *testing.T) {
	p := enterpriseTestPlugin(t)
	p.breakGlass = &fakeBreakGlass{}

	// good-token authenticates as a Principal with no roles by default
	// (fakeAuth), so this must be forbidden.
	rec := doRequest(t, p, "POST", "/api/breakglass/grant", api.BreakGlassRequest{Requestor: "bob", Reason: "incident", Resource: "db1"}, "good-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestBreakGlassGrant_SucceedsForAdmin(t *testing.T) {
	reg := newFakeRegistry()
	kv := newFakeKV()
	obj := newFakeObjectStore()
	reg.Provide("kv", kv)
	reg.Provide("object", obj)
	reg.Provide("auth.jwt", &fakeAuth{validToken: "admin-token", principal: api.Principal{Subject: "root", Roles: []string{"admin"}}})
	k := &fakeKernel{reg: reg, cfg: &fakeConfig{data: map[string]any{}}, log: noopLogger{t: t}}
	p := NewPlugin("", "", "")
	if err := p.Init(context.Background(), k); err != nil {
		t.Fatalf("Init: %v", err)
	}
	p.breakGlass = &fakeBreakGlass{}

	rec := doRequest(t, p, "POST", "/api/breakglass/grant", api.BreakGlassRequest{Requestor: "bob", Reason: "incident", Resource: "db1"}, "admin-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var grant api.BreakGlassGrant
	json.Unmarshal(rec.Body.Bytes(), &grant)
	if grant.ID != "grant-1" {
		t.Fatalf("unexpected grant: %+v", grant)
	}
}

func TestBreakGlass_NotConfiguredIs501(t *testing.T) {
	p := enterpriseTestPlugin(t)
	rec := doRequest(t, p, "POST", "/api/breakglass/grant", api.BreakGlassRequest{}, "good-token")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

func TestKGEntityRelationTraverse(t *testing.T) {
	p := enterpriseTestPlugin(t)
	fg := &fakeGraph{}
	p.graph = fg

	rec := doRequest(t, p, "POST", "/api/kg/entities", map[string]any{"id": "e1", "attrs": map[string]any{"type": "person"}}, "good-token")
	if rec.Code != http.StatusCreated {
		t.Fatalf("entity status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doRequest(t, p, "POST", "/api/kg/relations", map[string]any{"from": "e1", "to": "e2", "type": "knows"}, "good-token")
	if rec.Code != http.StatusCreated {
		t.Fatalf("relation status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doRequest(t, p, "GET", "/api/kg/traverse/e1", nil, "good-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("traverse status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var ids []string
	json.Unmarshal(rec.Body.Bytes(), &ids)
	if len(ids) != 1 || ids[0] != "e1" {
		t.Fatalf("unexpected traverse result: %+v", ids)
	}
	if len(fg.entities) != 1 || fg.relations != 1 {
		t.Fatalf("graph fake state unexpected: %+v", fg)
	}
}

func TestKG_NotConfiguredIs501(t *testing.T) {
	p := enterpriseTestPlugin(t)
	rec := doRequest(t, p, "GET", "/api/kg/traverse/e1", nil, "good-token")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

func TestEnterpriseRoutes_RequireAuthWhenConfigured(t *testing.T) {
	p := enterpriseTestPlugin(t)
	p.mfa = &fakeMFA{secret: "x", valid: true}
	rec := doRequest(t, p, "POST", "/api/auth/mfa/enroll", map[string]string{"subject": "alice"}, "" /* no bearer */)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
