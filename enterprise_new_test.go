package velocity

import (
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func createTestBuckets(t *testing.T, db *DB, names ...string) {
	t.Helper()
	bm := NewBucketManager(db)
	for _, name := range names {
		if err := bm.CreateBucket(name, "test-owner", "us-east-1"); err != nil {
			t.Fatalf("CreateBucket(%q): %v", name, err)
		}
	}
}

func storeTestObject(t *testing.T, db *DB, path, contentType string, data []byte, opts *ObjectOptions) *ObjectMetadata {
	t.Helper()
	meta, err := db.StoreObject(path, contentType, "test-user", data, opts)
	if err != nil {
		t.Fatalf("StoreObject(%q): %v", path, err)
	}
	return meta
}

// ---------------------------------------------------------------------------
// 1. IAMPolicyEngine tests
// ---------------------------------------------------------------------------

func TestIAMPolicyEngine(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	engine := NewIAMPolicyEngine(db)

	// Reusable policy helper
	makePolicy := func(name, effect string, actions, resources []string) *IAMPolicy {
		return &IAMPolicy{
			Name: name,
			Statements: []IAMStatement{
				{
					Sid:       name + "-stmt",
					Effect:    effect,
					Principal: []string{"*"},
					Action:    actions,
					Resource:  resources,
				},
			},
		}
	}

	t.Run("CreatePolicy stores and retrieves policy", func(t *testing.T) {
		p := makePolicy("read-policy", IAMEffectAllow,
			[]string{"s3:GetObject"}, []string{"arn:velocity:s3:::mybucket/*"})
		if err := engine.CreatePolicy(p); err != nil {
			t.Fatalf("CreatePolicy: %v", err)
		}
		got, err := engine.GetPolicy("read-policy")
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if got.Name != "read-policy" {
			t.Fatalf("expected name %q, got %q", "read-policy", got.Name)
		}
		if len(got.Statements) != 1 {
			t.Fatalf("expected 1 statement, got %d", len(got.Statements))
		}
		if got.Statements[0].Effect != IAMEffectAllow {
			t.Fatalf("expected effect %q, got %q", IAMEffectAllow, got.Statements[0].Effect)
		}
		if got.Version != "2012-10-17" {
			t.Fatalf("expected default version, got %q", got.Version)
		}
		if got.CreatedAt.IsZero() {
			t.Fatal("expected non-zero CreatedAt")
		}
	})

	t.Run("CreatePolicy rejects empty name", func(t *testing.T) {
		p := &IAMPolicy{Name: "", Statements: []IAMStatement{
			{Effect: IAMEffectAllow, Action: []string{"s3:*"}, Resource: []string{"*"}},
		}}
		if err := engine.CreatePolicy(p); err == nil {
			t.Fatal("expected error for empty policy name")
		}
	})

	t.Run("CreatePolicy rejects invalid Effect", func(t *testing.T) {
		p := &IAMPolicy{
			Name: "bad-effect",
			Statements: []IAMStatement{
				{Sid: "s1", Effect: "Maybe", Action: []string{"s3:*"}, Resource: []string{"*"}},
			},
		}
		err := engine.CreatePolicy(p)
		if err == nil {
			t.Fatal("expected error for invalid effect")
		}
		if !strings.Contains(err.Error(), "invalid effect") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("DeletePolicy removes policy", func(t *testing.T) {
		p := makePolicy("delete-me", IAMEffectAllow, []string{"s3:*"}, []string{"*"})
		if err := engine.CreatePolicy(p); err != nil {
			t.Fatalf("CreatePolicy: %v", err)
		}
		if err := engine.DeletePolicy("delete-me"); err != nil {
			t.Fatalf("DeletePolicy: %v", err)
		}
		if _, err := engine.GetPolicy("delete-me"); err == nil {
			t.Fatal("expected error after delete")
		}
	})

	t.Run("ListPolicies returns all policies", func(t *testing.T) {
		db2 := openTestDB(t)
		defer db2.Close()
		e2 := NewIAMPolicyEngine(db2)

		for _, name := range []string{"pol-a", "pol-b", "pol-c"} {
			if err := e2.CreatePolicy(makePolicy(name, IAMEffectAllow, []string{"s3:*"}, []string{"*"})); err != nil {
				t.Fatalf("CreatePolicy(%q): %v", name, err)
			}
		}
		policies, err := e2.ListPolicies()
		if err != nil {
			t.Fatalf("ListPolicies: %v", err)
		}
		if len(policies) != 3 {
			t.Fatalf("expected 3 policies, got %d", len(policies))
		}
	})

	t.Run("AttachUserPolicy and DetachUserPolicy", func(t *testing.T) {
		policyName := "user-attach-test"
		if err := engine.CreatePolicy(makePolicy(policyName, IAMEffectAllow,
			[]string{"s3:GetObject"}, []string{"*"})); err != nil {
			t.Fatalf("CreatePolicy: %v", err)
		}

		if err := engine.AttachUserPolicy("alice", policyName); err != nil {
			t.Fatalf("AttachUserPolicy: %v", err)
		}
		policies := engine.GetUserPolicies("alice")
		found := false
		for _, p := range policies {
			if p == policyName {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected %q in user policies, got %v", policyName, policies)
		}

		// Idempotent attach
		if err := engine.AttachUserPolicy("alice", policyName); err != nil {
			t.Fatalf("re-attach should be idempotent: %v", err)
		}

		// Detach
		if err := engine.DetachUserPolicy("alice", policyName); err != nil {
			t.Fatalf("DetachUserPolicy: %v", err)
		}
		policies = engine.GetUserPolicies("alice")
		for _, p := range policies {
			if p == policyName {
				t.Fatalf("policy %q should have been detached", policyName)
			}
		}
	})

	t.Run("AttachUserPolicy with non-existent policy returns error", func(t *testing.T) {
		err := engine.AttachUserPolicy("bob", "no-such-policy")
		if err == nil {
			t.Fatal("expected error for non-existent policy")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("DetachUserPolicy with unattached policy returns error", func(t *testing.T) {
		polName := "detach-test-policy"
		if err := engine.CreatePolicy(makePolicy(polName, IAMEffectAllow,
			[]string{"s3:*"}, []string{"*"})); err != nil {
			t.Fatalf("CreatePolicy: %v", err)
		}
		err := engine.DetachUserPolicy("charlie", polName)
		if err == nil {
			t.Fatal("expected error when detaching unattached policy")
		}
		if !strings.Contains(err.Error(), "not attached") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("GetUserPolicies returns attached policies", func(t *testing.T) {
		db2 := openTestDB(t)
		defer db2.Close()
		e2 := NewIAMPolicyEngine(db2)

		for _, name := range []string{"gup-1", "gup-2"} {
			if err := e2.CreatePolicy(makePolicy(name, IAMEffectAllow,
				[]string{"s3:*"}, []string{"*"})); err != nil {
				t.Fatalf("CreatePolicy: %v", err)
			}
			if err := e2.AttachUserPolicy("dave", name); err != nil {
				t.Fatalf("AttachUserPolicy: %v", err)
			}
		}
		got := e2.GetUserPolicies("dave")
		if len(got) != 2 {
			t.Fatalf("expected 2 policies, got %d", len(got))
		}
	})

	t.Run("EvaluateAccess with Allow policy", func(t *testing.T) {
		db2 := openTestDB(t)
		defer db2.Close()
		e2 := NewIAMPolicyEngine(db2)

		if err := e2.CreatePolicy(makePolicy("allow-get", IAMEffectAllow,
			[]string{"s3:GetObject"}, []string{"arn:velocity:s3:::mybucket/*"})); err != nil {
			t.Fatal(err)
		}
		if err := e2.AttachUserPolicy("eve", "allow-get"); err != nil {
			t.Fatal(err)
		}

		result := e2.EvaluateAccess(&IAMEvalRequest{
			Principal: "eve",
			Action:    "s3:GetObject",
			Resource:  "arn:velocity:s3:::mybucket/file.txt",
		})
		if !result.Allowed {
			t.Fatalf("expected allowed, got denied: %s", result.Reason)
		}
		if result.MatchedPolicy != "allow-get" {
			t.Fatalf("expected matched policy %q, got %q", "allow-get", result.MatchedPolicy)
		}
	})

	t.Run("EvaluateAccess with Deny policy overrides Allow", func(t *testing.T) {
		db2 := openTestDB(t)
		defer db2.Close()
		e2 := NewIAMPolicyEngine(db2)

		if err := e2.CreatePolicy(makePolicy("allow-all", IAMEffectAllow,
			[]string{"s3:*"}, []string{"*"})); err != nil {
			t.Fatal(err)
		}
		if err := e2.CreatePolicy(makePolicy("deny-delete", IAMEffectDeny,
			[]string{"s3:DeleteObject"}, []string{"*"})); err != nil {
			t.Fatal(err)
		}
		if err := e2.AttachUserPolicy("frank", "allow-all"); err != nil {
			t.Fatal(err)
		}
		if err := e2.AttachUserPolicy("frank", "deny-delete"); err != nil {
			t.Fatal(err)
		}

		result := e2.EvaluateAccess(&IAMEvalRequest{
			Principal: "frank",
			Action:    "s3:DeleteObject",
			Resource:  "arn:velocity:s3:::mybucket/secret.txt",
		})
		if result.Allowed {
			t.Fatal("expected deny to override allow")
		}
		if !result.ExplicitDeny {
			t.Fatal("expected explicit deny flag")
		}
	})

	t.Run("EvaluateAccess with wildcard action", func(t *testing.T) {
		db2 := openTestDB(t)
		defer db2.Close()
		e2 := NewIAMPolicyEngine(db2)

		if err := e2.CreatePolicy(makePolicy("allow-s3-star", IAMEffectAllow,
			[]string{"s3:*"}, []string{"*"})); err != nil {
			t.Fatal(err)
		}
		if err := e2.AttachUserPolicy("grace", "allow-s3-star"); err != nil {
			t.Fatal(err)
		}

		for _, action := range []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"} {
			result := e2.EvaluateAccess(&IAMEvalRequest{
				Principal: "grace",
				Action:    action,
				Resource:  "arn:velocity:s3:::anybucket/anykey",
			})
			if !result.Allowed {
				t.Fatalf("expected s3:* to allow %q", action)
			}
		}
	})

	t.Run("EvaluateAccess with wildcard resource", func(t *testing.T) {
		db2 := openTestDB(t)
		defer db2.Close()
		e2 := NewIAMPolicyEngine(db2)

		if err := e2.CreatePolicy(&IAMPolicy{
			Name: "bucket-wildcard",
			Statements: []IAMStatement{{
				Sid:       "stmt1",
				Effect:    IAMEffectAllow,
				Principal: []string{"*"},
				Action:    []string{"s3:GetObject"},
				Resource:  []string{"arn:*:s3:::mybucket/*"},
			}},
		}); err != nil {
			t.Fatal(err)
		}
		if err := e2.AttachUserPolicy("heidi", "bucket-wildcard"); err != nil {
			t.Fatal(err)
		}

		result := e2.EvaluateAccess(&IAMEvalRequest{
			Principal: "heidi",
			Action:    "s3:GetObject",
			Resource:  "arn:velocity:s3:::mybucket/deep/path/file.txt",
		})
		if !result.Allowed {
			t.Fatalf("expected allowed for wildcard resource, got denied: %s", result.Reason)
		}
	})

	t.Run("EvaluateAccess with no matching policy returns denied", func(t *testing.T) {
		db2 := openTestDB(t)
		defer db2.Close()
		e2 := NewIAMPolicyEngine(db2)

		result := e2.EvaluateAccess(&IAMEvalRequest{
			Principal: "nobody",
			Action:    "s3:GetObject",
			Resource:  "arn:velocity:s3:::private/data",
		})
		if result.Allowed {
			t.Fatal("expected denied when no policies exist")
		}
		if result.ExplicitDeny {
			t.Fatal("should not be explicit deny when no policies match")
		}
		if !strings.Contains(result.Reason, "no matching policy") {
			t.Fatalf("unexpected reason: %q", result.Reason)
		}
	})

	t.Run("EvaluateAccess with condition IpAddress", func(t *testing.T) {
		db2 := openTestDB(t)
		defer db2.Close()
		e2 := NewIAMPolicyEngine(db2)

		if err := e2.CreatePolicy(&IAMPolicy{
			Name: "ip-restricted",
			Statements: []IAMStatement{{
				Sid:       "ip-stmt",
				Effect:    IAMEffectAllow,
				Principal: []string{"*"},
				Action:    []string{"s3:GetObject"},
				Resource:  []string{"*"},
				Condition: &IAMConditionBlock{
					IpAddress: map[string]string{
						"aws:SourceIp": "10.0.0.0/8",
					},
				},
			}},
		}); err != nil {
			t.Fatal(err)
		}
		if err := e2.AttachUserPolicy("ivan", "ip-restricted"); err != nil {
			t.Fatal(err)
		}

		// Request from allowed IP
		allowed := e2.EvaluateAccess(&IAMEvalRequest{
			Principal: "ivan",
			Action:    "s3:GetObject",
			Resource:  "arn:velocity:s3:::mybucket/file.txt",
			Context:   map[string]string{"aws:SourceIp": "10.1.2.3"},
		})
		if !allowed.Allowed {
			t.Fatalf("expected allowed from 10.x IP, got: %s", allowed.Reason)
		}

		// Request from disallowed IP
		denied := e2.EvaluateAccess(&IAMEvalRequest{
			Principal: "ivan",
			Action:    "s3:GetObject",
			Resource:  "arn:velocity:s3:::mybucket/file.txt",
			Context:   map[string]string{"aws:SourceIp": "192.168.1.1"},
		})
		if denied.Allowed {
			t.Fatal("expected denied from non-10.x IP")
		}
	})

	t.Run("AttachGroupPolicy and DetachGroupPolicy", func(t *testing.T) {
		db2 := openTestDB(t)
		defer db2.Close()
		e2 := NewIAMPolicyEngine(db2)

		polName := "group-policy"
		if err := e2.CreatePolicy(makePolicy(polName, IAMEffectAllow,
			[]string{"s3:ListBucket"}, []string{"*"})); err != nil {
			t.Fatal(err)
		}

		if err := e2.AttachGroupPolicy("admins", polName); err != nil {
			t.Fatalf("AttachGroupPolicy: %v", err)
		}

		// Idempotent
		if err := e2.AttachGroupPolicy("admins", polName); err != nil {
			t.Fatalf("re-attach group policy should be idempotent: %v", err)
		}

		// Non-existent policy
		if err := e2.AttachGroupPolicy("admins", "no-such"); err == nil {
			t.Fatal("expected error for non-existent policy on group attach")
		}

		// Detach
		if err := e2.DetachGroupPolicy("admins", polName); err != nil {
			t.Fatalf("DetachGroupPolicy: %v", err)
		}

		// Detach again should fail
		if err := e2.DetachGroupPolicy("admins", polName); err == nil {
			t.Fatal("expected error when detaching already-detached group policy")
		}
	})
}

// ---------------------------------------------------------------------------
// 2. MetricsCollector tests
// ---------------------------------------------------------------------------

func TestMetricsCollector(t *testing.T) {
	t.Run("NewMetricsCollector creates instance", func(t *testing.T) {
		mc := NewMetricsCollector()
		if mc == nil {
			t.Fatal("expected non-nil MetricsCollector")
		}
		if mc.requestDuration == nil {
			t.Fatal("expected requestDuration histogram to be initialized")
		}
		if mc.metricHelp == nil || mc.metricType == nil {
			t.Fatal("expected metric metadata maps to be initialized")
		}
	})

	t.Run("RecordRequest increments counter", func(t *testing.T) {
		mc := NewMetricsCollector()

		mc.RecordRequest("GET", "200", 50*time.Millisecond)
		mc.RecordRequest("GET", "200", 100*time.Millisecond)
		mc.RecordRequest("POST", "201", 200*time.Millisecond)

		// Verify by rendering and checking the output
		output := mc.RenderMetrics()
		if !strings.Contains(output, "velocity_requests_total") {
			t.Fatal("expected velocity_requests_total in output")
		}
		// GET 200 should have count 2
		if !strings.Contains(output, `velocity_requests_total{method="GET",status="200"} 2`) {
			t.Fatalf("expected GET/200 counter = 2 in output:\n%s", output)
		}
		// POST 201 should have count 1
		if !strings.Contains(output, `velocity_requests_total{method="POST",status="201"} 1`) {
			t.Fatalf("expected POST/201 counter = 1 in output:\n%s", output)
		}
	})

	t.Run("RecordRequest records histogram observation", func(t *testing.T) {
		mc := NewMetricsCollector()

		mc.RecordRequest("GET", "200", 50*time.Millisecond)

		output := mc.RenderMetrics()
		if !strings.Contains(output, "velocity_request_duration_seconds") {
			t.Fatal("expected histogram metric in output")
		}
		if !strings.Contains(output, "velocity_request_duration_seconds_count 1") {
			t.Fatalf("expected histogram count = 1 in output:\n%s", output)
		}
		if !strings.Contains(output, "velocity_request_duration_seconds_bucket") {
			t.Fatalf("expected histogram buckets in output:\n%s", output)
		}
	})

	t.Run("RenderMetrics produces valid Prometheus format", func(t *testing.T) {
		mc := NewMetricsCollector()
		mc.RecordRequest("PUT", "200", 10*time.Millisecond)

		output := mc.RenderMetrics()
		if !strings.Contains(output, "# HELP") {
			t.Fatal("expected # HELP line in Prometheus output")
		}
		if !strings.Contains(output, "# TYPE") {
			t.Fatal("expected # TYPE line in Prometheus output")
		}
		if !strings.Contains(output, "velocity_requests_total") {
			t.Fatal("expected velocity_requests_total metric name")
		}
		if !strings.Contains(output, "velocity_request_duration_seconds") {
			t.Fatal("expected velocity_request_duration_seconds metric name")
		}
		// HELP and TYPE for histogram
		if !strings.Contains(output, "# HELP velocity_request_duration_seconds") {
			t.Fatal("expected HELP for histogram")
		}
		if !strings.Contains(output, "# TYPE velocity_request_duration_seconds histogram") {
			t.Fatal("expected TYPE histogram")
		}
	})

	t.Run("Multiple requests with different methods and statuses produce separate counter lines", func(t *testing.T) {
		mc := NewMetricsCollector()
		mc.RecordRequest("GET", "200", 5*time.Millisecond)
		mc.RecordRequest("GET", "404", 3*time.Millisecond)
		mc.RecordRequest("POST", "200", 10*time.Millisecond)
		mc.RecordRequest("DELETE", "204", 8*time.Millisecond)

		output := mc.RenderMetrics()
		lines := strings.Split(output, "\n")

		expectedLabels := []string{
			`method="GET",status="200"`,
			`method="GET",status="404"`,
			`method="POST",status="200"`,
			`method="DELETE",status="204"`,
		}

		for _, label := range expectedLabels {
			found := false
			for _, line := range lines {
				if strings.Contains(line, label) && strings.Contains(line, "velocity_requests_total") {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected counter line with labels %q in output:\n%s", label, output)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 3. StorageTierManager tests
// ---------------------------------------------------------------------------

func TestStorageTierManager(t *testing.T) {
	t.Run("PutBucketLifecycle and GetBucketLifecycle roundtrip", func(t *testing.T) {
		db := openTestDB(t)
		defer db.Close()
		stm := NewStorageTierManager(db, time.Hour)

		config := &LifecycleConfig{
			Rules: []LifecycleRule{
				{
					ID:     "archive-30d",
					Status: "Enabled",
					Filter: LifecycleRuleFilter{Prefix: "logs/"},
					Transitions: []Transition{
						{Days: 30, StorageClass: ClassGlacier},
					},
				},
			},
		}
		if err := stm.PutBucketLifecycle("my-bucket", config); err != nil {
			t.Fatalf("PutBucketLifecycle: %v", err)
		}

		got, err := stm.GetBucketLifecycle("my-bucket")
		if err != nil {
			t.Fatalf("GetBucketLifecycle: %v", err)
		}
		if got == nil {
			t.Fatal("expected non-nil lifecycle config")
		}
		if len(got.Rules) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(got.Rules))
		}
		if got.Rules[0].ID != "archive-30d" {
			t.Fatalf("expected rule ID %q, got %q", "archive-30d", got.Rules[0].ID)
		}
		if got.Rules[0].Status != "Enabled" {
			t.Fatalf("expected Enabled status, got %q", got.Rules[0].Status)
		}
		if len(got.Rules[0].Transitions) != 1 {
			t.Fatalf("expected 1 transition, got %d", len(got.Rules[0].Transitions))
		}
		if got.Rules[0].Transitions[0].StorageClass != ClassGlacier {
			t.Fatalf("expected GLACIER, got %q", got.Rules[0].Transitions[0].StorageClass)
		}
	})

	t.Run("DeleteBucketLifecycle", func(t *testing.T) {
		db := openTestDB(t)
		defer db.Close()
		stm := NewStorageTierManager(db, time.Hour)

		config := &LifecycleConfig{
			Rules: []LifecycleRule{
				{ID: "rule1", Status: "Enabled", Transitions: []Transition{
					{Days: 10, StorageClass: ClassInfrequentAccess},
				}},
			},
		}
		if err := stm.PutBucketLifecycle("del-bucket", config); err != nil {
			t.Fatal(err)
		}
		if err := stm.DeleteBucketLifecycle("del-bucket"); err != nil {
			t.Fatalf("DeleteBucketLifecycle: %v", err)
		}
		got, err := stm.GetBucketLifecycle("del-bucket")
		if err != nil {
			t.Fatalf("GetBucketLifecycle after delete: %v", err)
		}
		if got != nil {
			t.Fatal("expected nil config after delete")
		}
	})

	t.Run("PutBucketLifecycle validates rules - duplicate IDs", func(t *testing.T) {
		db := openTestDB(t)
		defer db.Close()
		stm := NewStorageTierManager(db, time.Hour)

		config := &LifecycleConfig{
			Rules: []LifecycleRule{
				{ID: "dup", Status: "Enabled", Transitions: []Transition{
					{Days: 30, StorageClass: ClassGlacier},
				}},
				{ID: "dup", Status: "Enabled", Transitions: []Transition{
					{Days: 60, StorageClass: ClassDeepArchive},
				}},
			},
		}
		err := stm.PutBucketLifecycle("val-bucket", config)
		if err == nil {
			t.Fatal("expected error for duplicate rule IDs")
		}
		if !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("PutBucketLifecycle validates rules - invalid status", func(t *testing.T) {
		db := openTestDB(t)
		defer db.Close()
		stm := NewStorageTierManager(db, time.Hour)

		config := &LifecycleConfig{
			Rules: []LifecycleRule{
				{ID: "bad-status", Status: "Active"},
			},
		}
		err := stm.PutBucketLifecycle("val-bucket2", config)
		if err == nil {
			t.Fatal("expected error for invalid status")
		}
		if !strings.Contains(err.Error(), "status") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("PutBucketLifecycle validates rules - invalid storage class", func(t *testing.T) {
		db := openTestDB(t)
		defer db.Close()
		stm := NewStorageTierManager(db, time.Hour)

		config := &LifecycleConfig{
			Rules: []LifecycleRule{
				{ID: "bad-class", Status: "Enabled", Transitions: []Transition{
					{Days: 30, StorageClass: "INVALID_CLASS"},
				}},
			},
		}
		err := stm.PutBucketLifecycle("val-bucket3", config)
		if err == nil {
			t.Fatal("expected error for invalid storage class")
		}
		if !strings.Contains(err.Error(), "invalid storage class") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("TransitionObject changes storage class", func(t *testing.T) {
		db := openTestDB(t)
		defer db.Close()
		stm := NewStorageTierManager(db, time.Hour)
		createTestBuckets(t, db, "transition-bucket")

		// Store an object with STANDARD class
		storeTestObject(t, db, "transition-bucket/myfile.txt", "text/plain",
			[]byte("hello"), &ObjectOptions{
				StorageClass:    ClassStandard,
				SystemOperation: true,
			})

		// Transition to GLACIER
		if err := stm.TransitionObject("transition-bucket/myfile.txt", ClassGlacier); err != nil {
			t.Fatalf("TransitionObject: %v", err)
		}

		meta, err := db.GetObjectMetadata("transition-bucket/myfile.txt")
		if err != nil {
			t.Fatalf("GetObjectMetadata: %v", err)
		}
		if meta.StorageClass != ClassGlacier {
			t.Fatalf("expected storage class %q, got %q", ClassGlacier, meta.StorageClass)
		}
	})

	t.Run("TransitionObject rejects warmer transitions", func(t *testing.T) {
		db := openTestDB(t)
		defer db.Close()
		stm := NewStorageTierManager(db, time.Hour)
		createTestBuckets(t, db, "warm-bucket")

		storeTestObject(t, db, "warm-bucket/frozen.dat", "application/octet-stream",
			[]byte("frozen"), &ObjectOptions{
				StorageClass:    ClassGlacier,
				SystemOperation: true,
			})

		err := stm.TransitionObject("warm-bucket/frozen.dat", ClassStandard)
		if err == nil {
			t.Fatal("expected error when transitioning to warmer class")
		}
		if !strings.Contains(err.Error(), "must be colder") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("GetLifecycleStatus returns stats", func(t *testing.T) {
		db := openTestDB(t)
		defer db.Close()
		stm := NewStorageTierManager(db, time.Hour)

		status := stm.GetLifecycleStatus()
		if status.Running {
			t.Fatal("expected not running")
		}
		if status.ObjectsTransitioned != 0 {
			t.Fatalf("expected 0 transitioned, got %d", status.ObjectsTransitioned)
		}
		if status.ObjectsExpired != 0 {
			t.Fatalf("expected 0 expired, got %d", status.ObjectsExpired)
		}
		if status.EvaluationInterval == "" {
			t.Fatal("expected non-empty evaluation interval")
		}
	})
}

// ---------------------------------------------------------------------------
// 4. LoadBalancer tests
// ---------------------------------------------------------------------------

func TestLoadBalancer(t *testing.T) {
	setupCluster := func(t *testing.T) (*DB, *ClusterManager) {
		t.Helper()
		db := openTestDB(t)
		cm := NewClusterManager(db, ClusterConfig{
			NodeID:      "node1",
			BindAddress: "127.0.0.1:0",
			APIAddress:  "127.0.0.1:0",
		})
		// Set node1 to active
		cm.localNode.State = NodeStateActive

		// Add more nodes directly to the ring and nodes map
		for _, id := range []string{"node2", "node3"} {
			cm.ring.AddNode(id)
			cm.mu.Lock()
			cm.nodes[id] = &ClusterNode{
				ID:      id,
				Address: "127.0.0.1:0",
				State:   NodeStateActive,
			}
			cm.mu.Unlock()
		}
		return db, cm
	}

	t.Run("NewLoadBalancer with each strategy", func(t *testing.T) {
		db, cm := setupCluster(t)
		defer db.Close()

		strategies := []LoadBalanceStrategy{
			StrategyConsistentHash,
			StrategyRoundRobin,
			StrategyLeastLoad,
			StrategyRandom,
		}
		for _, s := range strategies {
			lb := NewLoadBalancer(cm, s)
			if lb == nil {
				t.Fatalf("expected non-nil LoadBalancer for strategy %d", s)
			}
			if lb.strategy != s {
				t.Fatalf("expected strategy %d, got %d", s, lb.strategy)
			}
		}
	})

	t.Run("GetNode with consistent hash returns same node for same key", func(t *testing.T) {
		db, cm := setupCluster(t)
		defer db.Close()
		lb := NewLoadBalancer(cm, StrategyConsistentHash)

		key := "bucket/my-object.txt"
		first := lb.GetNode(key)
		if first == nil {
			t.Fatal("expected non-nil node")
		}

		// Same key should always return the same node
		for i := 0; i < 50; i++ {
			node := lb.GetNode(key)
			if node.ID != first.ID {
				t.Fatalf("iteration %d: expected node %q, got %q", i, first.ID, node.ID)
			}
		}
	})

	t.Run("GetNode with round robin distributes across nodes", func(t *testing.T) {
		db, cm := setupCluster(t)
		defer db.Close()
		lb := NewLoadBalancer(cm, StrategyRoundRobin)

		seen := make(map[string]int)
		iterations := 30
		for i := 0; i < iterations; i++ {
			node := lb.GetNode("")
			if node == nil {
				t.Fatal("expected non-nil node from round robin")
			}
			seen[node.ID]++
		}

		// With 3 nodes and 30 iterations, each should get ~10
		if len(seen) < 3 {
			t.Fatalf("expected all 3 nodes to be selected, only got %d: %v", len(seen), seen)
		}
		for id, count := range seen {
			if count == 0 {
				t.Fatalf("node %q was never selected", id)
			}
		}
	})

	t.Run("GetReadNodes returns requested count", func(t *testing.T) {
		db, cm := setupCluster(t)
		defer db.Close()
		lb := NewLoadBalancer(cm, StrategyConsistentHash)

		nodes := lb.GetReadNodes("some-key", 2)
		if len(nodes) != 2 {
			t.Fatalf("expected 2 read nodes, got %d", len(nodes))
		}

		// All 3
		all := lb.GetReadNodes("some-key", 3)
		if len(all) != 3 {
			t.Fatalf("expected 3 read nodes, got %d", len(all))
		}

		// Request more than available — capped
		capped := lb.GetReadNodes("some-key", 10)
		if len(capped) != 3 {
			t.Fatalf("expected capped to 3 read nodes, got %d", len(capped))
		}
	})

	t.Run("GetWriteNodes returns requested count", func(t *testing.T) {
		db, cm := setupCluster(t)
		defer db.Close()
		lb := NewLoadBalancer(cm, StrategyRoundRobin)

		nodes := lb.GetWriteNodes("key", 2)
		if len(nodes) != 2 {
			t.Fatalf("expected 2 write nodes, got %d", len(nodes))
		}

		all := lb.GetWriteNodes("key", 3)
		if len(all) != 3 {
			t.Fatalf("expected 3 write nodes, got %d", len(all))
		}
	})

	t.Run("HealthFilter filters out non-active nodes", func(t *testing.T) {
		nodes := []*ClusterNode{
			{ID: "a", State: NodeStateActive},
			{ID: "b", State: NodeStateDown},
			{ID: "c", State: NodeStateActive},
			{ID: "d", State: NodeStateLeaving},
			{ID: "e", State: NodeStateJoining},
		}
		healthy := HealthFilter(nodes)
		if len(healthy) != 2 {
			t.Fatalf("expected 2 healthy nodes, got %d", len(healthy))
		}
		for _, n := range healthy {
			if n.State != NodeStateActive {
				t.Fatalf("expected only active nodes, got state %d for %q", n.State, n.ID)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 5. BucketReplicationManager tests
// ---------------------------------------------------------------------------

func TestBucketReplicationManager(t *testing.T) {
	t.Run("PutReplicationConfig and GetReplicationConfig roundtrip", func(t *testing.T) {
		db := openTestDB(t)
		defer db.Close()
		createTestBuckets(t, db, "src-bucket", "dst-bucket")
		brm := NewBucketReplicationManager(db)

		config := &BucketReplicationConfig{
			SourceBucket: "src-bucket",
			Rules: []ReplicationRule{
				{
					ID:                "rule-1",
					Status:            ReplicationRuleEnabled,
					Priority:          1,
					SourceBucket:      "src-bucket",
					DestinationBucket: "dst-bucket",
					Prefix:            "logs/",
				},
			},
		}
		if err := brm.PutReplicationConfig(config); err != nil {
			t.Fatalf("PutReplicationConfig: %v", err)
		}

		got, err := brm.GetReplicationConfig("src-bucket")
		if err != nil {
			t.Fatalf("GetReplicationConfig: %v", err)
		}
		if got.SourceBucket != "src-bucket" {
			t.Fatalf("expected source bucket %q, got %q", "src-bucket", got.SourceBucket)
		}
		if len(got.Rules) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(got.Rules))
		}
		if got.Rules[0].ID != "rule-1" {
			t.Fatalf("expected rule ID %q, got %q", "rule-1", got.Rules[0].ID)
		}
		if got.Rules[0].DestinationBucket != "dst-bucket" {
			t.Fatalf("expected dest bucket %q, got %q", "dst-bucket", got.Rules[0].DestinationBucket)
		}
		if got.Rules[0].Prefix != "logs/" {
			t.Fatalf("expected prefix %q, got %q", "logs/", got.Rules[0].Prefix)
		}
	})

	t.Run("DeleteReplicationConfig", func(t *testing.T) {
		db := openTestDB(t)
		defer db.Close()
		createTestBuckets(t, db, "src-del", "dst-del")
		brm := NewBucketReplicationManager(db)

		config := &BucketReplicationConfig{
			SourceBucket: "src-del",
			Rules: []ReplicationRule{{
				ID:                "r1",
				Status:            ReplicationRuleEnabled,
				SourceBucket:      "src-del",
				DestinationBucket: "dst-del",
			}},
		}
		if err := brm.PutReplicationConfig(config); err != nil {
			t.Fatal(err)
		}

		if err := brm.DeleteReplicationConfig("src-del"); err != nil {
			t.Fatalf("DeleteReplicationConfig: %v", err)
		}

		_, err := brm.GetReplicationConfig("src-del")
		if err == nil {
			t.Fatal("expected error after delete")
		}

		// Delete non-existent should error
		if err := brm.DeleteReplicationConfig("src-del"); err == nil {
			t.Fatal("expected error when deleting non-existent config")
		}
	})

	t.Run("FilterObjects matches prefix and tags", func(t *testing.T) {
		db := openTestDB(t)
		defer db.Close()
		brm := NewBucketReplicationManager(db)

		rule := &ReplicationRule{
			ID:           "filter-rule",
			SourceBucket: "test-bucket",
			Prefix:       "docs/",
			TagFilter:    map[string]string{"env": "production"},
		}

		// Matching object
		metaMatch := &ObjectMetadata{
			Path: "test-bucket/docs/readme.md",
			Tags: map[string]string{"env": "production", "team": "eng"},
		}
		if !brm.FilterObjects(rule, "test-bucket/docs/readme.md", metaMatch) {
			t.Fatal("expected filter to match object with correct prefix and tags")
		}

		// Non-matching prefix
		metaNoPrefix := &ObjectMetadata{
			Path: "test-bucket/images/photo.jpg",
			Tags: map[string]string{"env": "production"},
		}
		if brm.FilterObjects(rule, "test-bucket/images/photo.jpg", metaNoPrefix) {
			t.Fatal("expected filter to reject object with wrong prefix")
		}

		// Non-matching tag
		metaNoTag := &ObjectMetadata{
			Path: "test-bucket/docs/draft.md",
			Tags: map[string]string{"env": "staging"},
		}
		if brm.FilterObjects(rule, "test-bucket/docs/draft.md", metaNoTag) {
			t.Fatal("expected filter to reject object with wrong tag value")
		}

		// No tags at all
		metaEmpty := &ObjectMetadata{
			Path: "test-bucket/docs/file.md",
		}
		if brm.FilterObjects(rule, "test-bucket/docs/file.md", metaEmpty) {
			t.Fatal("expected filter to reject object with no tags")
		}

		// Nil metadata
		if brm.FilterObjects(rule, "test-bucket/docs/x.md", nil) {
			t.Fatal("expected filter to reject nil metadata")
		}
	})

	t.Run("ProcessReplication stores object in destination bucket", func(t *testing.T) {
		db := openTestDB(t)
		defer db.Close()
		createTestBuckets(t, db, "repl-src", "repl-dst")
		brm := NewBucketReplicationManager(db)

		config := &BucketReplicationConfig{
			SourceBucket: "repl-src",
			Rules: []ReplicationRule{{
				ID:                "repl-rule",
				Status:            ReplicationRuleEnabled,
				Priority:          1,
				SourceBucket:      "repl-src",
				DestinationBucket: "repl-dst",
			}},
		}
		if err := brm.PutReplicationConfig(config); err != nil {
			t.Fatal(err)
		}

		// Store the source object
		srcData := []byte("replicated content")
		srcMeta := storeTestObject(t, db, "repl-src/file.txt", "text/plain",
			srcData, &ObjectOptions{
				StorageClass:    ClassStandard,
				SystemOperation: true,
			})

		// Process replication
		status, err := brm.ProcessReplication("repl-src", "repl-src/file.txt", srcData, srcMeta)
		if err != nil {
			t.Fatalf("ProcessReplication: %v", err)
		}
		if status == nil {
			t.Fatal("expected non-nil replication status")
		}
		if len(status.RuleStatuses) != 1 {
			t.Fatalf("expected 1 rule status, got %d", len(status.RuleStatuses))
		}

		rs, ok := status.RuleStatuses["repl-rule"]
		if !ok {
			t.Fatal("expected rule status for 'repl-rule'")
		}
		if rs.Status != ReplicationStatusComplete {
			t.Fatalf("expected COMPLETE status, got %q (err: %s)", rs.Status, rs.ErrorMessage)
		}

		// Verify the object exists in the destination bucket
		destMeta, err := db.GetObjectMetadata("repl-dst/file.txt")
		if err != nil {
			t.Fatalf("expected replicated object in destination: %v", err)
		}
		if destMeta.ContentType != "text/plain" {
			t.Fatalf("expected content type %q, got %q", "text/plain", destMeta.ContentType)
		}
	})

	t.Run("AddRule RemoveRule GetRule", func(t *testing.T) {
		db := openTestDB(t)
		defer db.Close()
		createTestBuckets(t, db, "rule-src", "rule-dst-a", "rule-dst-b")
		brm := NewBucketReplicationManager(db)

		// Start with one rule
		config := &BucketReplicationConfig{
			SourceBucket: "rule-src",
			Rules: []ReplicationRule{{
				ID:                "initial-rule",
				Status:            ReplicationRuleEnabled,
				SourceBucket:      "rule-src",
				DestinationBucket: "rule-dst-a",
			}},
		}
		if err := brm.PutReplicationConfig(config); err != nil {
			t.Fatal(err)
		}

		// GetRule
		r, err := brm.GetRule("rule-src", "initial-rule")
		if err != nil {
			t.Fatalf("GetRule: %v", err)
		}
		if r.ID != "initial-rule" {
			t.Fatalf("expected rule ID %q, got %q", "initial-rule", r.ID)
		}

		// AddRule
		if err := brm.AddRule("rule-src", ReplicationRule{
			ID:                "added-rule",
			Status:            ReplicationRuleEnabled,
			SourceBucket:      "rule-src",
			DestinationBucket: "rule-dst-b",
		}); err != nil {
			t.Fatalf("AddRule: %v", err)
		}

		got, err := brm.GetReplicationConfig("rule-src")
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Rules) != 2 {
			t.Fatalf("expected 2 rules after add, got %d", len(got.Rules))
		}

		// RemoveRule
		if err := brm.RemoveRule("rule-src", "initial-rule"); err != nil {
			t.Fatalf("RemoveRule: %v", err)
		}

		got, err = brm.GetReplicationConfig("rule-src")
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Rules) != 1 {
			t.Fatalf("expected 1 rule after remove, got %d", len(got.Rules))
		}
		if got.Rules[0].ID != "added-rule" {
			t.Fatalf("expected remaining rule %q, got %q", "added-rule", got.Rules[0].ID)
		}

		// GetRule non-existent
		_, err = brm.GetRule("rule-src", "initial-rule")
		if err == nil {
			t.Fatal("expected error for removed rule")
		}

		// RemoveRule non-existent
		if err := brm.RemoveRule("rule-src", "ghost"); err == nil {
			t.Fatal("expected error for removing non-existent rule")
		}
	})
}
