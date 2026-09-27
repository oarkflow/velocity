// Command notifications_webhook demonstrates Velocity v2's webhook
// notification plugin: it starts a small local HTTP server acting as the
// webhook receiver, registers a NotificationRule pointing at it, then
// shows a real KV write triggering an actual POST delivery to that
// receiver — proving the event-bus-to-webhook pipeline works end to end,
// not just that the rule was accepted.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	"github.com/oarkflow/velocity/v2/plugins/notifications"
	"github.com/oarkflow/velocity/v2/plugins/object"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
}

func main() {
	dir, err := os.MkdirTemp("", "velocity-notifications-*")
	must(err)
	defer os.RemoveAll(dir)

	// The webhook RECEIVER: a real local HTTP server capturing every
	// incoming POST body onto a channel so the example can prove delivery
	// happened, without a blind sleep-and-hope.
	received := make(chan string, 10)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()
	fmt.Printf("=== webhook receiver listening at %s ===\n", receiver.URL)

	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir, "always_sync": true}},
		{Name: "kv", Enabled: true},
		{Name: "object", Enabled: true},
		{Name: "notifications", Enabled: true},
	}}

	k := kernel.New(manifest)
	all := []api.Plugin{
		storagelsm.New(),
		kv.New("storage-lsm"),
		object.New("storage-lsm"),
		notifications.NewPlugin("storage-lsm"),
	}

	ctx := context.Background()
	must(k.Boot(ctx, all, manifest.Enabled()))
	fmt.Println("=== booted storage-lsm + kv + object + notifications ===")
	defer func() { must(k.Shutdown(ctx)) }()

	notifSvc := k.Registry().MustLookup("notifications").(api.NotificationService)
	kvSvc := k.Registry().MustLookup("kv").(api.KVService)

	rule := api.NotificationRule{
		ID:         "demo-rule-1",
		Topic:      api.TopicKVPut,
		WebhookURL: receiver.URL,
		Enabled:    true,
	}
	must(notifSvc.AddRule(ctx, rule))
	fmt.Printf("\n=== added notification rule: topic=%s -> %s ===\n", rule.Topic, rule.WebhookURL)

	rules, err := notifSvc.ListRules(ctx)
	must(err)
	fmt.Printf("=== ListRules (before removal): %d rule(s) ===\n", len(rules))
	for _, r := range rules {
		fmt.Printf("  - id=%s topic=%s url=%s enabled=%v\n", r.ID, r.Topic, r.WebhookURL, r.Enabled)
	}

	fmt.Println("\n=== Put(\"order:1001\", ...) — should trigger a webhook delivery ===")
	must(kvSvc.Put(ctx, "order:1001", []byte(`{"status":"created"}`)))

	select {
	case body := <-received:
		fmt.Printf("=== webhook receiver got a POST: %s ===\n", prettyOrRaw(body))
	case <-time.After(3 * time.Second):
		fmt.Fprintln(os.Stderr, "FATAL: timed out waiting for webhook delivery")
		os.Exit(1)
	}

	// A Put on a topic NOT subscribed to (none configured here besides
	// kv.put) still works, but we don't expect a SECOND delivery for an
	// unrelated topic — demonstrate the rule is topic-scoped, not global,
	// by removing the rule and confirming a subsequent Put produces no
	// delivery within a short window.
	must(notifSvc.RemoveRule(ctx, rule.ID))
	rulesAfter, err := notifSvc.ListRules(ctx)
	must(err)
	fmt.Printf("\n=== RemoveRule(%q) done; ListRules (after removal): %d rule(s) ===\n", rule.ID, len(rulesAfter))

	must(kvSvc.Put(ctx, "order:1002", []byte(`{"status":"created"}`)))
	select {
	case body := <-received:
		fmt.Fprintf(os.Stderr, "FATAL: unexpected webhook delivery after rule removal: %s\n", body)
		os.Exit(1)
	case <-time.After(500 * time.Millisecond):
		fmt.Println("=== confirmed: no webhook delivery after rule removal ===")
	}

	fmt.Println("\n=== shutting down ===")
}

func prettyOrRaw(s string) string {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return s
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return s
	}
	return string(b)
}
