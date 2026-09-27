// Command full_server is the flagship Velocity v2 example: it boots a
// realistic server-shaped subset of the plugin set in-process, then drives
// the real HTTP API with actual net/http requests (not curl) to prove the
// kernel + web gateway work together end to end.
//
// Included plugins: storage-lsm (durable KV/object backend), crypto-xchacha
// (secrets encryption), kv, object, secret, auth-jwt (JWT issuance +
// verification), compliance (audit trail), metrics (Prometheus), web (the
// HTTP gateway tying it all together). Deliberately excluded to keep this
// example focused and fast to run: replication/sql/search/erasure/
// notifications — each has its own dedicated example under v2/examples/.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	authjwt "github.com/oarkflow/velocity/v2/plugins/auth-jwt"
	"github.com/oarkflow/velocity/v2/plugins/compliance"
	cryptoxchacha "github.com/oarkflow/velocity/v2/plugins/crypto-xchacha"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	"github.com/oarkflow/velocity/v2/plugins/metrics"
	"github.com/oarkflow/velocity/v2/plugins/object"
	"github.com/oarkflow/velocity/v2/plugins/secret"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
	"github.com/oarkflow/velocity/v2/plugins/web"
)

// addr is hardcoded to a high, unlikely-to-collide port for this demo.
const addr = "127.0.0.1:18090"

// jwtSecret is a fixed demo secret so this example is reproducible without
// external setup. A real deployment must never hardcode this — auth-jwt
// itself refuses to boot without an explicit secret (no built-in default),
// which is the point: load a real one from an env var or secret manager.
const jwtSecret = "full-server-example-demo-secret-DO-NOT-USE-IN-PRODUCTION!!"

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
}

func main() {
	dir, err := os.MkdirTemp("", "velocity-full-server-*")
	must(err)
	defer os.RemoveAll(dir)

	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir, "always_sync": true}},
		{Name: "crypto-xchacha", Enabled: true, Config: map[string]any{"key": "full-server-demo-key-is-32-bytes"}},
		{Name: "kv", Enabled: true},
		{Name: "object", Enabled: true},
		{Name: "secret", Enabled: true},
		{Name: "auth-jwt", Enabled: true, Config: map[string]any{"secret": jwtSecret}},
		{Name: "compliance", Enabled: true},
		{Name: "metrics", Enabled: true},
		{Name: "web", Enabled: true, Config: map[string]any{"addr": addr}},
	}}

	k := kernel.New(manifest)
	authPlugin := authjwt.New()

	all := []api.Plugin{
		storagelsm.New(),
		cryptoxchacha.New(),
		kv.New("storage-lsm"),
		object.New("storage-lsm"),
		secret.NewPlugin("storage-lsm", "crypto-xchacha"),
		authPlugin,
		compliance.NewPlugin("storage-lsm"),
		metrics.NewPlugin(),
		web.NewPlugin("kv", "object", "auth.jwt"),
	}

	fmt.Println("=== booting kernel with 9 plugins ===")
	must(k.Boot(context.Background(), all, manifest.Enabled()))
	fmt.Println("booted OK")

	defer func() {
		fmt.Println("\n=== shutting down ===")
		must(k.Shutdown(context.Background()))
		fmt.Println("stopped cleanly")
	}()

	// Start() already waits ~50ms internally before returning once the
	// HTTP listener is up; a small extra margin keeps this example robust
	// across slower machines.
	time.Sleep(100 * time.Millisecond)

	token, err := authPlugin.Issue("demo-user", []string{"admin"}, time.Hour)
	must(err)
	fmt.Printf("=== issued JWT for subject=demo-user roles=[admin] ===\n%s\n", token)

	client := &http.Client{Timeout: 5 * time.Second}

	fmt.Println("\n=== PUT /api/kv/greeting ===")
	doRequest(client, http.MethodPut, "/api/kv/greeting", []byte("hello from full_server"), token)

	fmt.Println("\n=== GET /api/kv/greeting ===")
	doRequest(client, http.MethodGet, "/api/kv/greeting", nil, token)

	fmt.Println("\n=== PUT /api/buckets/docs (create bucket) ===")
	doRequest(client, http.MethodPut, "/api/buckets/docs", nil, token)

	fmt.Println("\n=== PUT /api/buckets/docs/objects/readme.txt ===")
	doRequest(client, http.MethodPut, "/api/buckets/docs/objects/readme.txt", []byte("Velocity v2 full_server example"), token)

	fmt.Println("\n=== GET /api/buckets/docs/objects/readme.txt ===")
	doRequest(client, http.MethodGet, "/api/buckets/docs/objects/readme.txt", nil, token)

	fmt.Println("\n=== GET /metrics (Prometheus exposition) ===")
	resp, err := client.Get("http://" + addr + "/metrics")
	must(err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("status=%d\n%s\n", resp.StatusCode, truncate(string(body), 500))
}

func doRequest(client *http.Client, method, path string, body []byte, token string) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://"+addr+path, reader)
	must(err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	must(err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	fmt.Printf("%s %s -> status=%d body=%q\n", method, path, resp.StatusCode, truncate(string(respBody), 200))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "... (truncated)"
}
