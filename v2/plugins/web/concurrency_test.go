package web

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestConcurrentHTTPRequests fires many concurrent client goroutines at
// the SAME running handler (a mix of KV Put/Get and Object bucket/PutObject/
// GetObject requests) via net/http's standard one-goroutine-per-request
// server model — every response must be correct, and the underlying fakes
// (fakeKV/fakeObjectStore) are already mutex-guarded, so this proves the
// web plugin's own request handling introduces no additional data race on
// top of that (run under -race).
func TestConcurrentHTTPRequests(t *testing.T) {
	p, _, _ := newTestPlugin(t, false, false)
	rt, err := p.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	srv := httptest.NewServer(rt.mux)
	defer srv.Close()

	const n = 60
	var wg sync.WaitGroup

	// Half the goroutines exercise KV Put-then-Get on distinct keys.
	for i := 0; i < n/2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("ckey-%03d", i)
			val := fmt.Sprintf("cval-%03d", i)

			req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/kv/"+key, strings.NewReader(val))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Errorf("PUT %s: %v", key, err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("PUT %s: status=%d, want 204", key, resp.StatusCode)
				return
			}

			resp, err = http.Get(srv.URL + "/api/kv/" + key)
			if err != nil {
				t.Errorf("GET %s: %v", key, err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("GET %s: status=%d, want 200", key, resp.StatusCode)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			if string(body) != val {
				t.Errorf("GET %s: got %q, want %q", key, body, val)
			}
		}(i)
	}

	// The other half exercise bucket-create + object Put-then-Get on
	// distinct object keys within a SHARED bucket (created once, up
	// front, so we're only stressing concurrent object writes/reads, not
	// concurrent bucket creation semantics — that's covered by
	// plugins/object's own concurrency tests).
	bucketReq, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/buckets/shared", nil)
	bucketResp, err := http.DefaultClient.Do(bucketReq)
	if err != nil {
		t.Fatalf("create shared bucket: %v", err)
	}
	bucketResp.Body.Close()

	for i := 0; i < n/2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("okey-%03d", i)
			val := fmt.Sprintf("oval-%03d", i)

			req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/buckets/shared/objects/"+key, strings.NewReader(val))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Errorf("PUT object %s: %v", key, err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				t.Errorf("PUT object %s: status=%d, want 201", key, resp.StatusCode)
				return
			}

			resp, err = http.Get(srv.URL + "/api/buckets/shared/objects/" + key)
			if err != nil {
				t.Errorf("GET object %s: %v", key, err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("GET object %s: status=%d, want 200", key, resp.StatusCode)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			if string(body) != val {
				t.Errorf("GET object %s: got %q, want %q", key, body, val)
			}
		}(i)
	}

	wg.Wait()
}
