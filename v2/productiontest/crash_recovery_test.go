package productiontest

import (
	"bufio"
	"context"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	cryptoxchacha "github.com/oarkflow/velocity/v2/plugins/crypto-xchacha"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
)

// buildCrashHarness compiles the crashharness helper binary once per test
// run and returns its path.
func buildCrashHarness(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "crashharness")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/crashharness")
	cmd.Dir, _ = os.Getwd()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building crashharness: %v\n%s", err, out)
	}
	return bin
}

// TestCrashRecovery_SIGKILLMidWrite boots the crashharness in a real child
// process, SIGKILLs it after a randomized number of acknowledged writes,
// then reopens the same data directory in-process and verifies every
// acknowledged write survived — proving durability across an actual
// process death, not just an in-process simulated failure.
func TestCrashRecovery_SIGKILLMidWrite(t *testing.T) {
	bin := buildCrashHarness(t)

	seeds := []int64{1, 2, 3, 4, 5}
	for i, seed := range seeds {
		t.Run("run"+strconv.Itoa(i), func(t *testing.T) {
			dir := t.TempDir()
			cmd := exec.Command(bin, dir)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}

			// Randomized kill point: let it write a random number of
			// ACKed records (bounded, so the test stays fast) before
			// killing it — different each run via a distinct seed.
			rng := rand.New(rand.NewSource(seed))
			target := 50 + rng.Intn(200)

			var lastAcked int = -1
			sc := bufio.NewScanner(stdout)
			for sc.Scan() {
				line := sc.Text()
				if !strings.HasPrefix(line, "ACK ") {
					continue
				}
				n, err := strconv.Atoi(strings.TrimPrefix(line, "ACK "))
				if err != nil {
					continue
				}
				lastAcked = n
				if n >= target {
					break
				}
			}
			if lastAcked < 0 {
				t.Fatalf("child never acknowledged a single write before we stopped reading")
			}

			// Hard kill — SIGKILL, not SIGTERM: we're proving crash
			// safety, not graceful-shutdown safety.
			_ = cmd.Process.Signal(syscall.SIGKILL)
			_ = cmd.Wait()

			// Reopen the SAME data directory in-process (a fresh kernel,
			// simulating "the service restarted after a crash") and
			// verify every key 0..lastAcked is present and correct.
			manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
				{Name: "storage-lsm", Enabled: true, Config: map[string]any{"dir": dir, "always_sync": true}},
				{Name: "crypto-xchacha", Enabled: true, Config: map[string]any{"key": "crashharness-demo-key-32-bytes!!"}},
				{Name: "kv", Enabled: true},
			}}
			k := kernel.New(manifest)
			plugins := []api.Plugin{storagelsm.New(), cryptoxchacha.New(), kv.New("storage-lsm")}
			ctx := context.Background()
			if err := k.Boot(ctx, plugins, manifest.Enabled()); err != nil {
				t.Fatalf("reboot after crash failed (this itself is a durability bug): %v", err)
			}
			defer k.Shutdown(ctx)

			kvSvc := k.Registry().MustLookup("kv").(api.KVService)
			missing := 0
			for n := 0; n <= lastAcked; n++ {
				key := "crash:key:" + strconv.Itoa(n)
				val, found, err := kvSvc.Get(ctx, key)
				if err != nil {
					t.Fatalf("Get(%s): %v", key, err)
				}
				if !found {
					missing++
					continue
				}
				want := "value-" + strconv.Itoa(n)
				if string(val) != want {
					t.Fatalf("key %s: got %q, want %q (data corruption, not just loss)", key, val, want)
				}
			}
			if missing > 0 {
				t.Fatalf("seed=%d target=%d lastAcked=%d: %d/%d acknowledged writes LOST after SIGKILL — durability violated",
					seed, target, lastAcked, missing, lastAcked+1)
			}
			t.Logf("seed=%d: %d acknowledged writes, all survived SIGKILL + reboot", seed, lastAcked+1)
		})
	}
}
