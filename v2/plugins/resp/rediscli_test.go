package resp

import (
	"os/exec"
	"strings"
	"testing"
)

// runRedisCLI shells out to the REAL redis-cli binary (not a mock, not a
// Go client library) against our server — this is the actual proof of
// wire-protocol compatibility: redis-cli has no idea it isn't talking to
// real Redis.
func runRedisCLI(t *testing.T, addr string, args ...string) string {
	t.Helper()
	host, port, ok := strings.Cut(strings.TrimPrefix(addr, "[::]"), ":")
	if !ok {
		host, port = "127.0.0.1", strings.TrimPrefix(addr, ":")
	}
	if host == "" {
		host = "127.0.0.1"
	}
	fullArgs := append([]string{"-h", host, "-p", port}, args...)
	out, err := exec.Command("redis-cli", fullArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("redis-cli %v: %v\noutput: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestRealRedisCLI_BasicCommands(t *testing.T) {
	if _, err := exec.LookPath("redis-cli"); err != nil {
		t.Skip("redis-cli not on PATH in this environment")
	}
	addr, shutdown := bootTestServer(t, false)
	defer shutdown()

	if got := runRedisCLI(t, addr, "PING"); got != "PONG" {
		t.Fatalf("PING = %q, want PONG", got)
	}
	if got := runRedisCLI(t, addr, "SET", "foo", "bar"); got != "OK" {
		t.Fatalf("SET = %q, want OK", got)
	}
	if got := runRedisCLI(t, addr, "GET", "foo"); got != "bar" {
		t.Fatalf("GET = %q, want bar", got)
	}
	if got := runRedisCLI(t, addr, "INCR", "counter"); got != "1" {
		t.Fatalf("INCR = %q, want 1", got)
	}
	if got := runRedisCLI(t, addr, "INCR", "counter"); got != "2" {
		t.Fatalf("INCR again = %q, want 2", got)
	}
	if got := runRedisCLI(t, addr, "EXISTS", "foo"); got != "1" {
		t.Fatalf("EXISTS = %q, want 1", got)
	}
	if got := runRedisCLI(t, addr, "DEL", "foo"); got != "1" {
		t.Fatalf("DEL = %q, want 1", got)
	}
	if got := runRedisCLI(t, addr, "GET", "foo"); got != "" {
		t.Fatalf("GET after DEL = %q, want empty (nil)", got)
	}
	if got := runRedisCLI(t, addr, "SET", "temp", "v", "EX", "100"); got != "OK" {
		t.Fatalf("SET EX = %q, want OK", got)
	}
	if got := runRedisCLI(t, addr, "GET", "temp"); got != "v" {
		t.Fatalf("GET after SET EX = %q, want v", got)
	}
}

func TestRealRedisCLI_DataStructures(t *testing.T) {
	if _, err := exec.LookPath("redis-cli"); err != nil {
		t.Skip("redis-cli not on PATH in this environment")
	}
	addr, shutdown := bootTestServer(t, true)
	defer shutdown()

	// List
	if got := runRedisCLI(t, addr, "RPUSH", "mylist", "a", "b", "c"); got != "3" {
		t.Fatalf("RPUSH = %q, want 3", got)
	}
	// Note: redis-cli's non-interactive/scripted mode (no TTY, as used
	// here via exec.Command) prints array replies as plain newline-joined
	// lines, not the numbered "1) \"a\"" format its interactive REPL
	// shows — this is real, observed redis-cli behavior, not a server
	// defect. Confirmed by running it directly against this exact server.
	got := runRedisCLI(t, addr, "LRANGE", "mylist", "0", "-1")
	if got != "a\nb\nc" {
		t.Fatalf("LRANGE = %q", got)
	}

	// Set
	if got := runRedisCLI(t, addr, "SADD", "myset", "x", "y", "x"); got != "2" {
		t.Fatalf("SADD (with dup) = %q, want 2", got)
	}
	if got := runRedisCLI(t, addr, "SCARD", "myset"); got != "2" {
		t.Fatalf("SCARD = %q, want 2", got)
	}

	// Hash
	if got := runRedisCLI(t, addr, "HSET", "myhash", "f1", "v1"); got != "1" {
		t.Fatalf("HSET = %q, want 1", got)
	}
	if got := runRedisCLI(t, addr, "HGET", "myhash", "f1"); got != "v1" {
		t.Fatalf("HGET = %q, want v1", got)
	}

	// Sorted set
	if got := runRedisCLI(t, addr, "ZADD", "myzset", "1", "one", "2", "two"); got != "2" {
		t.Fatalf("ZADD = %q, want 2", got)
	}
	got = runRedisCLI(t, addr, "ZRANGE", "myzset", "0", "-1")
	if got != "one\ntwo" {
		t.Fatalf("ZRANGE = %q", got)
	}
}
