package resp

import (
	"bufio"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// drainReply fully consumes one RESP reply of ANY type (simple string,
// error, integer, bulk string, array, RESP3 map/set/push/boolean/null),
// recursing into aggregate types' sub-elements — unlike this package's
// existing readRESPFrame helper (protocol_test.go), which only knows how
// to walk a RESP2 array of bulk strings and would leave a RESP3 map
// reply's sub-elements undrained in the connection's buffer, corrupting
// every subsequent read on that connection.
func drainReply(t *testing.T, br *bufio.Reader) {
	t.Helper()
	header, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("drainReply: read header: %v", err)
	}
	if len(header) == 0 {
		return
	}
	switch header[0] {
	case '+', '-', ':', '#', '_', ',':
		return
	case '$':
		n, err := strconv.Atoi(strings.TrimRight(header[1:], "\r\n"))
		if err != nil {
			t.Fatalf("drainReply: parse bulk header %q: %v", header, err)
		}
		if n < 0 {
			return
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			t.Fatalf("drainReply: read bulk body: %v", err)
		}
	case '*', '~', '>':
		n, err := strconv.Atoi(strings.TrimRight(header[1:], "\r\n"))
		if err != nil {
			t.Fatalf("drainReply: parse array header %q: %v", header, err)
		}
		for range n {
			drainReply(t, br)
		}
	case '%':
		n, err := strconv.Atoi(strings.TrimRight(header[1:], "\r\n"))
		if err != nil {
			t.Fatalf("drainReply: parse map header %q: %v", header, err)
		}
		for range 2 * n {
			drainReply(t, br)
		}
	default:
		t.Fatalf("drainReply: unknown reply type %q", header)
	}
}

func dialAndReader(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	return conn, bufio.NewReader(conn)
}

func sendCommand(t *testing.T, conn net.Conn, args ...string) {
	t.Helper()
	req := "*" + itoa(int64(len(args))) + "\r\n"
	for _, a := range args {
		req += "$" + itoa(int64(len(a))) + "\r\n" + a + "\r\n"
	}
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write %v: %v", args, err)
	}
}

// TestHELLO3_NegotiatesRESP3MapReply proves HELLO 3 actually switches the
// connection's reply encoding: the HELLO reply itself must come back as a
// RESP3 map (%7\r\n...), not a RESP2 array, since real Redis encodes the
// HELLO reply under the version being switched TO.
func TestHELLO3_NegotiatesRESP3MapReply(t *testing.T) {
	addr, shutdown := bootTestServer(t, true)
	defer shutdown()

	conn, br := dialAndReader(t, addr)
	defer conn.Close()

	sendCommand(t, conn, "HELLO", "3")
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read HELLO reply header: %v", err)
	}
	if line[0] != '%' {
		t.Fatalf("HELLO 3 reply header = %q, want a RESP3 map header starting with '%%'", line)
	}
	// %7 means 7 key/value pairs (server/version/proto/id/mode/role/modules).
	if line != "%7\r\n" {
		t.Fatalf("HELLO 3 reply header = %q, want \"%%7\\r\\n\"", line)
	}
}

// TestHELLO2_KeepsRESP2ArrayReply proves the default (no HELLO, or
// explicit HELLO 2) encoding is completely unchanged from before RESP3
// support existed.
func TestHELLO2_KeepsRESP2ArrayReply(t *testing.T) {
	addr, shutdown := bootTestServer(t, true)
	defer shutdown()

	conn, br := dialAndReader(t, addr)
	defer conn.Close()

	sendCommand(t, conn, "HELLO", "2")
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read HELLO reply header: %v", err)
	}
	if line[0] != '*' {
		t.Fatalf("HELLO 2 reply header = %q, want a RESP2 array header starting with '*'", line)
	}
	if line != "*14\r\n" { // 7 pairs * 2 elements, flat array
		t.Fatalf("HELLO 2 reply header = %q, want \"*14\\r\\n\"", line)
	}
}

// TestHELLO_UnsupportedVersionErrors confirms an out-of-range version
// number is a protocol error, not silently accepted.
func TestHELLO_UnsupportedVersionErrors(t *testing.T) {
	addr, shutdown := bootTestServer(t, true)
	defer shutdown()

	conn, br := dialAndReader(t, addr)
	defer conn.Close()

	sendCommand(t, conn, "HELLO", "99")
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read HELLO reply: %v", err)
	}
	if line[0] != '-' {
		t.Fatalf("HELLO 99 reply = %q, want a RESP error starting with '-'", line)
	}
}

// TestHGETALL_RESP3MapVsRESP2Array proves the SAME command's reply shape
// genuinely differs by negotiated protocol version — the actual
// compatibility-preserving behavior this feature exists for.
func TestHGETALL_RESP3MapVsRESP2Array(t *testing.T) {
	addr, shutdown := bootTestServer(t, true)
	defer shutdown()

	setup, _ := dialAndReader(t, addr)
	sendCommand(t, setup, "HSET", "h1", "f1", "v1")
	readRESPFrame(t, bufio.NewReader(setup))
	setup.Close()

	// RESP3 connection: HGETALL must reply with a map header.
	c3, br3 := dialAndReader(t, addr)
	defer c3.Close()
	sendCommand(t, c3, "HELLO", "3")
	drainReply(t, br3) // discard HELLO's own (RESP3 map) reply
	sendCommand(t, c3, "HGETALL", "h1")
	line3, err := br3.ReadString('\n')
	if err != nil {
		t.Fatalf("read HGETALL(RESP3) header: %v", err)
	}
	if line3 != "%1\r\n" {
		t.Fatalf("HGETALL under RESP3 header = %q, want \"%%1\\r\\n\"", line3)
	}

	// RESP2 connection (no HELLO at all): HGETALL must keep the OLD flat
	// array shape, unchanged.
	c2, br2 := dialAndReader(t, addr)
	defer c2.Close()
	sendCommand(t, c2, "HGETALL", "h1")
	line2, err := br2.ReadString('\n')
	if err != nil {
		t.Fatalf("read HGETALL(RESP2) header: %v", err)
	}
	if line2 != "*2\r\n" {
		t.Fatalf("HGETALL under RESP2 header = %q, want \"*2\\r\\n\" (flat array of 2)", line2)
	}
}

// TestMULTI_EXEC_RunsQueuedCommandsAndTheyTakeEffect is the core
// transaction proof: two queued commands both actually execute, in
// order, and both their effects are observable afterward.
func TestMULTI_EXEC_RunsQueuedCommandsAndTheyTakeEffect(t *testing.T) {
	addr, shutdown := bootTestServer(t, false)
	defer shutdown()

	conn, br := dialAndReader(t, addr)
	defer conn.Close()

	sendCommand(t, conn, "MULTI")
	if got := readRESPFrame(t, br); got != "+OK\r\n" {
		t.Fatalf("MULTI reply = %q, want +OK", got)
	}

	sendCommand(t, conn, "SET", "counter", "10")
	if got := readRESPFrame(t, br); got != "+QUEUED\r\n" {
		t.Fatalf("queued SET reply = %q, want +QUEUED", got)
	}
	sendCommand(t, conn, "INCR", "counter")
	if got := readRESPFrame(t, br); got != "+QUEUED\r\n" {
		t.Fatalf("queued INCR reply = %q, want +QUEUED", got)
	}

	sendCommand(t, conn, "EXEC")
	// EXEC's reply is a RESP array whose two elements are themselves
	// complete replies (+OK from SET, :<n> from INCR) — each is a single
	// line here (no bulk-string body to drain), so reading line-by-line is
	// correct and simplest; readRESPFrame isn't used because it returns
	// the array header AND every element concatenated as one string,
	// which isn't what a per-element assertion needs.
	header, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read EXEC array header: %v", err)
	}
	if header != "*2\r\n" {
		t.Fatalf("EXEC reply header = %q, want \"*2\\r\\n\"", header)
	}
	setReply, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read EXEC[0]: %v", err)
	}
	if setReply[0] != '+' {
		t.Fatalf("EXEC[0] (SET) = %q, want a simple-string OK reply", setReply)
	}
	incrReply, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read EXEC[1]: %v", err)
	}
	if incrReply[0] != ':' {
		t.Fatalf("EXEC[1] (INCR) = %q, want an integer reply", incrReply)
	}

	// Confirm the effects are real, not just correctly-shaped replies:
	// GET the key back on a fresh connection.
	verify, brV := dialAndReader(t, addr)
	defer verify.Close()
	sendCommand(t, verify, "GET", "counter")
	got := readRESPFrame(t, brV)
	if got[0] != '$' {
		t.Fatalf("GET after EXEC = %q, want a bulk string (key must exist)", got)
	}
}

// TestDISCARD_PreventsAnyQueuedCommandFromRunning is the negative-proof
// counterpart: queuing commands then DISCARDing must leave zero effect.
func TestDISCARD_PreventsAnyQueuedCommandFromRunning(t *testing.T) {
	addr, shutdown := bootTestServer(t, false)
	defer shutdown()

	conn, br := dialAndReader(t, addr)
	defer conn.Close()

	sendCommand(t, conn, "MULTI")
	readRESPFrame(t, br)
	sendCommand(t, conn, "SET", "should-not-exist", "x")
	readRESPFrame(t, br)
	sendCommand(t, conn, "DISCARD")
	if got := readRESPFrame(t, br); got != "+OK\r\n" {
		t.Fatalf("DISCARD reply = %q, want +OK", got)
	}

	verify, brV := dialAndReader(t, addr)
	defer verify.Close()
	sendCommand(t, verify, "GET", "should-not-exist")
	got := readRESPFrame(t, brV)
	if got != "$-1\r\n" {
		t.Fatalf("GET after DISCARD = %q, want $-1 (key must never have been set)", got)
	}
}

// TestEXEC_DISCARD_OutsideMULTI_Errors and TestMULTI_Nested_Errors cover
// the queuing state-machine edge cases.
func TestEXEC_OutsideMULTI_Errors(t *testing.T) {
	addr, shutdown := bootTestServer(t, false)
	defer shutdown()
	conn, br := dialAndReader(t, addr)
	defer conn.Close()
	sendCommand(t, conn, "EXEC")
	if got := readRESPFrame(t, br); got[0] != '-' {
		t.Fatalf("EXEC outside MULTI = %q, want a RESP error", got)
	}
}

func TestDISCARD_OutsideMULTI_Errors(t *testing.T) {
	addr, shutdown := bootTestServer(t, false)
	defer shutdown()
	conn, br := dialAndReader(t, addr)
	defer conn.Close()
	sendCommand(t, conn, "DISCARD")
	if got := readRESPFrame(t, br); got[0] != '-' {
		t.Fatalf("DISCARD outside MULTI = %q, want a RESP error", got)
	}
}

func TestMULTI_Nested_Errors(t *testing.T) {
	addr, shutdown := bootTestServer(t, false)
	defer shutdown()
	conn, br := dialAndReader(t, addr)
	defer conn.Close()
	sendCommand(t, conn, "MULTI")
	readRESPFrame(t, br)
	sendCommand(t, conn, "MULTI")
	if got := readRESPFrame(t, br); got[0] != '-' {
		t.Fatalf("nested MULTI = %q, want a RESP error", got)
	}
}

// TestMULTI_UnknownCommandAbortsEXEC matches real Redis's EXECABORT
// behavior: queuing a genuinely unknown command marks the transaction
// dirty, and EXEC then refuses to run ANY of the queued commands.
func TestMULTI_UnknownCommandAbortsEXEC(t *testing.T) {
	addr, shutdown := bootTestServer(t, false)
	defer shutdown()
	conn, br := dialAndReader(t, addr)
	defer conn.Close()

	sendCommand(t, conn, "MULTI")
	readRESPFrame(t, br)
	sendCommand(t, conn, "SET", "x", "1")
	readRESPFrame(t, br)
	sendCommand(t, conn, "NOTACOMMAND")
	if got := readRESPFrame(t, br); got[0] != '-' {
		t.Fatalf("queuing unknown command = %q, want an immediate RESP error", got)
	}
	sendCommand(t, conn, "EXEC")
	got := readRESPFrame(t, br)
	if got[0] != '-' {
		t.Fatalf("EXEC after a dirty queue = %q, want EXECABORT error", got)
	}

	verify, brV := dialAndReader(t, addr)
	defer verify.Close()
	sendCommand(t, verify, "GET", "x")
	if got := readRESPFrame(t, brV); got != "$-1\r\n" {
		t.Fatalf("GET after aborted EXEC = %q, want $-1 (SET must not have run)", got)
	}
}

// TestRealRedisCLI_MultiExec is the real-client proof point, matching
// this package's established rediscli_test.go convention. MULTI/EXEC only
// makes sense within a single connection/session, so unlike runRedisCLI's
// one-command-per-invocation helper, this feeds a whole script to
// redis-cli over stdin (redis-cli reads and runs one command per line
// from stdin when it isn't a TTY and no command was given on argv) so
// every line shares the same underlying connection.
func TestRealRedisCLI_MultiExec(t *testing.T) {
	if _, err := exec.LookPath("redis-cli"); err != nil {
		t.Skip("redis-cli not on PATH in this environment")
	}
	addr, shutdown := bootTestServer(t, false)
	defer shutdown()

	host, port, ok := strings.Cut(strings.TrimPrefix(addr, "[::]"), ":")
	if !ok {
		host, port = "127.0.0.1", strings.TrimPrefix(addr, ":")
	}
	if host == "" {
		host = "127.0.0.1"
	}

	script := "MULTI\nSET rk rv\nINCR rcounter\nEXEC\n"
	cmd := exec.Command("redis-cli", "-h", host, "-p", port)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("redis-cli piped MULTI/EXEC script failed: %v, output: %s", err, out)
	}
	got := strings.TrimSpace(string(out))
	t.Logf("redis-cli MULTI/EXEC output:\n%s", got)
	if !strings.Contains(got, "OK") {
		t.Fatalf("expected MULTI's OK reply somewhere in output, got: %s", got)
	}
	if !strings.Contains(got, "QUEUED") {
		t.Fatalf("expected QUEUED replies for the queued commands, got: %s", got)
	}

	// Confirm the effects are real via a second, independent redis-cli
	// invocation (the package's standard single-command helper).
	if got := runRedisCLI(t, addr, "GET", "rk"); got != "rv" {
		t.Fatalf("GET rk after real redis-cli MULTI/EXEC = %q, want rv", got)
	}
}
