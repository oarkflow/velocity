package resp

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
)

// bootTestServer boots a real kernel with a fake kv/pubsub/... service set
// (this package's own memKV/memPubSub/etc., not the real storage-lsm/kv
// plugins, to keep these tests fast and dependency-free) plus a real
// *Plugin listening on an OS-assigned port, and returns its address and a
// cleanup func.
func bootTestServer(t *testing.T, withDataStructures bool) (addr string, shutdown func()) {
	t.Helper()
	k := kernel.New(kernel.Manifest{})

	kv := newMemKV()
	fakeKVPlugin := &fakeServicePlugin{name: "kv", svc: kv}

	all := []api.Plugin{fakeKVPlugin}
	enabled := map[string]bool{"kv": true, "resp": true}

	respPlugin := NewPlugin("kv")
	all = append(all, respPlugin)

	if withDataStructures {
		ds := &fakeMultiServicePlugin{
			name: "redisdata",
			services: map[string]any{
				"list":   newMemList(),
				"set":    newMemSet(),
				"hash":   newMemHash(),
				"zset":   newMemZSet(),
				"pubsub": newMemPubSub(),
			},
		}
		all = append(all, ds)
		enabled["redisdata"] = true
	}

	if err := k.Boot(context.Background(), all, enabled); err != nil {
		t.Fatalf("boot: %v", err)
	}
	// addr is ":0" by default (no manifest config) -> ask the OS for a
	// free port explicitly instead, since Plugin.Start already bound one.
	addr = respPlugin.Addr()
	return addr, func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = k.Shutdown(shutdownCtx)
	}
}

type fakeServicePlugin struct {
	name string
	svc  any
}

func (f *fakeServicePlugin) Name() string                    { return f.name }
func (f *fakeServicePlugin) Version() string                 { return "test" }
func (f *fakeServicePlugin) Dependencies() []string          { return nil }
func (f *fakeServicePlugin) Start(ctx context.Context) error { return nil }
func (f *fakeServicePlugin) Stop(ctx context.Context) error  { return nil }
func (f *fakeServicePlugin) Health() api.Health              { return api.Health{Status: "ok"} }
func (f *fakeServicePlugin) Init(ctx context.Context, k api.Kernel) error {
	return k.Registry().Provide(f.name, f.svc)
}

type fakeMultiServicePlugin struct {
	name     string
	services map[string]any
}

func (f *fakeMultiServicePlugin) Name() string                    { return f.name }
func (f *fakeMultiServicePlugin) Version() string                 { return "test" }
func (f *fakeMultiServicePlugin) Dependencies() []string          { return nil }
func (f *fakeMultiServicePlugin) Start(ctx context.Context) error { return nil }
func (f *fakeMultiServicePlugin) Stop(ctx context.Context) error  { return nil }
func (f *fakeMultiServicePlugin) Health() api.Health              { return api.Health{Status: "ok"} }
func (f *fakeMultiServicePlugin) Init(ctx context.Context, k api.Kernel) error {
	for name, svc := range f.services {
		if err := k.Registry().Provide(name, svc); err != nil {
			return err
		}
	}
	return nil
}

// dialAndExpect writes a raw RESP request and reads back exactly the
// expected raw RESP reply bytes — precise byte-level protocol coverage,
// not just "the command didn't error".
func dialAndExpect(t *testing.T, addr string, req string, wantPrefix string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(buf[:n])
	if wantPrefix != "" && !bytes.HasPrefix([]byte(got), []byte(wantPrefix)) {
		t.Fatalf("reply = %q, want prefix %q", got, wantPrefix)
	}
	return got
}

func TestProtocol_SetGetDelExpireIncr(t *testing.T) {
	addr, shutdown := bootTestServer(t, false)
	defer shutdown()

	// SET foo bar
	got := dialAndExpect(t, addr, "*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n", "+OK\r\n")
	if got != "+OK\r\n" {
		t.Fatalf("SET reply = %q", got)
	}

	// GET foo
	got = dialAndExpect(t, addr, "*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n", "$3\r\nbar\r\n")
	if got != "$3\r\nbar\r\n" {
		t.Fatalf("GET reply = %q", got)
	}

	// GET missing -> $-1
	got = dialAndExpect(t, addr, "*2\r\n$3\r\nGET\r\n$7\r\nmissing\r\n", "$-1\r\n")
	if got != "$-1\r\n" {
		t.Fatalf("GET missing reply = %q", got)
	}

	// DEL foo -> :1
	got = dialAndExpect(t, addr, "*2\r\n$3\r\nDEL\r\n$3\r\nfoo\r\n", ":1\r\n")
	if got != ":1\r\n" {
		t.Fatalf("DEL reply = %q", got)
	}

	// INCR counter -> :1, then :2
	got = dialAndExpect(t, addr, "*2\r\n$4\r\nINCR\r\n$7\r\ncounter\r\n", ":1\r\n")
	if got != ":1\r\n" {
		t.Fatalf("INCR reply = %q", got)
	}
	got = dialAndExpect(t, addr, "*2\r\n$4\r\nINCR\r\n$7\r\ncounter\r\n", ":2\r\n")
	if got != ":2\r\n" {
		t.Fatalf("INCR reply 2 = %q", got)
	}

	// unknown command -> RESP error
	got = dialAndExpect(t, addr, "*1\r\n$7\r\nBOGUSCMD\r\n", "-ERR")
	if len(got) < 4 || got[0] != '-' {
		t.Fatalf("unknown command reply = %q, want a RESP error", got)
	}
}

func TestProtocol_PublishSubscribe(t *testing.T) {
	addr, shutdown := bootTestServer(t, true)
	defer shutdown()

	sub, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial sub: %v", err)
	}
	defer sub.Close()

	if _, err := sub.Write([]byte("*2\r\n$9\r\nSUBSCRIBE\r\n$4\r\nnews\r\n")); err != nil {
		t.Fatalf("write subscribe: %v", err)
	}
	sub.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(sub)
	confirm := readRESPFrame(t, br)
	wantConfirm := "*3\r\n$9\r\nsubscribe\r\n$4\r\nnews\r\n:1\r\n"
	if confirm != wantConfirm {
		t.Fatalf("subscribe confirmation = %q, want %q", confirm, wantConfirm)
	}

	pub, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial pub: %v", err)
	}
	defer pub.Close()
	pub.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := pub.Write([]byte("*3\r\n$7\r\nPUBLISH\r\n$4\r\nnews\r\n$5\r\nhello\r\n")); err != nil {
		t.Fatalf("write publish: %v", err)
	}
	pubReply := make([]byte, 64)
	n, err := pub.Read(pubReply)
	if err != nil {
		t.Fatalf("read publish reply: %v", err)
	}
	if string(pubReply[:n]) != ":1\r\n" {
		t.Fatalf("PUBLISH reply = %q, want \":1\\r\\n\" (one subscriber)", pubReply[:n])
	}

	sub.SetReadDeadline(time.Now().Add(2 * time.Second))
	msg := readRESPFrame(t, br)
	wantMsg := "*3\r\n$7\r\nmessage\r\n$4\r\nnews\r\n$5\r\nhello\r\n"
	if msg != wantMsg {
		t.Fatalf("message push = %q, want %q", msg, wantMsg)
	}
}

// readRESPFrame reads exactly one RESP array frame (header line + N
// sub-elements) for the byte-precise assertions above.
func readRESPFrame(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	var out bytes.Buffer
	header, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	out.WriteString(header)
	if len(header) == 0 || header[0] != '*' {
		return out.String()
	}
	n, err := strconv.Atoi(strings.TrimRight(header[1:], "\r\n"))
	if err != nil {
		t.Fatalf("parse array header %q: %v", header, err)
	}
	for i := 0; i < n; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read frame element header: %v", err)
		}
		out.WriteString(line)
		if len(line) > 0 && line[0] == '$' {
			blen, err := strconv.Atoi(strings.TrimRight(line[1:], "\r\n"))
			if err != nil {
				t.Fatalf("parse bulk header %q: %v", line, err)
			}
			if blen >= 0 {
				buf := make([]byte, blen+2)
				if _, err := io.ReadFull(br, buf); err != nil {
					t.Fatalf("read bulk body: %v", err)
				}
				out.Write(buf)
			}
		}
	}
	return out.String()
}
