// Package resp implements a real RESP2 (Redis Serialization Protocol)
// server atop Velocity v2's KVService and optional data-structure/pub-sub
// services, so unmodified Redis clients (redis-cli, go-redis, any RESP
// client) can talk to Velocity without knowing it isn't real Redis.
package resp

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Reader parses client requests off the wire: RESP arrays of bulk strings
// (the format every real Redis client sends), plus a fallback for the
// simpler inline-command format (space-separated text, no framing) that
// some minimal/manual clients use.
//
// The parse path is allocation-conscious: line headers are read with
// bufio.ReadSlice (a view into the buffered reader's own buffer, no
// copy), bulk payloads are read into one reusable scratch buffer, and the
// argument slice itself is reused across ReadCommand calls. A command
// parse therefore allocates exactly one string per bulk argument — the
// unavoidable copies callers retain — and nothing else.
type Reader struct {
	br      *bufio.Reader
	scratch []byte   // reusable bulk-payload read buffer
	args    []string // reusable argument slice; see ReadCommand's contract
}

func NewReader(r io.Reader) *Reader { return &Reader{br: bufio.NewReader(r)} }

// Buffered reports how many bytes of client input are already buffered
// and readable without a syscall. The connection loop uses it to decide
// when a reply must actually be flushed to the socket: if the client's
// next command is already in hand (a pipeline), replies are accumulated
// and flushed once per burst instead of once per command — this is the
// same batching redis-benchmark-style throughput depends on.
func (r *Reader) Buffered() int { return r.br.Buffered() }

// HasCompleteCommand reports whether at least one COMPLETE request frame
// is sitting in the read buffer. The connection loop flushes replies when
// this returns false: a buffered-but-partial next command must not
// suppress a flush, or a client that sends slowly (or a half-written
// frame on the wire) would deadlock waiting for replies the server is
// holding while waiting for the rest of its request. Over-size frames
// beyond the read buffer simply report false and get the conservative
// flush-per-command behavior.
func (r *Reader) HasCompleteCommand() bool {
	n := r.br.Buffered()
	if n == 0 {
		return false
	}
	buf, _ := r.br.Peek(n)
	return frameLen(buf) > 0
}

// frameLen returns the total byte length of the first complete RESP
// request frame in buf (array or inline), or 0 if buf does not yet hold
// one. It only inspects framing (count/length headers and terminators),
// never payload contents.
func frameLen(buf []byte) int {
	if len(buf) == 0 {
		return 0
	}
	if buf[0] != '*' {
		// Inline command: a complete line is a complete frame — EXCEPT an
		// empty/whitespace-only line, which the read loop consumes as a
		// no-op (it produces no reply). Counting that as "a complete
		// command" would suppress the flush of a reply already owed to
		// the client and deadlock it behind the next blocking read — a
		// real failure mode reached by a stray "\n" on the wire (the
		// protocol tests do exactly that with a malformed bulk frame).
		if i := indexByte(buf, '\n'); i >= 0 {
			for _, c := range buf[:i] {
				if c != ' ' && c != '\r' && c != '\t' {
					return i + 1
				}
			}
			return 0
		}
		return 0
	}
	line, rest, ok := splitLine(buf)
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(string(trimCRLF(line[1:])))
	if err != nil {
		return 1 // malformed header: treat as "complete" so the parser reports the error instead of stalling
	}
	if n <= 0 {
		return len(buf) - len(rest)
	}
	total := len(buf) - len(rest)
	for i := 0; i < n; i++ {
		hdr, rest2, ok := splitLine(rest)
		if !ok {
			return 0
		}
		hdr = trimCRLF(hdr)
		if len(hdr) == 0 || hdr[0] != '$' {
			return total + 1 // malformed: let the real parser surface the error
		}
		bl, err := strconv.Atoi(string(hdr[1:]))
		if err != nil {
			return total + 1
		}
		total += len(rest) - len(rest2)
		rest = rest2
		if bl < 0 {
			continue // null bulk argument carries no payload bytes
		}
		if len(rest) < bl+2 {
			return 0
		}
		total += bl + 2
		rest = rest[bl+2:]
	}
	return total
}

// splitLine splits at the first '\n', returning the line (including the
// terminator) and everything after it.
func splitLine(buf []byte) (line, rest []byte, ok bool) {
	if i := indexByte(buf, '\n'); i >= 0 {
		return buf[:i+1], buf[i+1:], true
	}
	return nil, nil, false
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// ReadCommand reads one client request and returns its arguments. Returns
// io.EOF (or another error) when the connection is closed or the wire
// format is invalid.
//
// The returned slice is REUSED across calls: it is only valid until the
// next ReadCommand on this Reader (the individual argument strings are
// ordinary immutable Go strings and remain valid). Copy the slice if a
// caller must retain it across reads.
func (r *Reader) ReadCommand() ([]string, error) {
	line, err := r.readLineSlice()
	if err != nil {
		return nil, err
	}
	if len(line) == 0 {
		return nil, nil
	}
	switch line[0] {
	case '*':
		n, err := strconv.Atoi(string(trimCRLF(line[1:])))
		if err != nil {
			return nil, fmt.Errorf("resp: malformed array header %q: %w", line, err)
		}
		if n <= 0 {
			return nil, nil
		}
		args := r.args[:0]
		if cap(args) < n {
			args = make([]string, 0, n)
		}
		for i := 0; i < n; i++ {
			bulk, err := r.readBulk()
			if err != nil {
				return nil, err
			}
			args = append(args, bulk)
		}
		r.args = args
		return args, nil
	default:
		// Inline command: plain space-separated text terminated by \r\n or
		// \n, no length framing — real Redis supports this too, mainly for
		// hand-typed telnet-style sessions.
		return strings.Fields(string(trimCRLF(line))), nil
	}
}

// readLineSlice returns the next line without allocating — a view into
// the buffered reader's buffer, valid only until the next read on this
// Reader. Lines longer than the reader's buffer fall back to an
// allocating read (pathological case only).
func (r *Reader) readLineSlice() ([]byte, error) {
	line, err := r.br.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		full, err2 := r.readLineAlloc()
		if err2 != nil {
			return nil, err2
		}
		return full, nil
	}
	return line, err
}

func (r *Reader) readLineAlloc() ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.br.ReadSlice('\n')
		buf = append(buf, chunk...)
		if err == bufio.ErrBufferFull {
			continue
		}
		return buf, err
	}
}

func trimCRLF(line []byte) []byte {
	if n := len(line); n > 0 && line[n-1] == '\n' {
		line = line[:n-1]
	}
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	return line
}

func (r *Reader) readBulk() (string, error) {
	line, err := r.readLineSlice()
	if err != nil {
		return "", err
	}
	line = trimCRLF(line)
	if len(line) == 0 || line[0] != '$' {
		return "", fmt.Errorf("resp: expected bulk string header, got %q", line)
	}
	n, err := strconv.Atoi(string(line[1:]))
	if err != nil {
		return "", fmt.Errorf("resp: malformed bulk string header %q: %w", line, err)
	}
	if n < 0 {
		return "", nil // null bulk string used as an argument — unusual but not an error
	}
	if cap(r.scratch) < n+2 {
		r.scratch = make([]byte, n+2)
	}
	buf := r.scratch[:n+2] // +2 for the trailing \r\n
	if _, err := io.ReadFull(r.br, buf); err != nil {
		return "", err
	}
	return string(buf[:n]), nil // one copy: callers retain the argument
}

// Writer encodes RESP replies: simple strings, errors, integers, bulk
// strings (including nil), arrays (including nil), and — once a
// connection has negotiated RESP3 via HELLO 3 — the richer RESP3 reply
// types (map, boolean, unified null) for the handful of commands that
// upgrade to them. proto is 0 (treated as RESP2) or 3; there is no
// dedicated "2" state distinct from 0 since RESP2 is the default for
// every connection until HELLO 3 raises it.
//
// Every encoding path writes directly to the buffered writer (no
// fmt.Fprintf — its formatting machinery allocated on every reply) and
// reuses one scratch buffer for decimal lengths/integers, so replying is
// allocation-free outside of what the bufio writer itself needs.
type Writer struct {
	bw      *bufio.Writer
	proto   int
	scratch []byte // decimal encoding scratch (lengths, integers)
}

func NewWriter(w io.Writer) *Writer { return &Writer{bw: bufio.NewWriter(w)} }

// appendDecimal renders n into w.scratch and returns it — one reusable
// buffer instead of a strconv string per reply.
func (w *Writer) appendDecimal(n int64) []byte {
	w.scratch = strconv.AppendInt(w.scratch[:0], n, 10)
	return w.scratch
}

func (w *Writer) WriteSimpleString(s string) error {
	if err := w.bw.WriteByte('+'); err != nil {
		return err
	}
	if _, err := w.bw.WriteString(s); err != nil {
		return err
	}
	_, err := w.bw.WriteString("\r\n")
	return err
}

func (w *Writer) WriteError(msg string) error {
	if err := w.bw.WriteByte('-'); err != nil {
		return err
	}
	if _, err := w.bw.WriteString(msg); err != nil {
		return err
	}
	_, err := w.bw.WriteString("\r\n")
	return err
}

func (w *Writer) WriteInteger(n int64) error {
	if err := w.bw.WriteByte(':'); err != nil {
		return err
	}
	if _, err := w.bw.Write(w.appendDecimal(n)); err != nil {
		return err
	}
	_, err := w.bw.WriteString("\r\n")
	return err
}

// WriteBulkString writes s as a RESP bulk string, or a nil reply if s is
// nil (Redis's representation of "no such key" / "no such value") — the
// RESP2 nil bulk string ($-1\r\n) on a RESP2 connection, or the RESP3
// unified null (_\r\n) once HELLO 3 has been negotiated, matching real
// Redis 6+'s own behavior of unifying every "no value" reply under one
// null type in RESP3.
func (w *Writer) WriteBulkString(s []byte) error {
	if s == nil {
		if w.proto >= 3 {
			_, err := w.bw.WriteString("_\r\n")
			return err
		}
		_, err := w.bw.WriteString("$-1\r\n")
		return err
	}
	if err := w.bw.WriteByte('$'); err != nil {
		return err
	}
	if _, err := w.bw.Write(w.appendDecimal(int64(len(s)))); err != nil {
		return err
	}
	if _, err := w.bw.WriteString("\r\n"); err != nil {
		return err
	}
	if _, err := w.bw.Write(s); err != nil {
		return err
	}
	_, err := w.bw.WriteString("\r\n")
	return err
}

// WriteNullArray writes the RESP nil array (*-1\r\n).
func (w *Writer) WriteNullArray() error {
	_, err := w.bw.WriteString("*-1\r\n")
	return err
}

// WriteArrayHeader writes a RESP array header for n upcoming elements;
// the caller writes each element (WriteBulkString/WriteInteger/etc.)
// immediately after, n times.
func (w *Writer) WriteArrayHeader(n int) error {
	if err := w.bw.WriteByte('*'); err != nil {
		return err
	}
	if _, err := w.bw.Write(w.appendDecimal(int64(n))); err != nil {
		return err
	}
	_, err := w.bw.WriteString("\r\n")
	return err
}

// WriteBoolean writes a RESP3 boolean (#t\r\n / #f\r\n) on a RESP3
// connection, or the RESP2-compatible integer 1/0 otherwise — real Redis
// 6+ upgrades boolean-shaped replies (e.g. SISMEMBER) the same way.
func (w *Writer) WriteBoolean(b bool) error {
	if w.proto >= 3 {
		if b {
			_, err := w.bw.WriteString("#t\r\n")
			return err
		}
		_, err := w.bw.WriteString("#f\r\n")
		return err
	}
	if b {
		return w.WriteInteger(1)
	}
	return w.WriteInteger(0)
}

// WriteMapHeader writes a RESP3 map header for n upcoming key/value pairs
// (%n\r\n, caller writes 2*n elements after — key, value, key, value...)
// on a RESP3 connection, or the RESP2-compatible flat array header for
// the same 2*n elements otherwise — real Redis 6+ upgrades map-shaped
// replies (e.g. HGETALL) the same way, and a RESP2 client sees exactly
// the same flat-array shape it always has.
func (w *Writer) WriteMapHeader(n int) error {
	if w.proto >= 3 {
		if err := w.bw.WriteByte('%'); err != nil {
			return err
		}
		if _, err := w.bw.Write(w.appendDecimal(int64(n))); err != nil {
			return err
		}
		if _, err := w.bw.WriteString("\r\n"); err != nil {
			return err
		}
		return nil
	}
	return w.WriteArrayHeader(n * 2)
}

func (w *Writer) Flush() error { return w.bw.Flush() }
