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
type Reader struct {
	br *bufio.Reader
}

func NewReader(r io.Reader) *Reader { return &Reader{br: bufio.NewReader(r)} }

// ReadCommand reads one client request and returns its arguments. Returns
// io.EOF (or another error) when the connection is closed or the wire
// format is invalid.
func (r *Reader) ReadCommand() ([]string, error) {
	line, err := r.readLine()
	if err != nil {
		return nil, err
	}
	if len(line) == 0 {
		return nil, nil
	}
	switch line[0] {
	case '*':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, fmt.Errorf("resp: malformed array header %q: %w", line, err)
		}
		if n <= 0 {
			return nil, nil
		}
		args := make([]string, 0, n)
		for i := 0; i < n; i++ {
			bulk, err := r.readBulk()
			if err != nil {
				return nil, err
			}
			args = append(args, bulk)
		}
		return args, nil
	default:
		// Inline command: plain space-separated text terminated by \r\n or
		// \n, no length framing — real Redis supports this too, mainly for
		// hand-typed telnet-style sessions.
		return strings.Fields(line), nil
	}
}

func (r *Reader) readLine() (string, error) {
	line, err := r.br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (r *Reader) readBulk() (string, error) {
	line, err := r.readLine()
	if err != nil {
		return "", err
	}
	if len(line) == 0 || line[0] != '$' {
		return "", fmt.Errorf("resp: expected bulk string header, got %q", line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return "", fmt.Errorf("resp: malformed bulk string header %q: %w", line, err)
	}
	if n < 0 {
		return "", nil // null bulk string used as an argument — unusual but not an error
	}
	buf := make([]byte, n+2) // +2 for the trailing \r\n
	if _, err := io.ReadFull(r.br, buf); err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// Writer encodes RESP replies: simple strings, errors, integers, bulk
// strings (including nil), arrays (including nil), and — once a
// connection has negotiated RESP3 via HELLO 3 — the richer RESP3 reply
// types (map, boolean, unified null) for the handful of commands that
// upgrade to them. proto is 0 (treated as RESP2) or 3; there is no
// dedicated "2" state distinct from 0 since RESP2 is the default for
// every connection until HELLO 3 raises it.
type Writer struct {
	bw    *bufio.Writer
	proto int
}

func NewWriter(w io.Writer) *Writer { return &Writer{bw: bufio.NewWriter(w)} }

func (w *Writer) WriteSimpleString(s string) error {
	_, err := fmt.Fprintf(w.bw, "+%s\r\n", s)
	return err
}

func (w *Writer) WriteError(msg string) error {
	_, err := fmt.Fprintf(w.bw, "-%s\r\n", msg)
	return err
}

func (w *Writer) WriteInteger(n int64) error {
	_, err := fmt.Fprintf(w.bw, ":%d\r\n", n)
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
	if _, err := fmt.Fprintf(w.bw, "$%d\r\n", len(s)); err != nil {
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
	_, err := fmt.Fprintf(w.bw, "*%d\r\n", n)
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
		_, err := fmt.Fprintf(w.bw, "%%%d\r\n", n)
		return err
	}
	return w.WriteArrayHeader(n * 2)
}

func (w *Writer) Flush() error { return w.bw.Flush() }
