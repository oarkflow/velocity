package resp

import (
	"strconv"
	"sync/atomic"
)

// connIDCounter hands out a distinct, monotonically increasing connection
// id per HELLO call, purely cosmetic (matches real Redis's HELLO reply
// shape, which includes a per-connection id) — not used for anything
// else in this package.
var connIDCounter int64

// cmdHello implements RESP3 protocol negotiation. `HELLO` with no
// version, or `HELLO 2`, keeps/reverts the connection to RESP2 encoding;
// `HELLO 3` switches it to RESP3 (richer map/boolean/null reply types for
// the commands that support them — see protocol.go's Writer methods);
// any other version number is a protocol error, matching real Redis.
//
// The reply itself is encoded under the NEWLY NEGOTIATED protocol version
// (real Redis does this too — a client sending "HELLO 3" gets a
// RESP3-map-shaped reply describing the server, not a RESP2 array), so
// w.proto is updated before this function encodes anything.
func (p *Plugin) cmdHello(w *Writer, args []string) {
	newProto := w.proto
	if newProto == 0 {
		newProto = 2
	}
	if len(args) >= 2 {
		v, err := strconv.Atoi(args[1])
		if err != nil || (v != 2 && v != 3) {
			w.WriteError("NOPROTO unsupported protocol version")
			return
		}
		newProto = v
	}
	w.proto = newProto

	id := atomic.AddInt64(&connIDCounter, 1)

	w.WriteMapHeader(7)
	w.WriteBulkString([]byte("server"))
	w.WriteBulkString([]byte("velocity-resp"))
	w.WriteBulkString([]byte("version"))
	w.WriteBulkString([]byte("0.1.0"))
	w.WriteBulkString([]byte("proto"))
	w.WriteInteger(int64(newProto))
	w.WriteBulkString([]byte("id"))
	w.WriteInteger(id)
	w.WriteBulkString([]byte("mode"))
	w.WriteBulkString([]byte("standalone"))
	w.WriteBulkString([]byte("role"))
	w.WriteBulkString([]byte("master"))
	w.WriteBulkString([]byte("modules"))
	w.WriteArrayHeader(0)
}
