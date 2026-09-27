package resp

import (
	"bytes"
	"context"
	"fmt"
	"strings"
)

// connState holds the per-connection state that lives above individual
// command dispatch: whether the connection is currently queuing commands
// inside a MULTI block, and (via the Writer it's paired with) which RESP
// protocol version it negotiated — see protocol.go's Writer.proto.
//
// One connState is created per connection in handleConn and threaded
// through handleTop for the connection's whole lifetime; it is never
// shared across connections, so no locking is needed here.
type connState struct {
	multi bool
	dirty bool // true once a genuinely unknown command was queued — the
	// eventual EXEC must abort entirely without running anything, matching
	// real Redis's EXECABORT behavior for a bad command queued mid-MULTI.
	queue [][]string
}

func (cs *connState) reset() {
	cs.multi = false
	cs.dirty = false
	cs.queue = nil
}

// knownCommands is every command name dispatch's switch actually handles,
// used only to decide at QUEUE TIME (inside MULTI) whether a command name
// is real — this is a deliberately simplified subset of real Redis's
// queue-time validation, which also checks argument arity for some
// commands and aborts EXEC on an arity error too; here, an arity mistake
// on a known command name is still queued and only errors when EXEC
// actually runs it (that one command's reply is an error, the rest of the
// transaction still runs) — documented as a real, intentional scope
// narrowing, not a bug.
var knownCommands = map[string]bool{
	"PING": true, "ECHO": true, "SELECT": true, "COMMAND": true,
	"SET": true, "GET": true, "DEL": true, "EXISTS": true, "EXPIRE": true, "TTL": true,
	"INCR": true, "DECR": true, "INCRBY": true, "DECRBY": true, "KEYS": true,
	"LPUSH": true, "RPUSH": true, "LPOP": true, "RPOP": true, "LRANGE": true, "LLEN": true,
	"SADD": true, "SREM": true, "SMEMBERS": true, "SISMEMBER": true, "SCARD": true,
	"HSET": true, "HGET": true, "HDEL": true, "HGETALL": true, "HLEN": true,
	"ZADD": true, "ZRANGE": true, "ZSCORE": true, "ZREM": true, "ZCARD": true,
	"PUBLISH": true, "HELLO": true,
}

// handleTop is the entry point handleConn calls for every non-SUBSCRIBE
// command. It owns HELLO/MULTI/EXEC/DISCARD directly (they mutate cs, not
// just reply), and — while cs.multi is true — queues every other command
// instead of running it, exactly matching real Redis MULTI semantics.
func (p *Plugin) handleTop(ctx context.Context, w *Writer, args []string, cs *connState) {
	cmd := strings.ToUpper(args[0])

	switch cmd {
	case "HELLO":
		p.cmdHello(w, args)
		return
	case "MULTI":
		p.cmdMulti(w, cs)
		return
	case "EXEC":
		p.cmdExec(ctx, w, cs)
		return
	case "DISCARD":
		p.cmdDiscard(w, cs)
		return
	}

	if cs.multi {
		if !knownCommands[cmd] {
			w.WriteError(fmt.Sprintf("ERR unknown command '%s'", args[0]))
			cs.dirty = true
			return
		}
		cs.queue = append(cs.queue, args)
		w.WriteSimpleString("QUEUED")
		return
	}

	p.dispatch(ctx, w, args)
}

func (p *Plugin) cmdMulti(w *Writer, cs *connState) {
	if cs.multi {
		w.WriteError("ERR MULTI calls can not be nested")
		return
	}
	cs.multi = true
	cs.dirty = false
	cs.queue = nil
	w.WriteSimpleString("OK")
}

func (p *Plugin) cmdDiscard(w *Writer, cs *connState) {
	if !cs.multi {
		w.WriteError("ERR DISCARD without MULTI")
		return
	}
	cs.reset()
	w.WriteSimpleString("OK")
}

// cmdExec runs every queued command in order and replies with a RESP
// array of their individual replies — matching real Redis, EXEC is NOT
// atomic-with-rollback: a runtime error from one queued command (e.g. a
// wrong-arity SET) does not abort the rest, it just becomes that one
// slot's error reply within the array.
func (p *Plugin) cmdExec(ctx context.Context, w *Writer, cs *connState) {
	if !cs.multi {
		w.WriteError("ERR EXEC without MULTI")
		return
	}
	if cs.dirty {
		cs.reset()
		w.WriteError("EXECABORT Transaction discarded because of previous errors.")
		return
	}

	queue := cs.queue
	cs.reset()

	w.WriteArrayHeader(len(queue))
	for _, qargs := range queue {
		var buf bytes.Buffer
		sub := NewWriter(&buf)
		sub.proto = w.proto // each queued reply encodes under the same negotiated protocol version as the EXEC reply itself
		p.dispatch(ctx, sub, qargs)
		sub.Flush()
		// Each queued command's reply is already a complete, correctly
		// framed RESP value — concatenating these raw bytes inside the
		// outer array header is exactly how nested RESP array elements
		// are encoded on the wire.
		w.bw.Write(buf.Bytes())
	}
}
