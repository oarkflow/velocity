package resp

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const errNoDataStructures = "ERR data structure support not configured (enable the redisdata plugin)"

func wrongArgs(cmd string) string {
	return fmt.Sprintf("ERR wrong number of arguments for '%s' command", strings.ToLower(cmd))
}

func isSubscribeCommand(cmd string) bool { return strings.EqualFold(cmd, "SUBSCRIBE") }

// dispatch handles every command except SUBSCRIBE, which takes over the
// connection's read loop entirely (see handleConn/cmdSubscribe).
func (p *Plugin) dispatch(ctx context.Context, w *Writer, args []string) {
	cmd := strings.ToUpper(args[0])
	switch cmd {
	case "PING":
		if len(args) > 1 {
			w.WriteBulkString([]byte(args[1]))
		} else {
			w.WriteSimpleString("PONG")
		}
	case "ECHO":
		if len(args) != 2 {
			w.WriteError(wrongArgs(cmd))
			return
		}
		w.WriteBulkString([]byte(args[1]))
	case "SELECT":
		// Velocity has one keyspace per manifest, not Redis's numbered-DB
		// model — accept and no-op so clients that always SELECT on
		// connect (most do) don't break.
		w.WriteSimpleString("OK")
	case "COMMAND":
		// Some clients probe COMMAND/COMMAND DOCS for introspection on
		// connect; an empty array is a valid, harmless answer.
		w.WriteArrayHeader(0)

	case "SET":
		p.cmdSet(ctx, w, args)
	case "GET":
		p.cmdGet(ctx, w, args)
	case "DEL":
		p.cmdDel(ctx, w, args)
	case "EXISTS":
		p.cmdExists(ctx, w, args)
	case "EXPIRE":
		p.cmdExpire(ctx, w, args)
	case "TTL":
		p.cmdTTL(ctx, w, args)
	case "INCR":
		p.cmdIncrByArg(ctx, w, cmd, args, 1)
	case "DECR":
		p.cmdIncrByArg(ctx, w, cmd, args, -1)
	case "INCRBY":
		p.cmdIncrByN(ctx, w, cmd, args, 1)
	case "DECRBY":
		p.cmdIncrByN(ctx, w, cmd, args, -1)
	case "KEYS":
		p.cmdKeys(ctx, w, args)

	case "LPUSH", "RPUSH":
		p.cmdPush(ctx, w, cmd, args)
	case "LPOP", "RPOP":
		p.cmdPop(ctx, w, cmd, args)
	case "LRANGE":
		p.cmdLRange(ctx, w, args)
	case "LLEN":
		p.cmdLLen(ctx, w, args)

	case "SADD":
		p.cmdSAdd(ctx, w, args)
	case "SREM":
		p.cmdSRem(ctx, w, args)
	case "SMEMBERS":
		p.cmdSMembers(ctx, w, args)
	case "SISMEMBER":
		p.cmdSIsMember(ctx, w, args)
	case "SCARD":
		p.cmdSCard(ctx, w, args)

	case "HSET":
		p.cmdHSet(ctx, w, args)
	case "HGET":
		p.cmdHGet(ctx, w, args)
	case "HDEL":
		p.cmdHDel(ctx, w, args)
	case "HGETALL":
		p.cmdHGetAll(ctx, w, args)
	case "HLEN":
		p.cmdHLen(ctx, w, args)

	case "ZADD":
		p.cmdZAdd(ctx, w, args)
	case "ZRANGE":
		p.cmdZRange(ctx, w, args)
	case "ZSCORE":
		p.cmdZScore(ctx, w, args)
	case "ZREM":
		p.cmdZRem(ctx, w, args)
	case "ZCARD":
		p.cmdZCard(ctx, w, args)

	case "PUBLISH":
		p.cmdPublish(ctx, w, args)

	default:
		w.WriteError(fmt.Sprintf("ERR unknown command '%s'", args[0]))
	}
}

// --- string/KV commands ---

func (p *Plugin) cmdSet(ctx context.Context, w *Writer, args []string) {
	if len(args) < 3 {
		w.WriteError(wrongArgs("SET"))
		return
	}
	key, val := args[1], args[2]
	var ttl time.Duration
	nx, xx := false, false
	for i := 3; i < len(args); i++ {
		switch strings.ToUpper(args[i]) {
		case "EX":
			if i+1 >= len(args) {
				w.WriteError("ERR syntax error")
				return
			}
			i++
			secs, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil {
				w.WriteError("ERR value is not an integer or out of range")
				return
			}
			ttl = time.Duration(secs) * time.Second
		case "PX":
			if i+1 >= len(args) {
				w.WriteError("ERR syntax error")
				return
			}
			i++
			ms, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil {
				w.WriteError("ERR value is not an integer or out of range")
				return
			}
			ttl = time.Duration(ms) * time.Millisecond
		case "NX":
			nx = true
		case "XX":
			xx = true
		default:
			w.WriteError("ERR syntax error")
			return
		}
	}

	if nx || xx {
		exists, err := p.kv.Exists(ctx, key)
		if err != nil {
			w.WriteError("ERR " + err.Error())
			return
		}
		if (nx && exists) || (xx && !exists) {
			w.WriteBulkString(nil)
			return
		}
	}

	var err error
	if ttl > 0 {
		err = p.kv.PutWithTTL(ctx, key, []byte(val), ttl)
	} else {
		err = p.kv.Put(ctx, key, []byte(val))
	}
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteSimpleString("OK")
}

func (p *Plugin) cmdGet(ctx context.Context, w *Writer, args []string) {
	if len(args) != 2 {
		w.WriteError(wrongArgs("GET"))
		return
	}
	val, ok, err := p.kv.Get(ctx, args[1])
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	if !ok {
		w.WriteBulkString(nil)
		return
	}
	w.WriteBulkString(val)
}

func (p *Plugin) cmdDel(ctx context.Context, w *Writer, args []string) {
	if len(args) < 2 {
		w.WriteError(wrongArgs("DEL"))
		return
	}
	var n int64
	for _, k := range args[1:] {
		ok, err := p.kv.Exists(ctx, k)
		if err != nil {
			w.WriteError("ERR " + err.Error())
			return
		}
		if ok {
			if err := p.kv.Delete(ctx, k); err != nil {
				w.WriteError("ERR " + err.Error())
				return
			}
			n++
		}
	}
	w.WriteInteger(n)
}

func (p *Plugin) cmdExists(ctx context.Context, w *Writer, args []string) {
	if len(args) < 2 {
		w.WriteError(wrongArgs("EXISTS"))
		return
	}
	var n int64
	for _, k := range args[1:] {
		ok, err := p.kv.Exists(ctx, k)
		if err != nil {
			w.WriteError("ERR " + err.Error())
			return
		}
		if ok {
			n++
		}
	}
	w.WriteInteger(n)
}

// cmdExpire re-Puts the current value with a new TTL. This is a
// read-modify-write, not atomic against a concurrent writer on the same
// key — api.KVService has no lower-level "set TTL on an existing entry in
// place" primitive. Acceptable for RESP EXPIRE semantics (which only ever
// reset the TTL going forward anyway), documented here since it's a real,
// if narrow, race window.
func (p *Plugin) cmdExpire(ctx context.Context, w *Writer, args []string) {
	if len(args) != 3 {
		w.WriteError(wrongArgs("EXPIRE"))
		return
	}
	secs, err := strconv.ParseInt(args[2], 10, 64)
	if err != nil {
		w.WriteError("ERR value is not an integer or out of range")
		return
	}
	val, ok, err := p.kv.Get(ctx, args[1])
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	if !ok {
		w.WriteInteger(0)
		return
	}
	if err := p.kv.PutWithTTL(ctx, args[1], val, time.Duration(secs)*time.Second); err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteInteger(1)
}

// cmdTTL: api.KVService exposes no way to query a key's REMAINING TTL
// (only PutWithTTL to set one going forward) — there is no
// TTLRemaining-style method on the interface. Returns -2 for a genuinely
// missing key (real Redis semantics) and -1 for any existing key
// ("persistent/no expiry info available") rather than fabricating a
// number this plugin cannot actually know. This under-reports keys that
// do have an active TTL; a real fix needs a KVService interface addition,
// out of scope for this plugin alone.
func (p *Plugin) cmdTTL(ctx context.Context, w *Writer, args []string) {
	if len(args) != 2 {
		w.WriteError(wrongArgs("TTL"))
		return
	}
	ok, err := p.kv.Exists(ctx, args[1])
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	if !ok {
		w.WriteInteger(-2)
		return
	}
	w.WriteInteger(-1)
}

func (p *Plugin) cmdIncrByArg(ctx context.Context, w *Writer, cmd string, args []string, delta int64) {
	if len(args) != 2 {
		w.WriteError(wrongArgs(cmd))
		return
	}
	n, err := p.kv.Incr(ctx, args[1], delta)
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteInteger(n)
}

func (p *Plugin) cmdIncrByN(ctx context.Context, w *Writer, cmd string, args []string, sign int64) {
	if len(args) != 3 {
		w.WriteError(wrongArgs(cmd))
		return
	}
	delta, err := strconv.ParseInt(args[2], 10, 64)
	if err != nil {
		w.WriteError("ERR value is not an integer or out of range")
		return
	}
	n, err := p.kv.Incr(ctx, args[1], sign*delta)
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteInteger(n)
}

func (p *Plugin) cmdKeys(ctx context.Context, w *Writer, args []string) {
	if len(args) != 2 {
		w.WriteError(wrongArgs("KEYS"))
		return
	}
	keys, err := p.kv.Keys(ctx, args[1])
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteArrayHeader(len(keys))
	for _, k := range keys {
		w.WriteBulkString([]byte(k))
	}
}

// --- list commands ---

func (p *Plugin) cmdPush(ctx context.Context, w *Writer, cmd string, args []string) {
	if p.list == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) < 3 {
		w.WriteError(wrongArgs(cmd))
		return
	}
	vals := make([][]byte, 0, len(args)-2)
	for _, a := range args[2:] {
		vals = append(vals, []byte(a))
	}
	var n int64
	var err error
	if cmd == "LPUSH" {
		n, err = p.list.LPush(ctx, args[1], vals...)
	} else {
		n, err = p.list.RPush(ctx, args[1], vals...)
	}
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteInteger(n)
}

func (p *Plugin) cmdPop(ctx context.Context, w *Writer, cmd string, args []string) {
	if p.list == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) != 2 {
		w.WriteError(wrongArgs(cmd))
		return
	}
	var val []byte
	var ok bool
	var err error
	if cmd == "LPOP" {
		val, ok, err = p.list.LPop(ctx, args[1])
	} else {
		val, ok, err = p.list.RPop(ctx, args[1])
	}
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	if !ok {
		w.WriteBulkString(nil)
		return
	}
	w.WriteBulkString(val)
}

func (p *Plugin) cmdLRange(ctx context.Context, w *Writer, args []string) {
	if p.list == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) != 4 {
		w.WriteError(wrongArgs("LRANGE"))
		return
	}
	start, err1 := strconv.ParseInt(args[2], 10, 64)
	stop, err2 := strconv.ParseInt(args[3], 10, 64)
	if err1 != nil || err2 != nil {
		w.WriteError("ERR value is not an integer or out of range")
		return
	}
	items, err := p.list.LRange(ctx, args[1], start, stop)
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteArrayHeader(len(items))
	for _, it := range items {
		w.WriteBulkString(it)
	}
}

func (p *Plugin) cmdLLen(ctx context.Context, w *Writer, args []string) {
	if p.list == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) != 2 {
		w.WriteError(wrongArgs("LLEN"))
		return
	}
	n, err := p.list.LLen(ctx, args[1])
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteInteger(n)
}

// --- set commands ---

func (p *Plugin) cmdSAdd(ctx context.Context, w *Writer, args []string) {
	if p.set == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) < 3 {
		w.WriteError(wrongArgs("SADD"))
		return
	}
	members := make([][]byte, 0, len(args)-2)
	for _, a := range args[2:] {
		members = append(members, []byte(a))
	}
	n, err := p.set.SAdd(ctx, args[1], members...)
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteInteger(n)
}

func (p *Plugin) cmdSRem(ctx context.Context, w *Writer, args []string) {
	if p.set == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) < 3 {
		w.WriteError(wrongArgs("SREM"))
		return
	}
	members := make([][]byte, 0, len(args)-2)
	for _, a := range args[2:] {
		members = append(members, []byte(a))
	}
	n, err := p.set.SRem(ctx, args[1], members...)
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteInteger(n)
}

func (p *Plugin) cmdSMembers(ctx context.Context, w *Writer, args []string) {
	if p.set == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) != 2 {
		w.WriteError(wrongArgs("SMEMBERS"))
		return
	}
	members, err := p.set.SMembers(ctx, args[1])
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteArrayHeader(len(members))
	for _, m := range members {
		w.WriteBulkString(m)
	}
}

func (p *Plugin) cmdSIsMember(ctx context.Context, w *Writer, args []string) {
	if p.set == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) != 3 {
		w.WriteError(wrongArgs("SISMEMBER"))
		return
	}
	ok, err := p.set.SIsMember(ctx, args[1], []byte(args[2]))
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteBoolean(ok)
}

func (p *Plugin) cmdSCard(ctx context.Context, w *Writer, args []string) {
	if p.set == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) != 2 {
		w.WriteError(wrongArgs("SCARD"))
		return
	}
	n, err := p.set.SCard(ctx, args[1])
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteInteger(n)
}

// --- hash commands ---

func (p *Plugin) cmdHSet(ctx context.Context, w *Writer, args []string) {
	if p.hash == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) < 4 || len(args)%2 != 0 {
		w.WriteError(wrongArgs("HSET"))
		return
	}
	var added int64
	for i := 2; i+1 < len(args); i += 2 {
		field, val := args[i], args[i+1]
		_, existed, err := p.hash.HGet(ctx, args[1], field)
		if err != nil {
			w.WriteError("ERR " + err.Error())
			return
		}
		if err := p.hash.HSet(ctx, args[1], field, []byte(val)); err != nil {
			w.WriteError("ERR " + err.Error())
			return
		}
		if !existed {
			added++
		}
	}
	w.WriteInteger(added)
}

func (p *Plugin) cmdHGet(ctx context.Context, w *Writer, args []string) {
	if p.hash == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) != 3 {
		w.WriteError(wrongArgs("HGET"))
		return
	}
	val, ok, err := p.hash.HGet(ctx, args[1], args[2])
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	if !ok {
		w.WriteBulkString(nil)
		return
	}
	w.WriteBulkString(val)
}

func (p *Plugin) cmdHDel(ctx context.Context, w *Writer, args []string) {
	if p.hash == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) < 3 {
		w.WriteError(wrongArgs("HDEL"))
		return
	}
	var removed int64
	for _, field := range args[2:] {
		_, existed, err := p.hash.HGet(ctx, args[1], field)
		if err != nil {
			w.WriteError("ERR " + err.Error())
			return
		}
		if !existed {
			continue
		}
		if err := p.hash.HDel(ctx, args[1], field); err != nil {
			w.WriteError("ERR " + err.Error())
			return
		}
		removed++
	}
	w.WriteInteger(removed)
}

func (p *Plugin) cmdHGetAll(ctx context.Context, w *Writer, args []string) {
	if p.hash == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) != 2 {
		w.WriteError(wrongArgs("HGETALL"))
		return
	}
	m, err := p.hash.HGetAll(ctx, args[1])
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	// RESP3 connections get a real map reply; RESP2 connections get the
	// exact same flat array shape as before (WriteMapHeader falls back to
	// WriteArrayHeader(n*2) when w.proto < 3) — see protocol.go.
	w.WriteMapHeader(len(m))
	for field, val := range m {
		w.WriteBulkString([]byte(field))
		w.WriteBulkString(val)
	}
}

func (p *Plugin) cmdHLen(ctx context.Context, w *Writer, args []string) {
	if p.hash == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) != 2 {
		w.WriteError(wrongArgs("HLEN"))
		return
	}
	n, err := p.hash.HLen(ctx, args[1])
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteInteger(n)
}

// --- sorted set commands ---

func formatScore(score float64) string {
	return strconv.FormatFloat(score, 'f', -1, 64)
}

func (p *Plugin) cmdZAdd(ctx context.Context, w *Writer, args []string) {
	if p.zset == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) < 4 || len(args)%2 != 0 {
		w.WriteError(wrongArgs("ZADD"))
		return
	}
	var added int64
	for i := 2; i+1 < len(args); i += 2 {
		score, err := strconv.ParseFloat(args[i], 64)
		if err != nil {
			w.WriteError("ERR value is not a valid float")
			return
		}
		member := []byte(args[i+1])
		_, existed, err := p.zset.ZScore(ctx, args[1], member)
		if err != nil {
			w.WriteError("ERR " + err.Error())
			return
		}
		if err := p.zset.ZAdd(ctx, args[1], score, member); err != nil {
			w.WriteError("ERR " + err.Error())
			return
		}
		if !existed {
			added++
		}
	}
	w.WriteInteger(added)
}

func (p *Plugin) cmdZRange(ctx context.Context, w *Writer, args []string) {
	if p.zset == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) != 4 {
		w.WriteError(wrongArgs("ZRANGE"))
		return
	}
	start, err1 := strconv.ParseInt(args[2], 10, 64)
	stop, err2 := strconv.ParseInt(args[3], 10, 64)
	if err1 != nil || err2 != nil {
		w.WriteError("ERR value is not an integer or out of range")
		return
	}
	members, err := p.zset.ZRange(ctx, args[1], start, stop)
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteArrayHeader(len(members))
	for _, m := range members {
		w.WriteBulkString(m)
	}
}

func (p *Plugin) cmdZScore(ctx context.Context, w *Writer, args []string) {
	if p.zset == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) != 3 {
		w.WriteError(wrongArgs("ZSCORE"))
		return
	}
	score, ok, err := p.zset.ZScore(ctx, args[1], []byte(args[2]))
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	if !ok {
		w.WriteBulkString(nil)
		return
	}
	w.WriteBulkString([]byte(formatScore(score)))
}

func (p *Plugin) cmdZRem(ctx context.Context, w *Writer, args []string) {
	if p.zset == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) < 3 {
		w.WriteError(wrongArgs("ZREM"))
		return
	}
	var removed int64
	for _, m := range args[2:] {
		member := []byte(m)
		_, existed, err := p.zset.ZScore(ctx, args[1], member)
		if err != nil {
			w.WriteError("ERR " + err.Error())
			return
		}
		if !existed {
			continue
		}
		if err := p.zset.ZRem(ctx, args[1], member); err != nil {
			w.WriteError("ERR " + err.Error())
			return
		}
		removed++
	}
	w.WriteInteger(removed)
}

func (p *Plugin) cmdZCard(ctx context.Context, w *Writer, args []string) {
	if p.zset == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) != 2 {
		w.WriteError(wrongArgs("ZCARD"))
		return
	}
	n, err := p.zset.ZCard(ctx, args[1])
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteInteger(n)
}

// --- pub/sub ---

func (p *Plugin) cmdPublish(ctx context.Context, w *Writer, args []string) {
	if p.pubsub == nil {
		w.WriteError(errNoDataStructures)
		return
	}
	if len(args) != 3 {
		w.WriteError(wrongArgs("PUBLISH"))
		return
	}
	n, err := p.pubsub.Publish(ctx, args[1], []byte(args[2]))
	if err != nil {
		w.WriteError("ERR " + err.Error())
		return
	}
	w.WriteInteger(n)
}
