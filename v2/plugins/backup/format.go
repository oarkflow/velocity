package backup

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Stream format: HMAC-signed length-prefixed key/value records.
//
//	magic   [4]byte  = "VBK1"
//	record* : uint32 keyLen | key | uint32 valueLen | value
//	end     : uint32 sentinel (0xFFFFFFFF — not a valid keyLen)
//	tag     [32]byte HMAC-SHA256 over every byte written above (magic
//	                 through the end sentinel, inclusive)
//
// Chosen over v1's per-record hash-chain approach because a single
// trailing HMAC over the whole payload is simpler to implement correctly
// here and gives the same guarantee we actually need: reject the whole
// stream if anything in it was altered. Restore/Import verify the tag
// before decoding or applying a single record — a tampered or truncated
// stream never partially mutates the backend.
//
// Known limitation: api.StorageBackend's Iterator exposes Key()/Value()
// only, not the original Entry.TTL, so TTL is not preserved across a
// backup/restore round trip. Restored entries have no TTL (TTL == 0).
// This is a StorageBackend interface limitation, not a plugin choice —
// documented here so it isn't silently lost on anyone.
var magic = [4]byte{'V', 'B', 'K', '1'}

const sentinel = 0xFFFFFFFF

var (
	// ErrTampered is returned by decode when the trailing HMAC tag does
	// not match the payload — the stream was altered or corrupted, or was
	// signed with a different hmac_key than this plugin is configured
	// with.
	ErrTampered = errors.New("backup: signature verification failed — stream is tampered, corrupted, or signed with a different key")
	// ErrTruncated is returned when the stream ends before a complete
	// record or the trailing tag can be read.
	ErrTruncated = errors.New("backup: stream truncated")
)

type record struct {
	key   []byte
	value []byte
}

// encode writes every record in recs to w in the stream format above,
// signed with key.
func encode(w io.Writer, key []byte, recs []record) error {
	var buf bytes.Buffer
	buf.Write(magic[:])
	for _, r := range recs {
		if err := writeChunk(&buf, r.key); err != nil {
			return err
		}
		if err := writeChunk(&buf, r.value); err != nil {
			return err
		}
	}
	var end [4]byte
	binary.BigEndian.PutUint32(end[:], sentinel)
	buf.Write(end[:])

	tag := signTag(key, buf.Bytes())

	if _, err := w.Write(buf.Bytes()); err != nil {
		return err
	}
	_, err := w.Write(tag)
	return err
}

// decode reads a full stream produced by encode, verifies its HMAC tag
// against key, and only on success returns the decoded records. Returns
// ErrTampered if the tag doesn't match, before returning any records.
func decode(r io.Reader, key []byte) ([]record, error) {
	all, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	const tagLen = sha256.Size
	if len(all) < len(magic)+4+tagLen {
		return nil, ErrTruncated
	}
	payload := all[:len(all)-tagLen]
	gotTag := all[len(all)-tagLen:]

	wantTag := signTag(key, payload)
	if !hmac.Equal(gotTag, wantTag) {
		return nil, ErrTampered
	}

	if !bytes.Equal(payload[:len(magic)], magic[:]) {
		return nil, fmt.Errorf("backup: bad magic header")
	}
	buf := bytes.NewReader(payload[len(magic):])

	var recs []record
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(buf, lenBuf[:]); err != nil {
			return nil, ErrTruncated
		}
		keyLen := binary.BigEndian.Uint32(lenBuf[:])
		if keyLen == sentinel {
			break
		}
		key := make([]byte, keyLen)
		if _, err := io.ReadFull(buf, key); err != nil {
			return nil, ErrTruncated
		}
		var vLenBuf [4]byte
		if _, err := io.ReadFull(buf, vLenBuf[:]); err != nil {
			return nil, ErrTruncated
		}
		valLen := binary.BigEndian.Uint32(vLenBuf[:])
		val := make([]byte, valLen)
		if _, err := io.ReadFull(buf, val); err != nil {
			return nil, ErrTruncated
		}
		recs = append(recs, record{key: key, value: val})
	}
	return recs, nil
}

func writeChunk(buf *bytes.Buffer, b []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
	buf.Write(lenBuf[:])
	buf.Write(b)
	return nil
}

func signTag(key, payload []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(payload)
	return h.Sum(nil)
}
