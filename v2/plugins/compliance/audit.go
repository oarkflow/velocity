package compliance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// chainRecord is one persisted, hash-chained audit entry. Ported (in
// simplified per-event form — v1's audit_immutable.go batched events into
// sealed blocks with a Merkle tree; the api.ComplianceService interface
// here records one AuditEvent at a time, so this chains individual
// records instead of blocks) from v1's ImmutableAuditLog/AuditEvent.
type chainRecord struct {
	Seq      int            `json:"seq"`
	PrevHash string         `json:"prev_hash"`
	Hash     string         `json:"hash"`
	Event    api.AuditEvent `json:"event"`
}

type chainHead struct {
	Seq  int    `json:"seq"`
	Hash string `json:"hash"`
}

// errNotInitialized is returned by every ComplianceService method that
// needs the storage backend when Init hasn't run (or failed). This is the
// concrete fix for v1's silent-no-op GDPRController bug: callers get a
// real error instead of a misleading nil.
var errNotInitialized = errors.New("compliance: not initialized — storage backend is not wired (this plugin never silently no-ops; v1's GDPRController did, which is the bug this fixes)")

func computeHash(seq int, prevHash string, eventJSON []byte) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%s|", seq, prevHash)
	h.Write(eventJSON)
	return hex.EncodeToString(h.Sum(nil))
}

func (p *Plugin) loadHead(ctx context.Context) error {
	data, ok, err := p.storage.Get(ctx, []byte(auditHeadKey))
	if err != nil {
		return err
	}
	if !ok {
		p.headSeq = -1
		p.headHash = ""
		return nil
	}
	var h chainHead
	if err := json.Unmarshal(data, &h); err != nil {
		return fmt.Errorf("decoding audit chain head: %w", err)
	}
	p.headSeq = h.Seq
	p.headHash = h.Hash
	return nil
}

// Record appends ev to the tamper-evident audit chain: seq = previous
// seq + 1, hash = sha256(seq | prevHash | json(ev)), persisted alongside
// the event itself. Record and VerifyChain are the only two places that
// know this encoding.
func (p *Plugin) Record(ctx context.Context, ev api.AuditEvent) error {
	if p.storage == nil {
		return errNotInitialized
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	seq := p.headSeq + 1
	prevHash := p.headHash

	evData, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("compliance: marshal audit event: %w", err)
	}
	hash := computeHash(seq, prevHash, evData)

	rec := chainRecord{Seq: seq, PrevHash: prevHash, Hash: hash, Event: ev}
	recData, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("compliance: marshal audit record: %w", err)
	}
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(auditKey(seq)), Value: recData}); err != nil {
		return fmt.Errorf("compliance: persisting audit record %d: %w", seq, err)
	}

	headData, err := json.Marshal(chainHead{Seq: seq, Hash: hash})
	if err != nil {
		return fmt.Errorf("compliance: marshal audit head: %w", err)
	}
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(auditHeadKey), Value: headData}); err != nil {
		return fmt.Errorf("compliance: persisting audit head: %w", err)
	}

	p.headSeq = seq
	p.headHash = hash
	return nil
}

// VerifyChain walks every record from seq 0 to the current head,
// recomputing each hash and checking prev-hash linkage, and returns a
// descriptive error pinpointing exactly where the chain breaks (missing
// record, unreadable record, prev-hash mismatch, or hash mismatch) if
// tampering is detected.
func (p *Plugin) VerifyChain(ctx context.Context) error {
	if p.storage == nil {
		return errNotInitialized
	}

	p.mu.Lock()
	headSeq := p.headSeq
	headHash := p.headHash
	p.mu.Unlock()

	prevHash := ""
	for seq := 0; seq <= headSeq; seq++ {
		data, ok, err := p.storage.Get(ctx, []byte(auditKey(seq)))
		if err != nil {
			return fmt.Errorf("compliance: audit chain verify: reading record %d: %w", seq, err)
		}
		if !ok {
			return fmt.Errorf("compliance: audit chain broken: record %d is missing", seq)
		}
		var rec chainRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return fmt.Errorf("compliance: audit chain broken: record %d is unreadable: %w", seq, err)
		}
		if rec.Seq != seq {
			return fmt.Errorf("compliance: audit chain broken: record at key %d claims seq %d", seq, rec.Seq)
		}
		if rec.PrevHash != prevHash {
			return fmt.Errorf("compliance: audit chain broken at seq %d: prev-hash mismatch (expected %q, stored %q)", seq, prevHash, rec.PrevHash)
		}
		evData, err := json.Marshal(rec.Event)
		if err != nil {
			return fmt.Errorf("compliance: audit chain verify: re-marshal seq %d: %w", seq, err)
		}
		expected := computeHash(seq, rec.PrevHash, evData)
		if expected != rec.Hash {
			return fmt.Errorf("compliance: audit chain broken at seq %d: hash mismatch (expected %q, stored %q) — record has been tampered with", seq, expected, rec.Hash)
		}
		prevHash = rec.Hash
	}

	if headSeq >= 0 && prevHash != headHash {
		return fmt.Errorf("compliance: audit chain broken: head hash %q does not match last verified record hash %q", headHash, prevHash)
	}
	return nil
}
