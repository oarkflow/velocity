// Package envelope ports v1's envelope.go — a sealed, auditable
// "evidence cabinet" container with an append-only chain-of-custody
// ledger, exportable/importable as a portable encrypted file, and able to
// bundle references to file/secret/kv content (v1's Kind == "bundle"
// pattern; there is no separate persisted "Bundle" entity in v1 either,
// confirmed by reading v1's envelope.go and cmd/velocity/envelope.go).
//
// Deliberately NOT ported from v1 in this pass (v1's Envelope carried a
// much larger policy surface — see envelope.go's EnvelopePolicies):
//   - FingerprintPolicy (biometric access gating)
//   - TimeLockPolicy / TimeLockStatus (legal time-based unlocks)
//   - ColdStoragePolicy / ColdStorageStatus (offline vault scheduling)
//   - TamperPolicy / TamperSignal (offline AI tamper scanning)
//   - AccessPolicy's CentralAPIPolicy (server-side authorization +
//     audit-forwarding webhooks) and its IP-range/trust-level/MFA gates
//
// These are real v1 features, not stubs, but they are policy-enforcement
// concerns that substantially overlap with what v2's compliance plugin
// already owns (PolicyEngine.Evaluate, AuditSink, break-glass). Porting
// them faithfully here would either duplicate that machinery or need a
// cross-plugin design pass of its own; deferred rather than done half-way.
// What IS preserved, faithfully: sealed-at-rest storage via the looked-up
// CryptoProvider, a REAL hash-chained custody ledger (PrevHash/EventHash,
// same structure as v1's CustodyEvent), and tamper-evident export/import
// (AEAD authentication fails outright on any corruption, same guarantee
// v1's encrypted .sec format provided).
package envelope

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

const exportMagic = "VELOPE1\x00"

// Plugin implements api.Plugin + api.EnvelopeService.
type Plugin struct {
	storageDep string
	cryptoDep  string

	storage api.StorageBackend
	crypto  api.CryptoProvider
	kernel  api.Kernel

	mu sync.Mutex // serializes read-modify-write of a single envelope's ledger
}

// NewPlugin constructs the envelope plugin. Empty strings fall back to
// "storage-lsm" and "crypto-xchacha".
func NewPlugin(storageDep, cryptoDep string) *Plugin {
	if storageDep == "" {
		storageDep = "storage-lsm"
	}
	if cryptoDep == "" {
		cryptoDep = "crypto-xchacha"
	}
	return &Plugin{storageDep: storageDep, cryptoDep: cryptoDep}
}

func (p *Plugin) Name() string           { return "envelope" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return []string{p.storageDep, p.cryptoDep} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.kernel = k

	// Looked up by the FIXED service names ("storage"/"crypto"), not
	// p.storageDep/p.cryptoDep — those are plugin Names(), used only for
	// Dependencies()-graph boot ordering above. See
	// docs/ARCHITECTURE.md section (c) for why these are two different
	// namespaces.
	storageSvc := k.Registry().MustLookup("storage")
	storage, ok := storageSvc.(api.StorageBackend)
	if !ok {
		return fmt.Errorf("envelope: service %q does not implement api.StorageBackend", "storage")
	}
	p.storage = storage

	cryptoSvc := k.Registry().MustLookup("crypto")
	crypto, ok := cryptoSvc.(api.CryptoProvider)
	if !ok {
		return fmt.Errorf("envelope: service %q does not implement api.CryptoProvider", "crypto")
	}
	p.crypto = crypto

	return k.Registry().Provide("envelope", p)
}

func (p *Plugin) Start(ctx context.Context) error { return nil }
func (p *Plugin) Stop(ctx context.Context) error  { return nil }
func (p *Plugin) Health() api.Health              { return api.Health{Status: "ok"} }

var _ api.Plugin = (*Plugin)(nil)
var _ api.EnvelopeService = (*Plugin)(nil)

// --- storage record (what actually gets sealed and persisted) ---

type record struct {
	ID        string                 `json:"id"`
	Label     string                 `json:"label"`
	Kind      string                 `json:"kind"`
	CreatedAt time.Time              `json:"created_at"`
	CreatedBy string                 `json:"created_by"`
	Metadata  map[string]string      `json:"metadata,omitempty"`
	Inline    []byte                 `json:"inline,omitempty"`
	Resources []api.EnvelopeResource `json:"resources,omitempty"`
	Custody   []api.CustodyEvent     `json:"custody"`
}

func storageKey(id string) []byte { return []byte("envelope/" + id + "/data") }

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashCustodyEvent(prevHash, actor, action, notes string, ts time.Time) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte("|"))
	h.Write([]byte(actor))
	h.Write([]byte("|"))
	h.Write([]byte(action))
	h.Write([]byte("|"))
	h.Write([]byte(ts.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte("|"))
	h.Write([]byte(notes))
	return hex.EncodeToString(h.Sum(nil))
}

func (p *Plugin) seal(ctx context.Context, id string, r record) ([]byte, error) {
	plaintext, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("envelope: marshal: %w", err)
	}
	return p.crypto.Encrypt(ctx, plaintext, []byte("envelope:"+id))
}

func (p *Plugin) unseal(ctx context.Context, id string, sealed []byte) (record, error) {
	plaintext, err := p.crypto.Decrypt(ctx, sealed, []byte("envelope:"+id))
	if err != nil {
		return record{}, fmt.Errorf("envelope: unseal %q: %w", id, err)
	}
	var r record
	if err := json.Unmarshal(plaintext, &r); err != nil {
		return record{}, fmt.Errorf("envelope: unmarshal %q: %w", id, err)
	}
	return r, nil
}

func (p *Plugin) load(ctx context.Context, id string) (record, error) {
	sealed, ok, err := p.storage.Get(ctx, storageKey(id))
	if err != nil {
		return record{}, err
	}
	if !ok {
		return record{}, fmt.Errorf("envelope: %q not found", id)
	}
	return p.unseal(ctx, id, sealed)
}

func (p *Plugin) save(ctx context.Context, r record) error {
	sealed, err := p.seal(ctx, r.ID, r)
	if err != nil {
		return fmt.Errorf("envelope: seal: %w", err)
	}
	return p.storage.Put(ctx, api.Entry{Key: storageKey(r.ID), Value: sealed})
}

func toAPI(r record) api.Envelope {
	return api.Envelope{
		ID:        r.ID,
		Label:     r.Label,
		Kind:      r.Kind,
		CreatedAt: r.CreatedAt,
		CreatedBy: r.CreatedBy,
		Metadata:  r.Metadata,
		Inline:    r.Inline,
		Resources: r.Resources,
		Custody:   r.Custody,
	}
}

// --- api.EnvelopeService ---

func (p *Plugin) Create(ctx context.Context, actor string, env api.Envelope) (api.Envelope, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	id := env.ID
	if id == "" {
		var err error
		id, err = newID()
		if err != nil {
			return api.Envelope{}, fmt.Errorf("envelope: generate id: %w", err)
		}
	}

	now := time.Now()
	firstEvent := api.CustodyEvent{
		Sequence:  0,
		Timestamp: now,
		Actor:     actor,
		Action:    "created",
	}
	firstEvent.EventHash = hashCustodyEvent("", firstEvent.Actor, firstEvent.Action, firstEvent.Notes, firstEvent.Timestamp)

	r := record{
		ID:        id,
		Label:     env.Label,
		Kind:      env.Kind,
		CreatedAt: now,
		CreatedBy: actor,
		Metadata:  env.Metadata,
		Inline:    env.Inline,
		Resources: env.Resources,
		Custody:   []api.CustodyEvent{firstEvent},
	}

	if err := p.save(ctx, r); err != nil {
		return api.Envelope{}, err
	}
	return toAPI(r), nil
}

func (p *Plugin) Get(ctx context.Context, id string) (api.Envelope, error) {
	r, err := p.load(ctx, id)
	if err != nil {
		return api.Envelope{}, err
	}
	return toAPI(r), nil
}

func (p *Plugin) AppendCustodyEvent(ctx context.Context, id, actor, action, notes string) (api.Envelope, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	r, err := p.load(ctx, id)
	if err != nil {
		return api.Envelope{}, err
	}

	var prevHash string
	if n := len(r.Custody); n > 0 {
		prevHash = r.Custody[n-1].EventHash
	}
	ev := api.CustodyEvent{
		Sequence:  len(r.Custody),
		Timestamp: time.Now(),
		Actor:     actor,
		Action:    action,
		Notes:     notes,
		PrevHash:  prevHash,
	}
	ev.EventHash = hashCustodyEvent(prevHash, ev.Actor, ev.Action, ev.Notes, ev.Timestamp)
	r.Custody = append(r.Custody, ev)

	if err := p.save(ctx, r); err != nil {
		return api.Envelope{}, err
	}
	return toAPI(r), nil
}

// Export writes: magic | 4-byte length-prefixed ID | 4-byte
// length-prefixed sealed bytes. The sealed bytes are the SAME
// AEAD-encrypted record stored at rest (sealed under AAD "envelope:"+id —
// the ID travels alongside in the clear so Import knows which AAD to
// unseal with, since AEAD requires the same AAD used to seal). The AEAD
// tag itself is the tamper check: any corruption of the exported stream —
// including the ID, since it's bound in as AAD — causes Import's Decrypt
// to fail outright rather than silently accepting altered content.
func (p *Plugin) Export(ctx context.Context, id string, w io.Writer) error {
	sealed, ok, err := p.storage.Get(ctx, storageKey(id))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("envelope: %q not found", id)
	}
	if _, err := w.Write([]byte(exportMagic)); err != nil {
		return err
	}
	if err := writeLengthPrefixed(w, []byte(id)); err != nil {
		return err
	}
	return writeLengthPrefixed(w, sealed)
}

func writeLengthPrefixed(w io.Writer, b []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readLengthPrefixed(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Import reads back an Export'd stream, verifies it unseals cleanly
// (rejecting tampered input), and persists it into this instance's store.
func (p *Plugin) Import(ctx context.Context, r io.Reader) (api.Envelope, error) {
	magic := make([]byte, len(exportMagic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return api.Envelope{}, fmt.Errorf("envelope: read magic: %w", err)
	}
	if !bytes.Equal(magic, []byte(exportMagic)) {
		return api.Envelope{}, fmt.Errorf("envelope: not a valid envelope export (bad magic)")
	}
	idBytes, err := readLengthPrefixed(r)
	if err != nil {
		return api.Envelope{}, fmt.Errorf("envelope: read id: %w", err)
	}
	id := string(idBytes)
	sealed, err := readLengthPrefixed(r)
	if err != nil {
		return api.Envelope{}, fmt.Errorf("envelope: read payload: %w", err)
	}

	// Unseal under the same per-ID AAD Export/save use. If the ID field
	// was tampered with independently of the sealed payload, the AAD
	// mismatch makes Decrypt fail here too — the ID is authenticated
	// exactly as strongly as the payload.
	plaintext, err := p.crypto.Decrypt(ctx, sealed, []byte("envelope:"+id))
	if err != nil {
		return api.Envelope{}, fmt.Errorf("envelope: import rejected, seal did not verify (tampered or wrong key): %w", err)
	}
	var r2 record
	if err := json.Unmarshal(plaintext, &r2); err != nil {
		return api.Envelope{}, fmt.Errorf("envelope: unmarshal imported record: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.save(ctx, r2); err != nil {
		return api.Envelope{}, err
	}
	return toAPI(r2), nil
}

func (p *Plugin) ResolveResources(ctx context.Context, id string) (map[string][]byte, error) {
	r, err := p.load(ctx, id)
	if err != nil {
		return nil, err
	}
	if r.Kind != "bundle" {
		return nil, fmt.Errorf("envelope: %q is not a bundle (kind=%q)", id, r.Kind)
	}

	out := make(map[string][]byte, len(r.Resources))
	for _, res := range r.Resources {
		data, err := p.resolveOne(ctx, res)
		if err != nil {
			return nil, fmt.Errorf("envelope: resolve resource %q: %w", res.ID, err)
		}
		out[res.ID] = data
	}
	return out, nil
}

func (p *Plugin) resolveOne(ctx context.Context, res api.EnvelopeResource) ([]byte, error) {
	switch res.Type {
	case "inline":
		return res.Inline, nil

	case "kv":
		svc, ok := p.kernel.Registry().Lookup("kv")
		if !ok {
			return nil, fmt.Errorf("kv service not registered, cannot resolve kv resource %q", res.Ref)
		}
		kv, ok := svc.(api.KVService)
		if !ok {
			return nil, fmt.Errorf("registered %q service does not implement api.KVService", "kv")
		}
		val, found, err := kv.Get(ctx, res.Ref)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("kv key %q not found", res.Ref)
		}
		return val, nil

	case "secret":
		svc, ok := p.kernel.Registry().Lookup("secret")
		if !ok {
			return nil, fmt.Errorf("secret service not registered, cannot resolve secret resource %q", res.Ref)
		}
		sec, ok := svc.(api.SecretService)
		if !ok {
			return nil, fmt.Errorf("registered %q service does not implement api.SecretService", "secret")
		}
		version := 0
		if res.Version != "" {
			if _, err := fmt.Sscanf(res.Version, "%d", &version); err != nil {
				return nil, fmt.Errorf("invalid secret version %q: %w", res.Version, err)
			}
		}
		return sec.Get(ctx, res.Ref, version)

	case "file":
		svc, ok := p.kernel.Registry().Lookup("object")
		if !ok {
			return nil, fmt.Errorf("object service not registered, cannot resolve file resource %q", res.Ref)
		}
		obj, ok := svc.(api.ObjectService)
		if !ok {
			return nil, fmt.Errorf("registered %q service does not implement api.ObjectService", "object")
		}
		bucket, key, ok := splitRef(res.Ref)
		if !ok {
			return nil, fmt.Errorf("file resource ref %q must be \"bucket/key\"", res.Ref)
		}
		rc, _, err := obj.GetObject(ctx, bucket, key, res.Version)
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)

	default:
		return nil, fmt.Errorf("unknown resource type %q", res.Type)
	}
}

func splitRef(ref string) (bucket, key string, ok bool) {
	for i := 0; i < len(ref); i++ {
		if ref[i] == '/' {
			return ref[:i], ref[i+1:], true
		}
	}
	return "", "", false
}
