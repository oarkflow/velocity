package api

import (
	"context"
	"io"
	"time"
)

// EnvelopeResource identifies one piece of content a bundle envelope
// references, resolved lazily (not copied in) unless Type is "inline".
// This mirrors v1's EnvelopeResource (envelope.go): a bundle is not a
// separate persisted entity in v1 either — it is an Envelope whose Kind
// is "bundle" and whose Resources point at file/secret/kv content stored
// elsewhere, exactly as v1's cmd/velocity envelope bundle create/list/
// resolve subcommands operate (verified by reading v1's envelope.go and
// cmd/velocity/envelope.go: "bundle create" == CreateEnvelope with
// Kind="bundle", "bundle list" == reading Resources off a loaded
// envelope, "bundle resolve" == ResolveResources).
type EnvelopeResource struct {
	ID      string
	Type    string // "file" (object storage), "secret", "kv", "inline"
	Ref     string // "bucket/key" for file, secret name for secret, kv key for kv; unused for inline
	Version string // optional object version / secret version, "" = latest
	Inline  []byte // used only when Type == "inline"
}

// CustodyEvent is one entry in an envelope's append-only, hash-chained
// chain-of-custody ledger — ported from v1's CustodyEvent
// (PrevHash/EventHash chain), ported at reduced field scope (no
// ActorFingerprint/Location/Attachments/References — see
// plugins/envelope's doc comment for the full list of v1 fields
// deliberately dropped in this pass).
type CustodyEvent struct {
	Sequence  int
	Timestamp time.Time
	Actor     string
	Action    string
	Notes     string
	PrevHash  string
	EventHash string
}

// Envelope is a sealed, auditable container — ported from v1's Envelope
// concept (a "secure evidence cabinet" for court evidence / investigation
// records / custody proofs), with v1's fingerprint-gating, time-lock,
// cold-storage-scheduling, AI tamper-scanning, and central-API-webhook
// policies deliberately NOT ported in this pass (see plugins/envelope's
// doc comment for the full rationale) — what's preserved is the part that
// matters most: sealed-at-rest storage, an append-only hash-chained
// custody ledger, and tamper-evident export/import.
type Envelope struct {
	ID        string
	Label     string
	Kind      string // "inline" | "bundle"
	CreatedAt time.Time
	CreatedBy string
	Metadata  map[string]string

	// Inline holds the envelope's own content when Kind == "inline".
	// Sealed (encrypted) at rest by the plugin's CryptoProvider; returned
	// as plaintext from Get/Export since the caller has already been
	// authorized to read the envelope by that point.
	Inline []byte

	// Resources holds resource references when Kind == "bundle".
	Resources []EnvelopeResource

	Custody []CustodyEvent
}

// EnvelopeService is the surface plugins/envelope exposes.
type EnvelopeService interface {
	// Create seals env (Inline sealed via CryptoProvider if Kind ==
	// "inline") and appends the first custody ledger entry
	// (action "created"). env.ID may be left empty to have one
	// generated.
	Create(ctx context.Context, actor string, env Envelope) (Envelope, error)

	// Get loads and unseals an envelope by ID.
	Get(ctx context.Context, id string) (Envelope, error)

	// AppendCustodyEvent extends the hash-chained ledger and persists the
	// updated envelope.
	AppendCustodyEvent(ctx context.Context, id, actor, action, notes string) (Envelope, error)

	// Export writes a portable, sealed, tamper-evident representation of
	// the envelope to w (mirroring v1's ExportEnvelope ".sec" file, at
	// reduced format complexity — see plugins/envelope's doc comment).
	Export(ctx context.Context, id string, w io.Writer) error

	// Import reads an Export'd stream back in, rejecting it if it's been
	// tampered with (the seal fails to authenticate).
	Import(ctx context.Context, r io.Reader) (Envelope, error)

	// ResolveResources fetches the actual content for every resource in
	// a Kind == "bundle" envelope (equivalent to v1's ResolveResources /
	// the CLI's "envelope bundle resolve"), keyed by resource ID.
	ResolveResources(ctx context.Context, id string) (map[string][]byte, error)
}
