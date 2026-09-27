package envelope

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// --- minimal in-test stubs (avoid depending on other agents' packages) ---

type memStorage struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemStorage() *memStorage { return &memStorage{data: map[string][]byte{}} }

func (m *memStorage) Get(ctx context.Context, key []byte) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[string(key)]
	return v, ok, nil
}
func (m *memStorage) Put(ctx context.Context, e api.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[string(e.Key)] = e.Value
	return nil
}
func (m *memStorage) Delete(ctx context.Context, key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, string(key))
	return nil
}
func (m *memStorage) Batch(ctx context.Context, ops []api.BatchOp) error {
	for _, op := range ops {
		if op.Delete {
			_ = m.Delete(ctx, op.Entry.Key)
		} else {
			_ = m.Put(ctx, op.Entry)
		}
	}
	return nil
}
func (m *memStorage) Scan(ctx context.Context, prefix []byte) (api.Iterator, error) { return nil, nil }
func (m *memStorage) Snapshot(ctx context.Context) (api.Snapshot, error)            { return nil, nil }
func (m *memStorage) Close() error                                                  { return nil }

var _ api.StorageBackend = (*memStorage)(nil)

// fakeCrypto is a real (not no-op) reversible cipher for tests: XOR with a
// fixed key stream salted by AAD, plus an AAD-bound checksum so tampering
// with either ciphertext or AAD is detected — enough to exercise real
// tamper-rejection behavior without pulling in a real crypto plugin.
type fakeCrypto struct{}

func (fakeCrypto) Name() string { return "fake" }

func (fakeCrypto) Encrypt(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	out := make([]byte, len(plaintext))
	for i, b := range plaintext {
		out[i] = b ^ keystream(aad, i)
	}
	sum := checksum(aad, out)
	return append(sum, out...), nil
}

func (fakeCrypto) Decrypt(ctx context.Context, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < 4 {
		return nil, errShort
	}
	sum, body := ciphertext[:4], ciphertext[4:]
	want := checksum(aad, body)
	if !bytes.Equal(sum, want) {
		return nil, errAuth
	}
	out := make([]byte, len(body))
	for i, b := range body {
		out[i] = b ^ keystream(aad, i)
	}
	return out, nil
}

func keystream(aad []byte, i int) byte {
	if len(aad) == 0 {
		return byte(i)
	}
	return aad[i%len(aad)] ^ byte(i)
}

func checksum(aad, body []byte) []byte {
	var sum uint32
	for _, b := range aad {
		sum = sum*31 + uint32(b)
	}
	for _, b := range body {
		sum = sum*31 + uint32(b)
	}
	return []byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)}
}

type simpleErr string

func (e simpleErr) Error() string { return string(e) }

const (
	errShort = simpleErr("ciphertext too short")
	errAuth  = simpleErr("authentication failed")
)

// realCrypto adapts fakeCrypto to api.CryptoProvider (stream methods
// unused by these tests, implemented minimally to satisfy the interface).
type realCrypto struct{ fakeCrypto }

func (realCrypto) EncryptStream(w io.Writer) (io.WriteCloser, error) { return nil, errUnsupported }
func (realCrypto) DecryptStream(r io.Reader) (io.Reader, error)      { return nil, errUnsupported }

const errUnsupported = simpleErr("unsupported in test stub")

func newPlugin(t *testing.T) (*Plugin, *memStorage) {
	t.Helper()
	storage := newMemStorage()
	p := NewPlugin("storage-lsm", "crypto-xchacha")
	p.storage = storage
	p.crypto = realCrypto{}
	p.kernel = nil // not needed unless ResolveResources looks up other services
	return p, storage
}

func TestCreateGetRoundTrip(t *testing.T) {
	p, _ := newPlugin(t)
	ctx := context.Background()

	env, err := p.Create(ctx, "alice", api.Envelope{Label: "test", Kind: "inline", Inline: []byte("hello world")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if env.ID == "" {
		t.Fatal("expected generated ID")
	}
	if len(env.Custody) != 1 || env.Custody[0].Action != "created" {
		t.Fatalf("expected one 'created' custody event, got %+v", env.Custody)
	}

	got, err := p.Get(ctx, env.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.Inline, []byte("hello world")) {
		t.Fatalf("Inline mismatch: got %q", got.Inline)
	}
}

func TestAppendCustodyEventChain(t *testing.T) {
	p, _ := newPlugin(t)
	ctx := context.Background()

	env, err := p.Create(ctx, "alice", api.Envelope{Kind: "inline", Inline: []byte("x")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated, err := p.AppendCustodyEvent(ctx, env.ID, "bob", "reviewed", "looks fine")
	if err != nil {
		t.Fatalf("AppendCustodyEvent: %v", err)
	}
	if len(updated.Custody) != 2 {
		t.Fatalf("expected 2 custody events, got %d", len(updated.Custody))
	}
	if updated.Custody[1].PrevHash != updated.Custody[0].EventHash {
		t.Fatalf("hash chain broken: PrevHash %q != prior EventHash %q", updated.Custody[1].PrevHash, updated.Custody[0].EventHash)
	}
	if updated.Custody[1].EventHash == "" {
		t.Fatal("expected non-empty EventHash")
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	p, _ := newPlugin(t)
	ctx := context.Background()

	env, err := p.Create(ctx, "alice", api.Envelope{Kind: "inline", Inline: []byte("secret payload")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var buf bytes.Buffer
	if err := p.Export(ctx, env.ID, &buf); err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Import into a fresh plugin instance (fresh storage) to prove the
	// export is genuinely portable, not just re-reading the same store.
	p2, _ := newPlugin(t)
	imported, err := p2.Import(ctx, bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !bytes.Equal(imported.Inline, []byte("secret payload")) {
		t.Fatalf("Inline mismatch after import: got %q", imported.Inline)
	}
	if imported.ID != env.ID {
		t.Fatalf("ID mismatch: got %q want %q", imported.ID, env.ID)
	}
}

func TestImportRejectsTamperedPayload(t *testing.T) {
	p, _ := newPlugin(t)
	ctx := context.Background()

	env, err := p.Create(ctx, "alice", api.Envelope{Kind: "inline", Inline: []byte("secret payload")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var buf bytes.Buffer
	if err := p.Export(ctx, env.ID, &buf); err != nil {
		t.Fatalf("Export: %v", err)
	}
	tampered := buf.Bytes()
	// Flip a byte well inside the sealed payload (after magic + id length +
	// id bytes + payload length prefix).
	flipIdx := len(tampered) - 1
	tampered[flipIdx] ^= 0xFF

	p2, _ := newPlugin(t)
	if _, err := p2.Import(ctx, bytes.NewReader(tampered)); err == nil {
		t.Fatal("expected Import to reject tampered payload, got nil error")
	}
}

func TestBundleResolveResources(t *testing.T) {
	p, _ := newPlugin(t)
	ctx := context.Background()

	env, err := p.Create(ctx, "alice", api.Envelope{
		Kind: "bundle",
		Resources: []api.EnvelopeResource{
			{ID: "r1", Type: "inline", Inline: []byte("inline-data")},
		},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	resolved, err := p.ResolveResources(ctx, env.ID)
	if err != nil {
		t.Fatalf("ResolveResources: %v", err)
	}
	if !bytes.Equal(resolved["r1"], []byte("inline-data")) {
		t.Fatalf("resource r1 mismatch: got %q", resolved["r1"])
	}
}

func TestResolveResourcesRejectsNonBundle(t *testing.T) {
	p, _ := newPlugin(t)
	ctx := context.Background()

	env, err := p.Create(ctx, "alice", api.Envelope{Kind: "inline", Inline: []byte("x")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := p.ResolveResources(ctx, env.ID); err == nil {
		t.Fatal("expected error resolving resources on a non-bundle envelope")
	}
}
