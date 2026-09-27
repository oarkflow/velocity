// Package document implements the Velocity v2 "document" plugin:
// api.DocumentService, storing one JSON blob per key in a looked-up
// api.StorageBackend and supporting dot-notation Get/Set/Delete against a
// single field within that blob (e.g. "user.address.city", or "tags.0"
// for an array index) without the caller loading/mutating/re-saving the
// whole document by hand.
//
// Numeric values: documents are decoded with json.Decoder.UseNumber(), so
// numbers round-trip as json.Number (a string-backed type with
// Int64()/Float64()/String() accessors) instead of Go's default
// json.Unmarshal behavior of decoding every JSON number as float64. This
// avoids silently losing precision on large integers (a float64 cannot
// exactly represent every int64) and preserves the number's original
// textual form on write-back. Callers that want a plain float64 or int64
// can call the appropriate method on the returned json.Number.
package document

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/oarkflow/velocity/v2/api"
)

// ServiceName is the fixed Registry name this plugin provides its
// api.DocumentService under.
const ServiceName = "document"

// ErrTypeMismatch is returned (wrapped) by Get when a dot-notation path
// continues past a segment whose actual JSON type can't be navigated the
// way the next segment requires (e.g. the path expects an object but the
// stored value at that point is a string, or expects an array but finds
// an object). This is distinct from "not found": a missing key or an
// out-of-range/negative array index returns (nil, false, nil) with no
// error, since that's the normal shape of "nothing is there yet" — but a
// present value of the wrong kind is a real caller bug in the path it
// asked for, so it's surfaced as an error instead of silently returning
// not-found. Navigating through an explicit JSON null is treated as
// not-found (not a type mismatch), since null commonly means "not set
// yet" in practice.
var ErrTypeMismatch = errors.New("document: path segment type mismatch")

// ErrEmptyPath is returned by Set/Delete, which require a non-empty
// dot-notation path (use SetJSON to replace/create a whole document).
var ErrEmptyPath = errors.New("document: path must not be empty")

// Plugin implements api.Plugin and api.DocumentService.
type Plugin struct {
	storageDep string
	storage    api.StorageBackend
}

// NewPlugin constructs the document plugin. storageDep names the storage
// plugin this one depends on for boot ordering (NOT the service-lookup
// name, which is always the fixed "storage"); it defaults to
// "storage-lsm" when empty.
func NewPlugin(storageDep string) *Plugin {
	if storageDep == "" {
		storageDep = "storage-lsm"
	}
	return &Plugin{storageDep: storageDep}
}

func (p *Plugin) Name() string           { return "document" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return []string{p.storageDep} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.storage = k.Registry().MustLookup("storage").(api.StorageBackend)
	return k.Registry().Provide(ServiceName, api.DocumentService(p))
}

func (p *Plugin) Start(ctx context.Context) error { return nil }
func (p *Plugin) Stop(ctx context.Context) error  { return nil }
func (p *Plugin) Health() api.Health              { return api.Health{Status: "ok"} }

var (
	_ api.Plugin          = (*Plugin)(nil)
	_ api.DocumentService = (*Plugin)(nil)
)

// storageKey namespaces document blobs within the shared StorageBackend
// keyspace so they can't collide with keys any other plugin (kv, object,
// ...) writes there.
func storageKey(key string) []byte {
	return []byte("document/" + key)
}

// SetJSON replaces the entire document at key.
func (p *Plugin) SetJSON(ctx context.Context, key string, doc json.RawMessage) error {
	if key == "" {
		return errors.New("document: key must not be empty")
	}
	if !json.Valid(doc) {
		return errors.New("document: doc is not valid JSON")
	}
	cp := make([]byte, len(doc))
	copy(cp, doc)
	return p.storage.Put(ctx, api.Entry{Key: storageKey(key), Value: cp})
}

// GetJSON returns the entire document at key.
func (p *Plugin) GetJSON(ctx context.Context, key string) (json.RawMessage, bool, error) {
	if key == "" {
		return nil, false, errors.New("document: key must not be empty")
	}
	v, ok, err := p.storage.Get(ctx, storageKey(key))
	if err != nil || !ok {
		return nil, ok, err
	}
	return json.RawMessage(v), true, nil
}

// loadDoc decodes the document at key into a generic any tree
// (map[string]any / []any / json.Number / string / bool / nil), using
// UseNumber for the reason documented on the package. Returns (nil,
// false, nil) if no document exists at key yet — that is not an error,
// since Set is expected to create one on demand.
func (p *Plugin) loadDoc(ctx context.Context, key string) (any, bool, error) {
	v, ok, err := p.storage.Get(ctx, storageKey(key))
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}
	dec := json.NewDecoder(bytes.NewReader(v))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, false, fmt.Errorf("document: stored value for %q is not valid JSON: %w", key, err)
	}
	return doc, true, nil
}

func (p *Plugin) saveDoc(ctx context.Context, key string, root any) error {
	b, err := json.Marshal(root)
	if err != nil {
		return fmt.Errorf("document: marshal: %w", err)
	}
	return p.storage.Put(ctx, api.Entry{Key: storageKey(key), Value: b})
}

// splitPath turns "user.address.city" into ["user","address","city"].
func splitPath(path string) []string {
	if path == "" {
		return nil
	}
	return strings.Split(path, ".")
}

// parseIndexSegment reports whether seg parses as an integer (positive or
// negative) — i.e. whether it should be treated as an array index rather
// than an object key. A negative or out-of-range index is still "looks
// like an index" (so a wrong-type check against a non-array still fires
// correctly); bounds are checked separately by each caller.
func parseIndexSegment(seg string) (idx int, looksLikeIndex bool) {
	n, err := strconv.Atoi(seg)
	if err != nil {
		return 0, false
	}
	return n, true
}

// Get resolves path within the document at key. See ErrTypeMismatch's
// doc comment for the not-found-vs-error distinction.
func (p *Plugin) Get(ctx context.Context, key, path string) (any, bool, error) {
	doc, ok, err := p.loadDoc(ctx, key)
	if err != nil || !ok {
		return nil, false, err
	}
	if path == "" {
		return doc, true, nil
	}
	return navigate(doc, splitPath(path))
}

func navigate(doc any, segs []string) (any, bool, error) {
	cur := doc
	for i, seg := range segs {
		if cur == nil {
			// Missing key, out-of-range index, or an explicit JSON null
			// encountered earlier in the path — all "nothing here yet",
			// not an error. See ErrTypeMismatch's doc comment.
			return nil, false, nil
		}
		if idx, isIdx := parseIndexSegment(seg); isIdx {
			arr, isArr := cur.([]any)
			if !isArr {
				return nil, false, fmt.Errorf("%w: expected array at %q, got %T", ErrTypeMismatch, strings.Join(segs[:i], "."), cur)
			}
			if idx < 0 || idx >= len(arr) {
				return nil, false, nil
			}
			cur = arr[idx]
		} else {
			obj, isObj := cur.(map[string]any)
			if !isObj {
				return nil, false, fmt.Errorf("%w: expected object at %q, got %T", ErrTypeMismatch, strings.Join(segs[:i], "."), cur)
			}
			v, exists := obj[seg]
			if !exists {
				return nil, false, nil
			}
			cur = v
		}
	}
	return cur, true, nil
}

// Set writes value at path within the document at key, creating
// intermediate objects (never arrays — see api.DocumentService's doc
// comment) as needed. If the document at key doesn't exist yet, Set
// creates one starting from an empty object.
func (p *Plugin) Set(ctx context.Context, key, path string, value any) error {
	if path == "" {
		return ErrEmptyPath
	}
	doc, _, err := p.loadDoc(ctx, key)
	if err != nil {
		return err
	}
	newRoot, err := setPath(doc, splitPath(path), value)
	if err != nil {
		return err
	}
	return p.saveDoc(ctx, key, newRoot)
}

// setPath returns the (possibly newly-created) container that should
// replace cur, after applying value at the non-empty path segs within it.
func setPath(cur any, segs []string, value any) (any, error) {
	seg := segs[0]
	rest := segs[1:]

	if idx, isIdx := parseIndexSegment(seg); isIdx {
		arr, isArr := cur.([]any)
		switch {
		case isArr:
			// fall through to bounds check below
		case cur == nil:
			return nil, fmt.Errorf("%w: cannot create an array automatically at index segment %q — arrays are only indexed, never auto-extended; initialize the array first (e.g. via SetJSON or by Set-ing a sibling object field)", ErrTypeMismatch, seg)
		default:
			return nil, fmt.Errorf("%w: expected array at segment %q, got %T", ErrTypeMismatch, seg, cur)
		}
		if idx < 0 || idx >= len(arr) {
			return nil, fmt.Errorf("document: array index %d out of range (len=%d) at segment %q — arrays are only indexed, never auto-extended", idx, len(arr), seg)
		}
		if len(rest) == 0 {
			arr[idx] = value
			return arr, nil
		}
		child, err := setPath(arr[idx], rest, value)
		if err != nil {
			return nil, err
		}
		arr[idx] = child
		return arr, nil
	}

	var obj map[string]any
	switch v := cur.(type) {
	case map[string]any:
		obj = v
	case nil:
		obj = map[string]any{}
	default:
		return nil, fmt.Errorf("%w: expected object at segment %q, got %T", ErrTypeMismatch, seg, cur)
	}
	if len(rest) == 0 {
		obj[seg] = value
		return obj, nil
	}
	child, err := setPath(obj[seg], rest, value)
	if err != nil {
		return nil, err
	}
	obj[seg] = child
	return obj, nil
}

// Delete removes the field at path within the document at key. Missing
// documents, missing paths, and (deliberately, for leniency on a
// best-effort cleanup operation) paths that can't be navigated due to a
// type mismatch are all silent no-ops — Delete never errors on "there was
// nothing to delete", only on a genuine storage failure.
func (p *Plugin) Delete(ctx context.Context, key, path string) error {
	if path == "" {
		return ErrEmptyPath
	}
	doc, ok, err := p.loadDoc(ctx, key)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	newRoot := deletePath(doc, splitPath(path))
	return p.saveDoc(ctx, key, newRoot)
}

// deletePath returns the (possibly mutated) container that should
// replace cur after removing path segs from within it. Any segment that
// can't be navigated (missing key/index, or a type mismatch) leaves cur
// unchanged — see Delete's doc comment on why type mismatches are
// tolerated here but not in Get.
func deletePath(cur any, segs []string) any {
	seg := segs[0]
	rest := segs[1:]

	if idx, isIdx := parseIndexSegment(seg); isIdx {
		arr, isArr := cur.([]any)
		if !isArr || idx < 0 || idx >= len(arr) {
			return cur
		}
		if len(rest) == 0 {
			out := make([]any, 0, len(arr)-1)
			out = append(out, arr[:idx]...)
			out = append(out, arr[idx+1:]...)
			return out
		}
		arr[idx] = deletePath(arr[idx], rest)
		return arr
	}

	obj, isObj := cur.(map[string]any)
	if !isObj {
		return cur
	}
	if len(rest) == 0 {
		delete(obj, seg)
		return obj
	}
	v, exists := obj[seg]
	if !exists {
		return obj
	}
	obj[seg] = deletePath(v, rest)
	return obj
}
