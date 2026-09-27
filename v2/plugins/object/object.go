// Package object implements the Velocity v2 "object" plugin: api.ObjectService
// built as a layer over whatever api.StorageBackend is registered under the
// service name "storage".
//
// Ported/adapted from v1's object_storage.go, object_lock.go, and
// storage_tiering.go (retention/legal-hold gating logic, lifecycle rule
// evaluation), rebuilt to go through api.StorageBackend instead of v1's
// direct SSTable access.
//
// Key layout (all keys are ASCII, "/"-delimited, stored via
// api.StorageBackend which is otherwise opaque to structure):
//
//	b/<bucket>/meta                          bucket marker: JSON bucketMeta
//	b/<bucket>/lc                            JSON []api.LifecycleRule
//	b/<bucket>/o/<key>/latest                JSON record — latest version's ObjectMeta + RetentionPolicy
//	b/<bucket>/o/<key>/v/<versionID>/meta    JSON record for one specific version
//	b/<bucket>/o/<key>/v/<versionID>/data    raw object bytes for one specific version
//
// ListObjects scans the "b/<bucket>/o/<prefix>" range and keeps only keys
// ending in "/latest" — every object has exactly one such key regardless
// of how many versions it has, so this yields one row per object without
// needing a separate index structure.
//
// Scope trim vs. v1 for this first pass (documented, not hidden): whole
// object bodies are still buffered in memory on ingest — a Reader is read
// fully via io.ReadAll before being split into blocks (see below) —
// true streaming multipart *ingest* belongs to a future web/S3-facing
// layer built on top of this interface. Deleting the "latest" version does
// not resurrect the previous version as the new latest; it simply removes
// that version's data+meta, matching a "delete-marker-free" simplification
// of S3 versioning semantics for v2's initial rework.
//
// Range reads: object bodies are split into fixed-size rangeBlockSize
// blocks at PutObject time (".../data/block/<n>"), so GetObjectRange only
// reads the blocks overlapping [start,end] instead of the whole object —
// a small range on a large object costs O(1) blocks, not O(size). GetObject
// (no range) still reads every block and concatenates them, since it needs
// the whole body regardless.
//
// Optional erasure-coded storage for large objects: if a plugin
// implementing api.ShardStore is registered under the service name
// "erasure" (see plugins/erasure) AND this plugin's own config enables
// use_erasure_for_large_objects, PutObject bodies at or above
// erasure_threshold_bytes are stored via ShardStore.StoreShards instead of
// plain blocks, giving them Reed-Solomon self-healing durability; reads go
// through ShardStore.ReadShards. This is opt-in and looked up as an
// OptionalDependencies() entry so boot order is deterministic when both
// plugins are enabled, matching the pattern the web plugin already uses
// for its optional auth/metrics dependencies. Trade-off: ShardStore has no
// partial-read API, so GetObjectRange on an erasure-stored object still
// reconstructs the full body before slicing the requested range — the
// O(1)-blocks optimization above applies only to the normal (non-erasure)
// path. ShardStore also has no Delete method, so DeleteObject on an
// erasure-stored version does not remove its shards — documented as a
// follow-up (the shards become unreferenced but are not actively cleaned
// up).
package object

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// ServiceName is the fixed Registry name this plugin provides its
// api.ObjectService under.
const ServiceName = "object"

var (
	ErrBucketNotFound = errors.New("object: bucket not found")
	ErrBucketNotEmpty = errors.New("object: bucket is not empty")
	ErrObjectNotFound = errors.New("object: object not found")
	ErrObjectLocked   = errors.New("object: object is under retention or legal hold and cannot be deleted")
	ErrBucketExists   = errors.New("object: bucket already exists")
	ErrInvalidRange   = errors.New("object: invalid byte range")
	ErrUploadNotFound = errors.New("object: multipart upload not found")
)

// rangeBlockSize is the fixed block size object bodies are split into at
// PutObject time, so GetObjectRange can read only the blocks overlapping
// the requested range instead of the whole object. 256KiB balances key
// count (fewer, larger blocks) against range-read waste (smaller blocks
// mean less over-read at the edges of a range).
const rangeBlockSize = 256 * 1024

type bucketMeta struct {
	CreatedAt time.Time `json:"created_at"`
}

// versionRecord is what's stored at both the "/latest" pointer key and
// each "/v/<versionID>/meta" key. StoredViaErasure marks that this
// version's body lives in the erasure ShardStore (keyed by its data key)
// instead of as plain blocks — see the package doc comment.
type versionRecord struct {
	Meta             api.ObjectMeta      `json:"meta"`
	Retention        api.RetentionPolicy `json:"retention"`
	StoredViaErasure bool                `json:"stored_via_erasure,omitempty"`
}

// Plugin implements api.Plugin and api.ObjectService.
type Plugin struct {
	storageDep string

	storage api.StorageBackend
	events  api.EventBus
	log     api.Logger

	// erasure is optional: nil unless a ShardStore is registered under
	// "erasure" AND useErasure is true (see Init). See the package doc
	// comment for the opt-in mechanism and its trade-offs.
	erasure          api.ShardStore
	useErasure       bool
	erasureThreshold int64

	// crypto is non-nil only when this plugin's "encrypt" config is true
	// AND a CryptoProvider is registered under "crypto" — see Init. When
	// nil, seal/unseal are no-ops. Object bodies are encrypted per-block
	// (see rangeBlockSize) rather than as one whole-object blob, so
	// GetObjectRange can still decrypt only the blocks it actually needs
	// instead of the entire object — see sealBlock/unsealBlock. Bodies
	// routed through the optional erasure ShardStore are sealed as one
	// whole blob instead (see sealWhole/unsealWhole), since ShardStore has
	// no partial-read API anyway (GetObjectRange already reconstructs the
	// full body for erasure-stored objects regardless of encryption).
	//
	// NOT encrypted: individual multipart parts written by UploadPart are
	// stored as plaintext while an upload is in progress — they're a
	// short-lived staging area deleted by cleanupMultipart once
	// CompleteMultipart reassembles and re-writes them through the normal
	// (sealed) PutObject path. Documented trade-off, not an oversight:
	// giving each part its own AAD scheme that doesn't yet know its final
	// block layout would add real complexity for a window that's deleted
	// within the same request in the common case.
	crypto api.CryptoProvider

	lifecycleInterval time.Duration
	stopCh            chan struct{}
	wg                sync.WaitGroup
}

// New constructs the object plugin. storageDep names the storage plugin
// this one depends on for boot ordering (the service-lookup name is
// always the fixed "storage"); it defaults to "storage-lsm" when empty.
func New(storageDep string) *Plugin {
	if storageDep == "" {
		storageDep = "storage-lsm"
	}
	return &Plugin{storageDep: storageDep, lifecycleInterval: time.Minute, stopCh: make(chan struct{})}
}

func (p *Plugin) Name() string           { return "object" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return []string{p.storageDep} }

// OptionalDependencies lists "erasure" and "crypto": if either plugin is
// enabled in the manifest, the kernel Inits it before this one so the
// optional Registry.Lookup calls below are never a boot-order race — same
// pattern as the web plugin's optional auth/metrics dependencies.
func (p *Plugin) OptionalDependencies() []string { return []string{"erasure", "crypto"} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.storage = k.Registry().MustLookup("storage").(api.StorageBackend)
	p.events = k.Events()
	p.log = k.Logger()
	if d := k.Config().Scoped(p.Name()).Duration("lifecycle_interval", 0); d > 0 {
		p.lifecycleInterval = d
	}

	cfg := k.Config().Scoped(p.Name())
	p.useErasure = cfg.Bool("use_erasure_for_large_objects", false)
	p.erasureThreshold = int64(cfg.Int("erasure_threshold_bytes", 1<<20))
	if p.useErasure {
		if svc, ok := k.Registry().Lookup("erasure"); ok {
			if es, ok := svc.(api.ShardStore); ok {
				p.erasure = es
			} else if p.log != nil {
				p.log.Warn("object: service registered under \"erasure\" does not implement api.ShardStore, ignoring")
			}
		} else if p.log != nil {
			p.log.Warn("object: use_erasure_for_large_objects is true but no \"erasure\" service is registered — large objects will use normal block storage")
		}
	}

	if cfg.Bool("encrypt", false) {
		svc, ok := k.Registry().Lookup("crypto")
		if !ok {
			return fmt.Errorf("object: config \"encrypt\" is true but no \"crypto\" service is registered — enable a crypto-* plugin, or set encrypt to false")
		}
		cp, ok := svc.(api.CryptoProvider)
		if !ok {
			return fmt.Errorf("object: service registered under \"crypto\" does not implement api.CryptoProvider")
		}
		p.crypto = cp
	}

	return k.Registry().Provide(ServiceName, api.ObjectService(p))
}

func (p *Plugin) Start(ctx context.Context) error {
	p.wg.Add(1)
	go p.lifecycleLoop(ctx)
	return nil
}

func (p *Plugin) Stop(ctx context.Context) error {
	close(p.stopCh)
	p.wg.Wait()
	return nil
}

func (p *Plugin) Health() api.Health {
	return api.Health{Status: "ok"}
}

// --- bucket ops ---

func bucketMetaKey(bucket string) string        { return "b/" + bucket + "/meta" }
func bucketLifecycleKey(bucket string) string   { return "b/" + bucket + "/lc" }
func objectPrefix(bucket string) string         { return "b/" + bucket + "/o/" }
func objectLatestKey(bucket, key string) string { return objectPrefix(bucket) + key + "/latest" }
func objectVersionMetaKey(bucket, key, versionID string) string {
	return objectPrefix(bucket) + key + "/v/" + versionID + "/meta"
}
func objectVersionDataKey(bucket, key, versionID string) string {
	return objectPrefix(bucket) + key + "/v/" + versionID + "/data"
}

// blockKey addresses one fixed-size block of a version's body (see
// rangeBlockSize). n is zero-based.
func blockKey(bucket, key, versionID string, n int) string {
	return fmt.Sprintf("%s/block/%08d", objectVersionDataKey(bucket, key, versionID), n)
}

// blockCount returns how many rangeBlockSize blocks a body of the given
// size was split into (0 for an empty body).
func blockCount(size int64) int {
	if size <= 0 {
		return 0
	}
	return int((size + rangeBlockSize - 1) / rangeBlockSize)
}

// blockAAD binds a sealed block to its exact bucket/key/versionID/index,
// so a ciphertext can never be silently swapped for another block's.
func blockAAD(bucket, key, versionID string, n int) []byte {
	return []byte(fmt.Sprintf("object-block:%s:%s:%s:%d", bucket, key, versionID, n))
}

// sealBlock/unsealBlock encrypt/decrypt one fixed-size body block. No-ops
// when encryption isn't enabled (p.crypto == nil).
func (p *Plugin) sealBlock(ctx context.Context, bucket, key, versionID string, n int, data []byte) ([]byte, error) {
	if p.crypto == nil {
		return data, nil
	}
	sealed, err := p.crypto.Encrypt(ctx, data, blockAAD(bucket, key, versionID, n))
	if err != nil {
		return nil, fmt.Errorf("object: sealing block %d of %s/%s: %w", n, bucket, key, err)
	}
	return sealed, nil
}

func (p *Plugin) unsealBlock(ctx context.Context, bucket, key, versionID string, n int, data []byte) ([]byte, error) {
	if p.crypto == nil {
		return data, nil
	}
	plain, err := p.crypto.Decrypt(ctx, data, blockAAD(bucket, key, versionID, n))
	if err != nil {
		return nil, fmt.Errorf("object: unsealing block %d of %s/%s: %w", n, bucket, key, err)
	}
	return plain, nil
}

// wholeAAD binds a sealed whole-object blob (the erasure-coded storage
// path) to its exact bucket/key/versionID.
func wholeAAD(bucket, key, versionID string) []byte {
	return []byte(fmt.Sprintf("object-erasure:%s:%s:%s", bucket, key, versionID))
}

// sealWhole/unsealWhole encrypt/decrypt an entire object body as one blob
// — used only for the erasure-coded storage path, since ShardStore has no
// partial-read API to make per-block sealing worthwhile there. No-ops
// when encryption isn't enabled.
func (p *Plugin) sealWhole(ctx context.Context, bucket, key, versionID string, data []byte) ([]byte, error) {
	if p.crypto == nil {
		return data, nil
	}
	sealed, err := p.crypto.Encrypt(ctx, data, wholeAAD(bucket, key, versionID))
	if err != nil {
		return nil, fmt.Errorf("object: sealing %s/%s for erasure storage: %w", bucket, key, err)
	}
	return sealed, nil
}

func (p *Plugin) unsealWhole(ctx context.Context, bucket, key, versionID string, data []byte) ([]byte, error) {
	if p.crypto == nil {
		return data, nil
	}
	plain, err := p.crypto.Decrypt(ctx, data, wholeAAD(bucket, key, versionID))
	if err != nil {
		return nil, fmt.Errorf("object: unsealing %s/%s from erasure storage: %w", bucket, key, err)
	}
	return plain, nil
}

// splitBlocks slices data into rangeBlockSize-sized chunks (the last one
// possibly shorter). Returns nil for empty data.
func splitBlocks(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	blocks := make([][]byte, 0, blockCount(int64(len(data))))
	for i := 0; i < len(data); i += rangeBlockSize {
		end := i + rangeBlockSize
		if end > len(data) {
			end = len(data)
		}
		blocks = append(blocks, data[i:end])
	}
	return blocks
}

func (p *Plugin) CreateBucket(ctx context.Context, bucket string) error {
	_, ok, err := p.storage.Get(ctx, []byte(bucketMetaKey(bucket)))
	if err != nil {
		return err
	}
	if ok {
		return ErrBucketExists
	}
	buf, err := json.Marshal(bucketMeta{CreatedAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	return p.storage.Put(ctx, api.Entry{Key: []byte(bucketMetaKey(bucket)), Value: buf})
}

func (p *Plugin) DeleteBucket(ctx context.Context, bucket string) error {
	if err := p.requireBucket(ctx, bucket); err != nil {
		return err
	}
	objs, err := p.ListObjects(ctx, bucket, "")
	if err != nil {
		return err
	}
	if len(objs) > 0 {
		return ErrBucketNotEmpty
	}
	return p.storage.Delete(ctx, []byte(bucketMetaKey(bucket)))
}

func (p *Plugin) requireBucket(ctx context.Context, bucket string) error {
	_, ok, err := p.storage.Get(ctx, []byte(bucketMetaKey(bucket)))
	if err != nil {
		return err
	}
	if !ok {
		return ErrBucketNotFound
	}
	return nil
}

// --- object ops ---

func newVersionID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%020d-%s", time.Now().UnixNano(), hex.EncodeToString(b[:]))
}

func (p *Plugin) PutObject(ctx context.Context, bucket, key string, r io.Reader, meta api.ObjectMeta) (api.ObjectMeta, error) {
	if err := p.requireBucket(ctx, bucket); err != nil {
		return api.ObjectMeta{}, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return api.ObjectMeta{}, err
	}

	sum := sha256.Sum256(data)
	meta.Bucket = bucket
	meta.Key = key
	meta.VersionID = newVersionID()
	meta.Size = int64(len(data))
	meta.ETag = hex.EncodeToString(sum[:])
	meta.CreatedAt = time.Now().UTC()
	if meta.ContentType == "" {
		meta.ContentType = "application/octet-stream"
	}

	rec := versionRecord{Meta: meta}

	// Opt-in erasure-coded storage for large bodies (see package doc
	// comment). Falls back to normal block storage if disabled, no
	// ShardStore is registered, or the body is under the threshold.
	useErasureForThis := p.erasure != nil && p.useErasure && int64(len(data)) >= p.erasureThreshold
	dataKey := objectVersionDataKey(bucket, key, meta.VersionID)

	if useErasureForThis {
		sealed, err := p.sealWhole(ctx, bucket, key, meta.VersionID, data)
		if err != nil {
			return api.ObjectMeta{}, err
		}
		if err := p.erasure.StoreShards(ctx, dataKey, sealed); err != nil {
			return api.ObjectMeta{}, fmt.Errorf("object: erasure store: %w", err)
		}
		rec.StoredViaErasure = true
	}

	recBuf, err := json.Marshal(rec)
	if err != nil {
		return api.ObjectMeta{}, err
	}

	ops := []api.BatchOp{
		{Entry: api.Entry{Key: []byte(objectVersionMetaKey(bucket, key, meta.VersionID)), Value: recBuf}},
		{Entry: api.Entry{Key: []byte(objectLatestKey(bucket, key)), Value: recBuf}},
	}
	if !useErasureForThis {
		for i, blk := range splitBlocks(data) {
			sealed, err := p.sealBlock(ctx, bucket, key, meta.VersionID, i, blk)
			if err != nil {
				return api.ObjectMeta{}, err
			}
			ops = append(ops, api.BatchOp{Entry: api.Entry{Key: []byte(blockKey(bucket, key, meta.VersionID, i)), Value: sealed}})
		}
	}
	if err := p.storage.Batch(ctx, ops); err != nil {
		return api.ObjectMeta{}, err
	}

	p.publish(ctx, api.TopicObjectPut, map[string]any{"bucket": bucket, "key": key, "version_id": meta.VersionID, "size": meta.Size})
	return meta, nil
}

// readFullBody reconstructs a version's complete body, either from its
// erasure shard set or by concatenating its blocks in order.
func (p *Plugin) readFullBody(ctx context.Context, bucket, key string, rec versionRecord) ([]byte, error) {
	if rec.StoredViaErasure {
		if p.erasure == nil {
			return nil, errors.New("object: version was stored via erasure coding but no \"erasure\" service is registered in this boot")
		}
		data, err := p.erasure.ReadShards(ctx, objectVersionDataKey(bucket, key, rec.Meta.VersionID))
		if err != nil {
			return nil, err
		}
		return p.unsealWhole(ctx, bucket, key, rec.Meta.VersionID, data)
	}

	n := blockCount(rec.Meta.Size)
	body := make([]byte, 0, rec.Meta.Size)
	for i := 0; i < n; i++ {
		blk, ok, err := p.storage.Get(ctx, []byte(blockKey(bucket, key, rec.Meta.VersionID, i)))
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrObjectNotFound
		}
		plain, err := p.unsealBlock(ctx, bucket, key, rec.Meta.VersionID, i, blk)
		if err != nil {
			return nil, err
		}
		body = append(body, plain...)
	}
	return body, nil
}

func (p *Plugin) GetObject(ctx context.Context, bucket, key, versionID string) (io.ReadCloser, api.ObjectMeta, error) {
	rec, err := p.getVersionRecord(ctx, bucket, key, versionID)
	if err != nil {
		return nil, api.ObjectMeta{}, err
	}
	data, err := p.readFullBody(ctx, bucket, key, rec)
	if err != nil {
		return nil, api.ObjectMeta{}, err
	}
	return io.NopCloser(bytes.NewReader(data)), rec.Meta, nil
}

func (p *Plugin) getVersionRecord(ctx context.Context, bucket, key, versionID string) (versionRecord, error) {
	lookupKey := objectLatestKey(bucket, key)
	if versionID != "" {
		lookupKey = objectVersionMetaKey(bucket, key, versionID)
	}
	buf, ok, err := p.storage.Get(ctx, []byte(lookupKey))
	if err != nil {
		return versionRecord{}, err
	}
	if !ok {
		return versionRecord{}, ErrObjectNotFound
	}
	var rec versionRecord
	if err := json.Unmarshal(buf, &rec); err != nil {
		return versionRecord{}, err
	}
	return rec, nil
}

// DeleteObject removes one version (versionID == "" acts on the current
// latest). A LockCompliance object still under RetainUntil or LegalHold
// can never be deleted, regardless of bypassGovernance. A LockGovernance
// object under those same conditions can only be deleted when
// bypassGovernance is true.
func (p *Plugin) DeleteObject(ctx context.Context, bucket, key, versionID string, bypassGovernance bool) error {
	rec, err := p.getVersionRecord(ctx, bucket, key, versionID)
	if err != nil {
		return err
	}
	if locked(rec.Retention) {
		if rec.Retention.Mode == api.LockCompliance || !bypassGovernance {
			return ErrObjectLocked
		}
	}

	vID := rec.Meta.VersionID
	ops := []api.BatchOp{
		{Delete: true, Entry: api.Entry{Key: []byte(objectVersionDataKey(bucket, key, vID))}},
		{Delete: true, Entry: api.Entry{Key: []byte(objectVersionMetaKey(bucket, key, vID))}},
	}
	if versionID == "" {
		ops = append(ops, api.BatchOp{Delete: true, Entry: api.Entry{Key: []byte(objectLatestKey(bucket, key))}})
	}
	if err := p.storage.Batch(ctx, ops); err != nil {
		return err
	}
	p.publish(ctx, api.TopicObjectDelete, map[string]any{"bucket": bucket, "key": key, "version_id": vID})
	return nil
}

func locked(r api.RetentionPolicy) bool {
	if r.LegalHold {
		return true
	}
	return !r.RetainUntil.IsZero() && time.Now().Before(r.RetainUntil)
}

func (p *Plugin) ListObjects(ctx context.Context, bucket, prefix string) ([]api.ObjectMeta, error) {
	scanPrefix := objectPrefix(bucket) + prefix
	it, err := p.storage.Scan(ctx, []byte(scanPrefix))
	if err != nil {
		return nil, err
	}
	defer it.Close()

	var out []api.ObjectMeta
	for it.Next() {
		k := string(it.Key())
		if !strings.HasSuffix(k, "/latest") {
			continue
		}
		var rec versionRecord
		if err := json.Unmarshal(it.Value(), &rec); err != nil {
			return nil, err
		}
		out = append(out, rec.Meta)
	}
	return out, it.Err()
}

func (p *Plugin) PutRetention(ctx context.Context, bucket, key string, policy api.RetentionPolicy) error {
	rec, err := p.getVersionRecord(ctx, bucket, key, "")
	if err != nil {
		return err
	}
	rec.Retention = policy
	buf, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	ops := []api.BatchOp{
		{Entry: api.Entry{Key: []byte(objectLatestKey(bucket, key)), Value: buf}},
		{Entry: api.Entry{Key: []byte(objectVersionMetaKey(bucket, key, rec.Meta.VersionID)), Value: buf}},
	}
	return p.storage.Batch(ctx, ops)
}

func (p *Plugin) SetLifecycle(ctx context.Context, bucket string, rules []api.LifecycleRule) error {
	if err := p.requireBucket(ctx, bucket); err != nil {
		return err
	}
	buf, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	return p.storage.Put(ctx, api.Entry{Key: []byte(bucketLifecycleKey(bucket)), Value: buf})
}

// --- lifecycle scheduler ---

func (p *Plugin) lifecycleLoop(ctx context.Context) {
	defer p.wg.Done()
	ticker := time.NewTicker(p.lifecycleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.runLifecycleOnce(ctx)
		}
	}
}

func (p *Plugin) runLifecycleOnce(ctx context.Context) {
	it, err := p.storage.Scan(ctx, []byte("b/"))
	if err != nil {
		if p.log != nil {
			p.log.Error("object: lifecycle scan failed", "err", err)
		}
		return
	}
	buckets := map[string]bool{}
	for it.Next() {
		k := string(it.Key())
		if !strings.HasSuffix(k, "/lc") {
			continue
		}
		bucket := strings.TrimPrefix(strings.TrimSuffix(k, "/lc"), "b/")
		buckets[bucket] = true
	}
	it.Close()

	for bucket := range buckets {
		p.applyLifecycle(ctx, bucket)
	}
}

func (p *Plugin) applyLifecycle(ctx context.Context, bucket string) {
	buf, ok, err := p.storage.Get(ctx, []byte(bucketLifecycleKey(bucket)))
	if err != nil || !ok {
		return
	}
	var rules []api.LifecycleRule
	if err := json.Unmarshal(buf, &rules); err != nil {
		return
	}
	if len(rules) == 0 {
		return
	}

	objs, err := p.ListObjects(ctx, bucket, "")
	if err != nil {
		return
	}
	now := time.Now()
	for _, o := range objs {
		for _, rule := range rules {
			if rule.Prefix != "" && !strings.HasPrefix(o.Key, rule.Prefix) {
				continue
			}
			if rule.ExpireAfter > 0 && now.Sub(o.CreatedAt) >= rule.ExpireAfter {
				// DeleteObject itself enforces retention/legal-hold — an
				// object under active lock is correctly left alone here.
				if err := p.DeleteObject(ctx, bucket, o.Key, "", false); err != nil && p.log != nil {
					p.log.Warn("object: lifecycle expire skipped", "bucket", bucket, "key", o.Key, "err", err)
				}
			}
			// TransitionAfter/TransitionClass: logged only for now — there
			// is a single storage backend in this rework, so there is no
			// second storage class to actually move data to yet.
			if rule.TransitionAfter > 0 && rule.TransitionClass != "" && now.Sub(o.CreatedAt) >= rule.TransitionAfter && p.log != nil {
				p.log.Info("object: lifecycle transition due (no-op, single storage class)", "bucket", bucket, "key", o.Key, "class", rule.TransitionClass)
			}
		}
	}
}

// --- head / range / copy ---

func (p *Plugin) HeadObject(ctx context.Context, bucket, key, versionID string) (api.ObjectMeta, error) {
	rec, err := p.getVersionRecord(ctx, bucket, key, versionID)
	if err != nil {
		return api.ObjectMeta{}, err
	}
	return rec.Meta, nil
}

// GetObjectRange reads only the blocks overlapping [start,end] instead of
// the whole object (see the package doc comment) — for a small range on a
// large object this is O(1) blocks read, not O(size). start/end are
// inclusive; end == -1 means "to EOF". An out-of-range start returns
// ErrInvalidRange.
//
// Objects stored via erasure coding (rec.StoredViaErasure) don't get this
// optimization: ShardStore has no partial-read API, so the full body is
// reconstructed first and then sliced — documented trade-off, see the
// package doc comment.
func (p *Plugin) GetObjectRange(ctx context.Context, bucket, key, versionID string, start, end int64) (io.ReadCloser, api.ObjectMeta, error) {
	rec, err := p.getVersionRecord(ctx, bucket, key, versionID)
	if err != nil {
		return nil, api.ObjectMeta{}, err
	}
	size := rec.Meta.Size
	if end == -1 || end >= size {
		end = size - 1
	}
	if start < 0 || size == 0 || start > end {
		return nil, api.ObjectMeta{}, ErrInvalidRange
	}

	if rec.StoredViaErasure {
		data, err := p.readFullBody(ctx, bucket, key, rec)
		if err != nil {
			return nil, api.ObjectMeta{}, err
		}
		return io.NopCloser(bytes.NewReader(data[start : end+1])), rec.Meta, nil
	}

	firstBlock := int(start / rangeBlockSize)
	lastBlock := int(end / rangeBlockSize)
	firstBlockOffset := start % rangeBlockSize

	var buf bytes.Buffer
	for i := firstBlock; i <= lastBlock; i++ {
		blk, ok, err := p.storage.Get(ctx, []byte(blockKey(bucket, key, rec.Meta.VersionID, i)))
		if err != nil {
			return nil, api.ObjectMeta{}, err
		}
		if !ok {
			return nil, api.ObjectMeta{}, ErrObjectNotFound
		}
		// Decrypting only the blocks actually read (not the whole object)
		// is what keeps this O(range) instead of O(size) even with
		// encryption enabled — see sealBlock/unsealBlock's doc comment.
		plain, err := p.unsealBlock(ctx, bucket, key, rec.Meta.VersionID, i, blk)
		if err != nil {
			return nil, api.ObjectMeta{}, err
		}
		buf.Write(plain)
	}

	lo := firstBlockOffset
	hi := lo + (end - start + 1)
	out := buf.Bytes()
	if hi > int64(len(out)) {
		hi = int64(len(out))
	}
	return io.NopCloser(bytes.NewReader(out[lo:hi])), rec.Meta, nil
}

func (p *Plugin) CopyObject(ctx context.Context, srcBucket, srcKey, srcVersionID, dstBucket, dstKey string) (api.ObjectMeta, error) {
	body, meta, err := p.GetObject(ctx, srcBucket, srcKey, srcVersionID)
	if err != nil {
		return api.ObjectMeta{}, err
	}
	defer body.Close()
	return p.PutObject(ctx, dstBucket, dstKey, body, api.ObjectMeta{ContentType: meta.ContentType, Tags: meta.Tags})
}

// --- multipart upload ---

func multipartPrefix(bucket, key, uploadID string) string {
	return objectPrefix(bucket) + key + "/mp/" + uploadID + "/"
}
func multipartInitKey(bucket, key, uploadID string) string {
	return multipartPrefix(bucket, key, uploadID) + "init"
}
func multipartPartKey(bucket, key, uploadID string, partNumber int) string {
	return fmt.Sprintf("%spart/%05d", multipartPrefix(bucket, key, uploadID), partNumber)
}

type multipartInit struct {
	ContentType string    `json:"content_type"`
	CreatedAt   time.Time `json:"created_at"`
}

func (p *Plugin) InitiateMultipart(ctx context.Context, bucket, key string) (string, error) {
	if err := p.requireBucket(ctx, bucket); err != nil {
		return "", err
	}
	uploadID := newVersionID()
	buf, err := json.Marshal(multipartInit{ContentType: "application/octet-stream", CreatedAt: time.Now().UTC()})
	if err != nil {
		return "", err
	}
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(multipartInitKey(bucket, key, uploadID)), Value: buf}); err != nil {
		return "", err
	}
	return uploadID, nil
}

func (p *Plugin) requireMultipart(ctx context.Context, bucket, key, uploadID string) error {
	_, ok, err := p.storage.Get(ctx, []byte(multipartInitKey(bucket, key, uploadID)))
	if err != nil {
		return err
	}
	if !ok {
		return ErrUploadNotFound
	}
	return nil
}

func (p *Plugin) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, r io.Reader) (string, error) {
	if err := p.requireMultipart(ctx, bucket, key, uploadID); err != nil {
		return "", err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	etag := hex.EncodeToString(sum[:])
	if err := p.storage.Put(ctx, api.Entry{Key: []byte(multipartPartKey(bucket, key, uploadID, partNumber)), Value: data}); err != nil {
		return "", err
	}
	return etag, nil
}

func (p *Plugin) CompleteMultipart(ctx context.Context, bucket, key, uploadID string, parts []api.PartInfo) (api.ObjectMeta, error) {
	if err := p.requireMultipart(ctx, bucket, key, uploadID); err != nil {
		return api.ObjectMeta{}, err
	}
	sorted := append([]api.PartInfo(nil), parts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PartNumber < sorted[j].PartNumber })

	var body bytes.Buffer
	for _, part := range sorted {
		data, ok, err := p.storage.Get(ctx, []byte(multipartPartKey(bucket, key, uploadID, part.PartNumber)))
		if err != nil {
			return api.ObjectMeta{}, err
		}
		if !ok {
			return api.ObjectMeta{}, fmt.Errorf("object: part %d not found for upload %s", part.PartNumber, uploadID)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != part.ETag {
			return api.ObjectMeta{}, fmt.Errorf("object: part %d ETag mismatch", part.PartNumber)
		}
		body.Write(data)
	}

	meta, err := p.PutObject(ctx, bucket, key, &body, api.ObjectMeta{})
	if err != nil {
		return api.ObjectMeta{}, err
	}
	p.cleanupMultipart(ctx, bucket, key, uploadID)
	return meta, nil
}

func (p *Plugin) AbortMultipart(ctx context.Context, bucket, key, uploadID string) error {
	if err := p.requireMultipart(ctx, bucket, key, uploadID); err != nil {
		return err
	}
	p.cleanupMultipart(ctx, bucket, key, uploadID)
	return nil
}

func (p *Plugin) cleanupMultipart(ctx context.Context, bucket, key, uploadID string) {
	prefix := multipartPrefix(bucket, key, uploadID)
	it, err := p.storage.Scan(ctx, []byte(prefix))
	if err != nil {
		return
	}
	defer it.Close()
	var ops []api.BatchOp
	for it.Next() {
		ops = append(ops, api.BatchOp{Delete: true, Entry: api.Entry{Key: append([]byte(nil), it.Key()...)}})
	}
	if len(ops) > 0 {
		_ = p.storage.Batch(ctx, ops)
	}
}

func (p *Plugin) publish(ctx context.Context, topic string, payload any) {
	if p.events == nil {
		return
	}
	p.events.Publish(ctx, api.Event{Topic: topic, Source: p.Name(), Payload: payload})
}

// objectWatchHandle implements api.WatchHandle for a single Watch
// subscription (see kv's identical pattern in plugins/kv/kv.go — kept as
// a separate unexported type here rather than shared, so object and kv
// stay independently portable).
type objectWatchHandle struct {
	closeOnce func()
}

func (h *objectWatchHandle) Close() { h.closeOnce() }

// Watch implements api.Watchable: it subscribes to this plugin's own
// TopicObjectPut/TopicObjectDelete publications and forwards only events
// whose "bucket/key" has the given prefix, as api.ChangeEvent, until ctx
// is cancelled or the returned WatchHandle is closed.
func (p *Plugin) Watch(ctx context.Context, prefix string) (<-chan api.ChangeEvent, api.WatchHandle, error) {
	if p.events == nil {
		return nil, nil, errors.New("object: no event bus available to watch")
	}

	out := make(chan api.ChangeEvent, 16)
	var closeOnce sync.Once

	deliver := func(ctx context.Context, ev api.Event) {
		m, _ := ev.Payload.(map[string]any)
		bucket, _ := m["bucket"].(string)
		key, _ := m["key"].(string)
		full := bucket + "/" + key
		if !strings.HasPrefix(full, prefix) {
			return
		}
		ce := api.ChangeEvent{Topic: ev.Topic, Key: full, Deleted: ev.Topic == api.TopicObjectDelete}
		select {
		case out <- ce:
		case <-ctx.Done():
		}
	}

	putSub := p.events.Subscribe(api.TopicObjectPut, deliver)
	delSub := p.events.Subscribe(api.TopicObjectDelete, deliver)

	closeFn := func() {
		closeOnce.Do(func() {
			putSub.Unsubscribe()
			delSub.Unsubscribe()
			close(out)
		})
	}

	go func() {
		<-ctx.Done()
		closeFn()
	}()

	return out, &objectWatchHandle{closeOnce: closeFn}, nil
}

var (
	_ api.Plugin        = (*Plugin)(nil)
	_ api.ObjectService = (*Plugin)(nil)
	_ api.Watchable     = (*Plugin)(nil)
)
