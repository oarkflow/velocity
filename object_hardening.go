package velocity

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	ObjectRecordPrefix = "obj:record:"

	ObjectStatePending   = "pending"
	ObjectStateCommitted = "committed"
	ObjectStateDeleted   = "deleted"
)

var ErrObjectIntegrity = errors.New("object integrity verification failed")

type ObjectEncryptionInfo struct {
	Algorithm string `json:"algorithm,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	Version   int    `json:"version,omitempty"`
	Context   string `json:"context,omitempty"`
}

type ObjectRetentionInfo struct {
	Mode            ObjectLockMode `json:"mode,omitempty"`
	RetainUntilDate time.Time      `json:"retain_until_date,omitempty"`
	LegalHold       string         `json:"legal_hold,omitempty"`
}

type ObjectRecord struct {
	ObjectID       string               `json:"object_id"`
	Path           string               `json:"path"`
	Bucket         string               `json:"bucket,omitempty"`
	Key            string               `json:"key,omitempty"`
	Folder         string               `json:"folder"`
	Name           string               `json:"name"`
	ContentType    string               `json:"content_type"`
	State          string               `json:"state"`
	Size           int64                `json:"size"`
	EncryptedSize  int64                `json:"encrypted_size"`
	SHA256         string               `json:"sha256"`
	ETag           string               `json:"etag"`
	Encrypted      bool                 `json:"encrypted"`
	Encryption     ObjectEncryptionInfo `json:"encryption,omitempty"`
	Version        string               `json:"version"`
	VersionID      string               `json:"version_id"`
	IsLatest       bool                 `json:"is_latest"`
	CreatedAt      time.Time            `json:"created_at"`
	ModifiedAt     time.Time            `json:"modified_at"`
	CreatedBy      string               `json:"created_by"`
	ModifiedBy     string               `json:"modified_by"`
	Tags           map[string]string    `json:"tags,omitempty"`
	CustomMetadata map[string]string    `json:"custom_metadata,omitempty"`
	StorageClass   string               `json:"storage_class"`
	Retention      ObjectRetentionInfo  `json:"retention,omitempty"`
}

type PutObjectRequest struct {
	Path            string
	Bucket          string
	Key             string
	ContentType     string
	User            string
	Reader          io.Reader
	Size            int64
	Options         *ObjectOptions
	EnforceBucket   bool
	MultipartETag   string
	SystemOperation bool
}

type GetObjectRequest struct {
	Path      string
	Bucket    string
	Key       string
	User      string
	VersionID string
	System    bool
}

type ObjectStream struct {
	io.ReadCloser
	Record *ObjectRecord
}

type DeleteObjectRequest struct {
	Path             string
	Bucket           string
	Key              string
	User             string
	Hard             bool
	BypassGovernance bool
	System           bool
}

type RepairOptions struct {
	DryRun bool
}

type RepairReport struct {
	PendingRemoved     int `json:"pending_removed"`
	OrphanFilesRemoved int `json:"orphan_files_removed"`
	MissingFiles       int `json:"missing_files"`
	IndexesRebuilt     int `json:"indexes_rebuilt"`
}

func (db *DB) PutObject(ctx context.Context, req PutObjectRequest) (*ObjectRecord, error) {
	_ = ctx
	path := objectRequestPath(req.Path, req.Bucket, req.Key)
	if path == "" {
		return nil, ErrInvalidPath
	}
	path = normalizePath(path)
	if !isValidPath(path) {
		return nil, ErrInvalidPath
	}
	if req.Reader == nil {
		req.Reader = strings.NewReader("")
	}
	opts := req.Options
	if opts == nil {
		opts = &ObjectOptions{Version: DefaultVersion, Encrypt: true}
	}
	if opts.Version == "" {
		opts.Version = DefaultVersion
	}
	if req.SystemOperation {
		opts.SystemOperation = true
	}
	bucket, key := objectSplitBucketKey(path)
	if req.EnforceBucket && bucket != "" {
		if _, err := NewBucketManager(db).HeadBucket(bucket); err != nil {
			return nil, err
		}
	}
	if bucket != "" {
		if enc, err := NewBucketManager(db).GetBucketEncryption(bucket); err == nil && enc != nil {
			opts.Encrypt = true
			if opts.CustomMetadata == nil {
				opts.CustomMetadata = make(map[string]string)
			}
			opts.CustomMetadata["crypto_algorithm"] = enc.SSEAlgorithm
			if enc.KMSKeyID != "" {
				opts.CustomMetadata["kms_key_id"] = enc.KMSKeyID
			}
		}
	}
	if _, err := db.validateObjectCompliance("write", path, req.User, opts.Encrypt, opts.CustomMetadata, nil, opts.SystemOperation); err != nil {
		return nil, err
	}
	if db.filesDir == "" {
		db.filesDir = filepath.Join(db.path, "files")
	}
	objectsDir := filepath.Join(db.filesDir, "objects")
	if err := os.MkdirAll(objectsDir, 0700); err != nil {
		return nil, err
	}

	objectID := generateObjectID()
	versionID := versionIDForObject(db, bucket)
	folder := extractFolder(path)
	if folder != "" {
		folderUser := req.User
		if opts.SystemOperation {
			folderUser = "system"
		}
		if err := db.CreateFolder(folder, folderUser); err != nil && !errors.Is(err, ErrObjectExists) {
			return nil, err
		}
	}

	now := time.Now().UTC()
	record := &ObjectRecord{
		ObjectID:       objectID,
		Path:           path,
		Bucket:         bucket,
		Key:            key,
		Folder:         folder,
		Name:           extractName(path),
		ContentType:    req.ContentType,
		State:          ObjectStatePending,
		Encrypted:      opts.Encrypt && db.crypto != nil,
		Version:        opts.Version,
		VersionID:      versionID,
		IsLatest:       true,
		CreatedAt:      now,
		ModifiedAt:     now,
		CreatedBy:      req.User,
		ModifiedBy:     req.User,
		Tags:           cloneStringMap(opts.Tags),
		CustomMetadata: cloneStringMap(opts.CustomMetadata),
		StorageClass:   opts.StorageClass,
	}
	if record.StorageClass == "" {
		record.StorageClass = "STANDARD"
	}
	if record.Encrypted {
		record.Encryption = ObjectEncryptionInfo{Algorithm: "ChaCha20-Poly1305", Context: objectID}
	}
	if err := db.saveObjectRecord(record); err != nil {
		return nil, err
	}

	tmp, err := os.CreateTemp(objectsDir, "upload-*.tmp")
	if err != nil {
		_ = db.deleteObjectRecord(path)
		return nil, err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	sha := sha256.New()
	md5h := md5.New()
	var plaintextBytes int64
	tee := io.TeeReader(&countReader{R: req.Reader, Count: &plaintextBytes}, io.MultiWriter(sha, md5h))
	if record.Encrypted {
		_, err = io.Copy(tmp, db.crypto.NewEncryptReader(tee, []byte(objectID)))
	} else {
		_, err = io.Copy(tmp, tee)
	}
	if err != nil {
		_ = tmp.Close()
		_ = db.deleteObjectRecord(path)
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = db.deleteObjectRecord(path)
		return nil, err
	}
	encryptedSize, statErr := tmp.Seek(0, io.SeekEnd)
	if statErr != nil {
		_ = tmp.Close()
		_ = db.deleteObjectRecord(path)
		return nil, statErr
	}
	if err := tmp.Close(); err != nil {
		_ = db.deleteObjectRecord(path)
		return nil, err
	}

	finalPath := objectFilePath(db, objectID, versionID)
	if err := os.MkdirAll(filepath.Dir(finalPath), 0700); err != nil {
		_ = db.deleteObjectRecord(path)
		return nil, err
	}
	if err := os.Rename(tmpName, finalPath); err != nil {
		_ = db.deleteObjectRecord(path)
		return nil, err
	}
	_ = syncDir(filepath.Dir(finalPath))
	_ = syncDir(objectsDir)

	record.Size = plaintextBytes
	record.EncryptedSize = encryptedSize
	record.SHA256 = hex.EncodeToString(sha.Sum(nil))
	record.ETag = fmt.Sprintf(`"%s"`, hex.EncodeToString(md5h.Sum(nil)))
	if req.MultipartETag != "" {
		record.ETag = req.MultipartETag
	}
	record.State = ObjectStateCommitted

	if err := db.markObjectVersionsNotLatest(path); err != nil {
		_ = os.Remove(finalPath)
		return nil, err
	}
	if err := db.saveObjectMetadata(record.toMetadata()); err != nil {
		_ = os.Remove(finalPath)
		return nil, err
	}
	if err := db.saveObjectVersion(path, record.toVersion(false)); err != nil {
		_ = os.Remove(finalPath)
		return nil, err
	}
	if opts.ACL != nil {
		opts.ACL.ObjectID = objectID
		if err := db.SetObjectACL(path, opts.ACL); err != nil {
			return nil, err
		}
	} else {
		if err := db.SetObjectACL(path, defaultObjectACL(objectID, req.User)); err != nil {
			return nil, err
		}
	}
	if err := db.indexObject(path, objectID); err != nil {
		return nil, err
	}
	if bucket != "" && key != "" {
		_ = NewObjectLockManager(db).ApplyDefaultRetention(bucket, key)
		record.Retention = db.objectRetentionInfo(bucket, key)
	}
	if err := db.saveObjectRecord(record); err != nil {
		return nil, err
	}
	db.kgAutoIndexObjectRecord(record, nil)
	return record, nil
}

func (db *DB) GetObjectStreamV2(ctx context.Context, req GetObjectRequest) (*ObjectStream, error) {
	_ = ctx
	path := normalizePath(objectRequestPath(req.Path, req.Bucket, req.Key))
	if path == "" || !isValidPath(path) {
		return nil, ErrInvalidPath
	}
	record, err := db.getObjectRecord(path)
	if err != nil {
		return nil, err
	}
	if req.VersionID != "" {
		version, err := db.getObjectVersion(path, req.VersionID)
		if err != nil {
			return nil, err
		}
		if version.DeleteMarker {
			return nil, ErrObjectNotFound
		}
		record.VersionID = version.VersionID
		record.ObjectID = version.ObjectID
		record.Size = version.Size
		record.SHA256 = version.Hash
		record.IsLatest = version.IsLatest
		record.Encrypted = version.Encrypted || record.Encrypted
	} else if db.latestObjectVersionIsDeleteMarker(path) {
		return nil, ErrObjectNotFound
	}
	if record.State == ObjectStateDeleted {
		return nil, ErrObjectNotFound
	}
	if _, err := db.validateObjectCompliance("read", path, req.User, record.Encrypted, record.CustomMetadata, &record.CreatedAt, req.System); err != nil {
		return nil, err
	}
	if !db.hasPermissionInternal(path, req.User, PermissionRead, req.System) {
		return nil, ErrAccessDenied
	}
	f, err := os.Open(objectFilePath(db, record.ObjectID, record.VersionID))
	if err != nil {
		return nil, err
	}
	var r io.Reader = f
	if record.Encrypted && db.crypto != nil {
		r = db.crypto.NewDecryptReader(f, []byte(record.ObjectID))
	}
	return &ObjectStream{ReadCloser: &verifyingReadCloser{Reader: r, closer: f, expectedSHA256: record.SHA256}, Record: record}, nil
}

func (db *DB) latestObjectVersionIsDeleteMarker(path string) bool {
	versions, err := db.ListObjectVersions(path)
	if err != nil {
		return false
	}
	for _, version := range versions {
		if version.IsLatest {
			return version.DeleteMarker
		}
	}
	return false
}

func (db *DB) DeleteObjectV2(ctx context.Context, req DeleteObjectRequest) error {
	_ = ctx
	path := normalizePath(objectRequestPath(req.Path, req.Bucket, req.Key))
	if path == "" || !isValidPath(path) {
		return ErrInvalidPath
	}
	meta, err := db.GetObjectMetadata(path)
	if err != nil {
		return err
	}
	if _, err := db.validateObjectCompliance("delete", path, req.User, meta.Encrypted, meta.CustomMetadata, &meta.CreatedAt, req.System); err != nil {
		return err
	}
	if !db.hasPermissionInternal(path, req.User, PermissionDelete, req.System) {
		return ErrAccessDenied
	}
	bucket, key := objectSplitBucketKey(path)
	if bucket != "" && key != "" && !req.System {
		ok, reason, err := NewObjectLockManager(db).CanDeleteObject(bucket, key, req.User, req.BypassGovernance)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: %s", ErrAccessDenied, reason)
		}
	}
	if req.Hard {
		err := db.hardDeleteObjectUnlocked(path, meta)
		if err == nil {
			db.kgAutoDeleteObject(path)
		}
		return err
	}
	versionID := generateVersionID()
	version := &ObjectVersion{VersionID: versionID, ObjectID: meta.ObjectID, CreatedAt: time.Now().UTC(), CreatedBy: req.User, IsLatest: true, DeleteMarker: true}
	if err := db.markObjectVersionsNotLatest(path); err != nil {
		return err
	}
	meta.IsLatest = false
	if err := db.saveObjectMetadata(meta); err != nil {
		return err
	}
	if err := db.saveObjectVersion(path, version); err != nil {
		return err
	}
	if record, err := db.getObjectRecord(path); err == nil {
		record.State = ObjectStateDeleted
		record.IsLatest = false
		_ = db.saveObjectRecord(record)
	}
	_ = db.Delete([]byte(ObjectIndexPrefix + path))
	db.kgAutoDeleteObject(path)
	return nil
}

func (db *DB) RepairObjectStorage(ctx context.Context, opts RepairOptions) (*RepairReport, error) {
	_ = ctx
	report := &RepairReport{}
	keys, err := db.Keys(ObjectRecordPrefix + "*")
	if err != nil {
		return nil, err
	}
	seenFiles := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		data, err := db.Get([]byte(key))
		if err != nil {
			continue
		}
		var rec ObjectRecord
		if json.Unmarshal(data, &rec) != nil {
			continue
		}
		if rec.State == ObjectStatePending {
			report.PendingRemoved++
			if !opts.DryRun {
				_ = db.deleteObjectRecord(rec.Path)
			}
			continue
		}
		filePath := objectFilePath(db, rec.ObjectID, rec.VersionID)
		seenFiles[filePath] = struct{}{}
		if _, err := os.Stat(filePath); err != nil {
			report.MissingFiles++
			continue
		}
		if !opts.DryRun {
			_ = db.indexObject(rec.Path, rec.ObjectID)
		}
		report.IndexesRebuilt++
	}
	objectsDir := filepath.Join(db.filesDir, "objects")
	_ = filepath.WalkDir(objectsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if _, ok := seenFiles[path]; ok {
			return nil
		}
		report.OrphanFilesRemoved++
		if !opts.DryRun {
			_ = os.Remove(path)
		}
		return nil
	})
	return report, nil
}

type verifyingReadCloser struct {
	io.Reader
	closer         io.Closer
	expectedSHA256 string
	hash           hashWriter
	closed         bool
}

type hashWriter interface {
	io.Writer
	Sum([]byte) []byte
}

func (v *verifyingReadCloser) Read(p []byte) (int, error) {
	if v.hash == nil {
		v.hash = sha256.New()
	}
	n, err := v.Reader.Read(p)
	if n > 0 {
		_, _ = v.hash.Write(p[:n])
	}
	if err == io.EOF && v.expectedSHA256 != "" {
		got := hex.EncodeToString(v.hash.Sum(nil))
		if got != v.expectedSHA256 {
			return n, ErrObjectIntegrity
		}
	}
	return n, err
}

func (v *verifyingReadCloser) Close() error {
	if v.closed {
		return nil
	}
	v.closed = true
	return v.closer.Close()
}

func (db *DB) getObjectRecord(path string) (*ObjectRecord, error) {
	data, err := db.Get([]byte(ObjectRecordPrefix + path))
	if err == nil {
		var rec ObjectRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, err
		}
		return &rec, nil
	}
	meta, err := db.GetObjectMetadata(path)
	if err != nil {
		return nil, err
	}
	rec := objectRecordFromMetadata(meta)
	_ = db.saveObjectRecord(rec)
	return rec, nil
}

func (db *DB) saveObjectRecord(rec *ObjectRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return db.PutWithTTL([]byte(ObjectRecordPrefix+rec.Path), data, 0)
}

func (db *DB) deleteObjectRecord(path string) error {
	return db.Delete([]byte(ObjectRecordPrefix + path))
}

func (db *DB) getObjectVersion(path, versionID string) (*ObjectVersion, error) {
	data, err := db.Get([]byte(ObjectVersionPrefix + path + ":" + versionID))
	if err != nil {
		return nil, ErrInvalidVersion
	}
	var version ObjectVersion
	if err := json.Unmarshal(data, &version); err != nil {
		return nil, err
	}
	return &version, nil
}

func (db *DB) markObjectVersionsNotLatest(path string) error {
	keys, err := db.Keys(ObjectVersionPrefix + path + ":*")
	if err != nil {
		return nil
	}
	for _, key := range keys {
		data, err := db.Get([]byte(key))
		if err != nil {
			continue
		}
		var version ObjectVersion
		if json.Unmarshal(data, &version) != nil || !version.IsLatest {
			continue
		}
		version.IsLatest = false
		encoded, err := json.Marshal(&version)
		if err != nil {
			return err
		}
		if err := db.PutWithTTL([]byte(key), encoded, 0); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) hardDeleteObjectUnlocked(path string, meta *ObjectMetadata) error {
	versions, _ := db.ListObjectVersions(path)
	objectsDir := filepath.Join(db.filesDir, "objects")
	seenObjectDirs := map[string]struct{}{meta.ObjectID: {}}
	for _, version := range versions {
		if version.ObjectID != "" {
			seenObjectDirs[version.ObjectID] = struct{}{}
		}
	}
	for objectID := range seenObjectDirs {
		if err := os.RemoveAll(filepath.Join(objectsDir, objectID)); err != nil {
			return err
		}
	}
	_ = db.Delete([]byte(ObjectMetaPrefix + path))
	_ = db.Delete([]byte(ObjectACLPrefix + path))
	_ = db.Delete([]byte(ObjectIndexPrefix + path))
	_ = db.Delete([]byte(ObjectRecordPrefix + path))
	versionKeys, _ := db.Keys(ObjectVersionPrefix + path + ":*")
	for _, key := range versionKeys {
		_ = db.Delete([]byte(key))
	}
	return nil
}

func (rec *ObjectRecord) toMetadata() *ObjectMetadata {
	hashValue := rec.SHA256
	if strings.Contains(rec.ETag, "-") {
		hashValue = rec.ETag
	}
	return &ObjectMetadata{
		ObjectID:       rec.ObjectID,
		Path:           rec.Path,
		Folder:         rec.Folder,
		Name:           rec.Name,
		ContentType:    rec.ContentType,
		Size:           rec.Size,
		Hash:           hashValue,
		Encrypted:      rec.Encrypted,
		EncryptionAlgo: rec.Encryption.Algorithm,
		Version:        rec.Version,
		VersionID:      rec.VersionID,
		IsLatest:       rec.IsLatest,
		CreatedAt:      rec.CreatedAt,
		ModifiedAt:     rec.ModifiedAt,
		CreatedBy:      rec.CreatedBy,
		ModifiedBy:     rec.ModifiedBy,
		Tags:           cloneStringMap(rec.Tags),
		CustomMetadata: cloneStringMap(rec.CustomMetadata),
		Checksum:       rec.SHA256,
		StorageClass:   rec.StorageClass,
		ETag:           rec.ETag,
		State:          rec.State,
		EncryptedSize:  rec.EncryptedSize,
	}
}

func (rec *ObjectRecord) toVersion(deleteMarker bool) *ObjectVersion {
	return &ObjectVersion{
		VersionID:    rec.VersionID,
		ObjectID:     rec.ObjectID,
		Size:         rec.Size,
		Hash:         rec.SHA256,
		ETag:         rec.ETag,
		CreatedAt:    rec.CreatedAt,
		CreatedBy:    rec.CreatedBy,
		IsLatest:     rec.IsLatest,
		DeleteMarker: deleteMarker,
		Encrypted:    rec.Encrypted,
	}
}

func objectRecordFromMetadata(meta *ObjectMetadata) *ObjectRecord {
	bucket, key := objectSplitBucketKey(meta.Path)
	state := meta.State
	if state == "" {
		state = ObjectStateCommitted
	}
	etag := meta.ETag
	if etag == "" && meta.Hash != "" {
		etag = `"` + meta.Hash + `"`
	}
	return &ObjectRecord{
		ObjectID:       meta.ObjectID,
		Path:           meta.Path,
		Bucket:         bucket,
		Key:            key,
		Folder:         meta.Folder,
		Name:           meta.Name,
		ContentType:    meta.ContentType,
		State:          state,
		Size:           meta.Size,
		EncryptedSize:  meta.EncryptedSize,
		SHA256:         objectFirstNonEmpty(meta.Checksum, meta.Hash),
		ETag:           etag,
		Encrypted:      meta.Encrypted,
		Encryption:     ObjectEncryptionInfo{Algorithm: meta.EncryptionAlgo, Context: meta.ObjectID},
		Version:        meta.Version,
		VersionID:      meta.VersionID,
		IsLatest:       meta.IsLatest,
		CreatedAt:      meta.CreatedAt,
		ModifiedAt:     meta.ModifiedAt,
		CreatedBy:      meta.CreatedBy,
		ModifiedBy:     meta.ModifiedBy,
		Tags:           cloneStringMap(meta.Tags),
		CustomMetadata: cloneStringMap(meta.CustomMetadata),
		StorageClass:   meta.StorageClass,
	}
}

func objectRequestPath(path, bucket, key string) string {
	if path != "" {
		return path
	}
	if bucket == "" {
		return key
	}
	if key == "" {
		return bucket
	}
	return bucket + "/" + key
}

func objectSplitBucketKey(path string) (string, string) {
	path = normalizePath(path)
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func objectFilePath(db *DB, objectID, versionID string) string {
	return filepath.Join(db.filesDir, "objects", objectID, versionID)
}

func versionIDForObject(db *DB, bucket string) string {
	if bucket == "" {
		return generateVersionID()
	}
	state, err := NewBucketVersioning(db).GetVersioning(bucket)
	if err == nil && state == VersioningSuspended {
		return "null"
	}
	return generateVersionID()
}

func defaultObjectACL(objectID, user string) *ObjectACL {
	return &ObjectACL{
		ObjectID:    objectID,
		Owner:       user,
		Permissions: map[string][]string{user: {PermissionFull}},
		Public:      false,
		CreatedAt:   time.Now().UTC(),
		ModifiedAt:  time.Now().UTC(),
	}
}

func (db *DB) objectRetentionInfo(bucket, key string) ObjectRetentionInfo {
	olm := NewObjectLockManager(db)
	info := ObjectRetentionInfo{}
	if ret, _ := olm.GetObjectRetention(bucket, key); ret != nil {
		info.Mode = ret.Mode
		info.RetainUntilDate = ret.RetainUntilDate
	}
	if hold, _ := olm.GetObjectLegalHold(bucket, key); hold != nil {
		info.LegalHold = hold.Status
	}
	return info
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func objectFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
