package s3

import (
	"context"
	"io"
	"time"
)

type KVStore interface {
	PutWithTTL(key, value []byte, ttl time.Duration) error
	Get(key []byte) ([]byte, error)
	Delete(key []byte) error
	Keys(pattern string) ([]string, error)
	Has(key []byte) bool
}

type SecretCodec interface {
	EncryptCredentialSecret(accessKeyID, secret string) (string, error)
	DecryptCredentialSecret(accessKeyID, encrypted string) (string, error)
	HasCredentialEncryption() bool
}

type ObjectLister interface {
	ListObjectsForBucket(prefix string, maxKeys int) (int, error)
}

type MultipartStore interface {
	KVStore
	MultipartPartsDir() string
	PutMultipartObject(ctx context.Context, req MultipartPutObjectRequest) (*MultipartObjectMetadata, error)
}

type MultipartPutObjectRequest struct {
	Bucket        string
	Key           string
	ContentType   string
	User          string
	Reader        io.Reader
	Version       string
	Encrypt       bool
	StorageClass  string
	Metadata      map[string]string
	MultipartETag string
}

type MultipartObjectMetadata struct {
	Path         string
	ETag         string
	Hash         string
	Size         int64
	LastModified int64
}
