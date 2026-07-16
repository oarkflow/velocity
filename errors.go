package velocity

import "errors"

var (
	// ErrKeyNotFound is returned when a key does not exist, is deleted, or has expired.
	ErrKeyNotFound = errors.New("velocity: key not found")
	// ErrEmptyKey is returned when an operation requires a non-empty key.
	ErrEmptyKey = errors.New("velocity: key must not be empty")
	// ErrKeyTooLarge is returned when a key cannot be represented by the on-disk format.
	ErrKeyTooLarge = errors.New("velocity: key exceeds maximum supported size")
	// ErrValueTooLarge is returned when a value cannot be represented by the on-disk format.
	ErrValueTooLarge = errors.New("velocity: value exceeds maximum supported size")
	// ErrClosed is returned when an operation is attempted on a closed database.
	ErrClosed = errors.New("velocity: database is closed")
)

const (
	// MaxKeySize bounds memory use and keeps key lengths representable in WAL/SSTable records.
	MaxKeySize = 16 << 20 // 16 MiB
	// MaxValueSize bounds a single KV value. Large objects should use object/blob storage.
	MaxValueSize = 1 << 30 // 1 GiB
)

func validateKV(key, value []byte) error {
	return validateKVLengths(len(key), len(value))
}

func validateKVLengths(keyLen, valueLen int) error {
	if keyLen == 0 {
		return ErrEmptyKey
	}
	if keyLen > MaxKeySize {
		return ErrKeyTooLarge
	}
	if valueLen > MaxValueSize {
		return ErrValueTooLarge
	}
	return nil
}

func validateKey(key []byte) error {
	return validateKVLengths(len(key), 0)
}
