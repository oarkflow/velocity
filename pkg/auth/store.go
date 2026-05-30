package auth

type KVStore interface {
	Put(key, value []byte) error
	Get(key []byte) ([]byte, error)
	Delete(key []byte) error
	Keys(pattern string) ([]string, error)
	Has(key []byte) bool
}
