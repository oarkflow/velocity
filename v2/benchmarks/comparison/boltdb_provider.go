package comparison

import (
	"fmt"

	bolt "go.etcd.io/bbolt"
)

var boltBucket = []byte("kv")

// BoltEngine wraps a real go.etcd.io/bbolt database as a plain
// key-value store. bbolt fsyncs on every Update transaction by default
// (NoSync is left false), matching the durability level the other two
// providers run at.
type BoltEngine struct {
	db *bolt.DB
}

func NewBoltEngine(path string) (*BoltEngine, error) {
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("boltdb: open: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(boltBucket)
		return err
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("boltdb: create bucket: %w", err)
	}
	return &BoltEngine{db: db}, nil
}

func (e *BoltEngine) Put(key, value []byte) error {
	return e.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(boltBucket).Put(key, value)
	})
}

func (e *BoltEngine) Get(key []byte) ([]byte, bool, error) {
	var out []byte
	err := e.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(boltBucket).Get(key)
		if v != nil {
			out = append([]byte(nil), v...) // bbolt's returned slice is only valid within the transaction
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, out != nil, nil
}

func (e *BoltEngine) Close() error {
	return e.db.Close()
}

var _ KVEngine = (*BoltEngine)(nil)
