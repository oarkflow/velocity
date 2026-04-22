package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	bolt "go.etcd.io/bbolt"
)

var bucketName = []byte("users")

type BoltDBProvider struct {
	db   *bolt.DB
	path string
}

func NewBoltDBProvider(path string) *BoltDBProvider {
	return &BoltDBProvider{path: path}
}

func (p *BoltDBProvider) Name() string {
	return "BoltDB"
}

func (p *BoltDBProvider) Setup(ctx context.Context) error {
	os.Remove(p.path)
	db, err := bolt.Open(p.path, 0600, nil)
	if err != nil {
		return err
	}
	p.db = db
	return p.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketName)
		return err
	})
}

func (p *BoltDBProvider) Cleanup(ctx context.Context) error {
	if p.db != nil {
		p.db.Close()
	}
	return os.Remove(p.path)
}

func (p *BoltDBProvider) Insert(ctx context.Context, id int, name string, age int) error {
	return p.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		key := []byte(fmt.Sprintf("user:%d", id))
		data := fmt.Sprintf(`{"id":%d,"name":"%s","age":%d}`, id, name, age)
		return b.Put(key, []byte(data))
	})
}

func (p *BoltDBProvider) Read(ctx context.Context, id int) (string, int, error) {
	var name string
	var age int
	err := p.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		key := []byte(fmt.Sprintf("user:%d", id))
		val := b.Get(key)
		if val == nil {
			return fmt.Errorf("key not found")
		}
		var data struct {
			Name string `json:"name"`
			Age  int    `json:"age"`
		}
		if err := json.Unmarshal(val, &data); err != nil {
			return err
		}
		name = data.Name
		age = data.Age
		return nil
	})
	return name, age, err
}

func (p *BoltDBProvider) Update(ctx context.Context, id int, age int) error {
	return p.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		key := []byte(fmt.Sprintf("user:%d", id))
		data := fmt.Sprintf(`{"id":%d,"name":"user_%d","age":%d}`, id, id, age)
		return b.Put(key, []byte(data))
	})
}

func (p *BoltDBProvider) Delete(ctx context.Context, id int) error {
	return p.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		key := []byte(fmt.Sprintf("user:%d", id))
		return b.Delete(key)
	})
}

func (p *BoltDBProvider) Search(ctx context.Context, minAge int) (int, error) {
	count := 0
	err := p.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		c := b.Cursor()
		prefix := []byte("user:")
		for k, v := c.Seek(prefix); k != nil && len(k) >= len(prefix) && string(k[:len(prefix)]) == string(prefix); k, v = c.Next() {
			var data struct {
				Age int `json:"age"`
			}
			if err := json.Unmarshal(v, &data); err == nil {
				if data.Age >= minAge {
					count++
				}
			}
		}
		return nil
	})
	return count, err
}

func (p *BoltDBProvider) BatchInsert(ctx context.Context, startID int, count int) error {
	return p.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		for i := 0; i < count; i++ {
			id := startID + i
			name := fmt.Sprintf("user_%d", id)
			key := []byte(fmt.Sprintf("user:%d", id))
			data := fmt.Sprintf(`{"id":%d,"name":"%s","age":%d}`, id, name, 20+(id%50))
			if err := b.Put(key, []byte(data)); err != nil {
				return err
			}
		}
		return nil
	})
}
