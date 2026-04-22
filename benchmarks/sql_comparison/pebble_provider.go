package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cockroachdb/pebble"
)

type PebbleProvider struct {
	db   *pebble.DB
	path string
}

func NewPebbleProvider(path string) *PebbleProvider {
	return &PebbleProvider{path: path}
}

func (p *PebbleProvider) Name() string {
	return "Pebble"
}

func (p *PebbleProvider) Setup(ctx context.Context) error {
	os.RemoveAll(p.path)
	db, err := pebble.Open(p.path, &pebble.Options{})
	if err != nil {
		return err
	}
	p.db = db
	return nil
}

func (p *PebbleProvider) Cleanup(ctx context.Context) error {
	if p.db != nil {
		p.db.Close()
	}
	return os.RemoveAll(p.path)
}

func (p *PebbleProvider) Insert(ctx context.Context, id int, name string, age int) error {
	key := []byte(fmt.Sprintf("user:%d", id))
	data := fmt.Sprintf(`{"id":%d,"name":"%s","age":%d}`, id, name, age)
	return p.db.Set(key, []byte(data), pebble.Sync)
}

func (p *PebbleProvider) Read(ctx context.Context, id int) (string, int, error) {
	key := []byte(fmt.Sprintf("user:%d", id))
	val, closer, err := p.db.Get(key)
	if err != nil {
		return "", 0, err
	}
	defer closer.Close()

	var data struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}
	if err := json.Unmarshal(val, &data); err != nil {
		return "", 0, err
	}
	return data.Name, data.Age, nil
}

func (p *PebbleProvider) Update(ctx context.Context, id int, age int) error {
	key := []byte(fmt.Sprintf("user:%d", id))
	data := fmt.Sprintf(`{"id":%d,"name":"user_%d","age":%d}`, id, id, age)
	return p.db.Set(key, []byte(data), pebble.Sync)
}

func (p *PebbleProvider) Delete(ctx context.Context, id int) error {
	key := []byte(fmt.Sprintf("user:%d", id))
	return p.db.Delete(key, pebble.Sync)
}

func (p *PebbleProvider) Search(ctx context.Context, minAge int) (int, error) {
	iter, err := p.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte("user:"),
		UpperBound: []byte("user;"), // ';' is one after ':'
	})
	if err != nil {
		return 0, err
	}
	defer iter.Close()

	count := 0
	for iter.First(); iter.Valid(); iter.Next() {
		var data struct {
			Age int `json:"age"`
		}
		if err := json.Unmarshal(iter.Value(), &data); err == nil {
			if data.Age >= minAge {
				count++
			}
		}
	}
	return count, nil
}

func (p *PebbleProvider) BatchInsert(ctx context.Context, startID int, count int) error {
	batch := p.db.NewBatch()
	for i := 0; i < count; i++ {
		id := startID + i
		name := fmt.Sprintf("user_%d", id)
		key := []byte(fmt.Sprintf("user:%d", id))
		data := fmt.Sprintf(`{"id":%d,"name":"%s","age":%d}`, id, name, 20+(id%50))
		if err := batch.Set(key, []byte(data), nil); err != nil {
			batch.Close()
			return err
		}
	}
	return batch.Commit(pebble.Sync)
}
