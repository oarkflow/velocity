package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/glycerine/yogadb"
)

type YogaDBProvider struct {
	db   *yogadb.FlexDB
	path string
}

func NewYogaDBProvider(path string) *YogaDBProvider {
	return &YogaDBProvider{path: path}
}

func (p *YogaDBProvider) Name() string {
	return "YogaDB"
}

func (p *YogaDBProvider) Setup(ctx context.Context) error {
	os.RemoveAll(p.path)
	db, err := yogadb.OpenFlexDB(p.path, nil)
	if err != nil {
		return err
	}
	p.db = db
	return nil
}

func (p *YogaDBProvider) Cleanup(ctx context.Context) error {
	if p.db != nil {
		p.db.Close()
	}
	return os.RemoveAll(p.path)
}

func (p *YogaDBProvider) Insert(ctx context.Context, id int, name string, age int) error {
	key := fmt.Sprintf("user:%d", id)
	data := fmt.Sprintf(`{"id":%d,"name":"%s","age":%d}`, id, name, age)
	return p.db.Put(key, []byte(data))
}

func (p *YogaDBProvider) Read(ctx context.Context, id int) (string, int, error) {
	key := fmt.Sprintf("user:%d", id)
	kvc, err := p.db.GetKV(key)
	if err != nil {
		return "", 0, err
	}
	if kvc == nil {
		return "", 0, fmt.Errorf("key not found")
	}
	defer kvc.Close()

	var data struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}
	if err := json.Unmarshal(kvc.Value, &data); err != nil {
		return "", 0, err
	}
	return data.Name, data.Age, nil
}

func (p *YogaDBProvider) Update(ctx context.Context, id int, age int) error {
	key := fmt.Sprintf("user:%d", id)
	data := fmt.Sprintf(`{"id":%d,"name":"user_%d","age":%d}`, id, id, age)
	return p.db.Put(key, []byte(data))
}

func (p *YogaDBProvider) Delete(ctx context.Context, id int) error {
	key := fmt.Sprintf("user:%d", id)
	return p.db.Delete(key)
}

func (p *YogaDBProvider) Search(ctx context.Context, minAge int) (int, error) {
	count := 0
	err := p.db.View(func(ro *yogadb.ReadOnlyTx) error {
		ro.Ascend("user:", func(key string, value []byte) bool {
			if !strings.HasPrefix(key, "user:") {
				return false
			}
			var data struct {
				Age int `json:"age"`
			}
			if err := json.Unmarshal(value, &data); err == nil {
				if data.Age >= minAge {
					count++
				}
			}
			return true
		})
		return nil
	})
	return count, err
}

func (p *YogaDBProvider) BatchInsert(ctx context.Context, startID int, count int) error {
	batch := p.db.NewBatch()
	for i := 0; i < count; i++ {
		id := startID + i
		name := fmt.Sprintf("user_%d", id)
		key := fmt.Sprintf("user:%d", id)
		data := fmt.Sprintf(`{"id":%d,"name":"%s","age":%d}`, id, name, 20+(id%50))
		if err := batch.Set(key, []byte(data)); err != nil {
			batch.Close()
			return err
		}
	}
	_, err := batch.Commit(true)
	return err
}
