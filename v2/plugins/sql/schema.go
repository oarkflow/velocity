package sql

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/oarkflow/velocity/v2/api"
)

// Column describes one table column, as declared by CREATE TABLE.
type Column struct {
	Name          string
	Type          string
	PrimaryKey    bool
	NotNull       bool
	AutoIncrement bool
}

// Schema is a table's persisted definition.
type Schema struct {
	Table   string
	Columns []Column
	// PKOrder lists the primary-key column names in declared order. Its
	// length is 1 for a normal single-column PK and >1 for a composite
	// key declared via a table-level PRIMARY KEY (col1, col2, ...)
	// constraint — see execCreateTable and encodePK.
	PKOrder []string
}

// PrimaryKeyColumn returns the schema's primary-key column, but only if
// it has exactly one — composite keys report ok=false here so callers
// (e.g. the point-lookup fast path in selectRowsOne) correctly fall back
// to a full scan instead of assuming a single PK column. Use
// PrimaryKeyColumns for the general (1 or more) case.
func (s *Schema) PrimaryKeyColumn() (Column, bool) {
	if len(s.PKOrder) != 1 {
		return Column{}, false
	}
	for _, c := range s.Columns {
		if c.Name == s.PKOrder[0] {
			return c, true
		}
	}
	return Column{}, false
}

// PrimaryKeyColumns returns every primary-key column, in declared order
// (length 1 for a normal PK, >1 for a composite one).
func (s *Schema) PrimaryKeyColumns() []Column {
	out := make([]Column, 0, len(s.PKOrder))
	for _, name := range s.PKOrder {
		for _, c := range s.Columns {
			if c.Name == name {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

func (s *Schema) hasColumn(name string) bool {
	for _, c := range s.Columns {
		if c.Name == name {
			return true
		}
	}
	return false
}

func schemaKey(table string) string  { return "sql/" + table + "/schema" }
func rowKey(table, pk string) string { return "sql/" + table + "/row/" + pk }
func rowPrefix(table string) string  { return "sql/" + table + "/row/" }
func seqKey(table string) string     { return "sql/" + table + "/seq" }

func loadSchema(ctx context.Context, kv api.KVService, table string) (*Schema, error) {
	b, ok, err := kv.Get(ctx, schemaKey(table))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("sql: table %q does not exist", table)
	}
	var s Schema
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("sql: corrupt schema for table %q: %w", table, err)
	}
	return &s, nil
}

func tableExists(ctx context.Context, kv api.KVService, table string) (bool, error) {
	return kv.Exists(ctx, schemaKey(table))
}

func saveSchema(ctx context.Context, kv api.KVService, s *Schema) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return kv.Put(ctx, schemaKey(s.Table), b)
}
