package sqldriver

import (
	"context"
	"encoding/json"

	"github.com/oarkflow/velocity"
)

// Row represents a single mapped row traveling through the execution pipeline.
type Row map[string]interface{}

// Iterator defines the physical relational algebra iterators.
type Iterator interface {
	Next(ctx context.Context) (Row, error) // Returns (nil, nil) on EOF
	Close() error
}

// TableScanIterator handles reading from a single Velocity Prefix collection.
// It wraps a pre-executed db.Search query or directly streams if Velocity adds a cursor later.
type TableScanIterator struct {
	db      *velocity.DB
	prefix  string
	results []velocity.SearchResult
	cursor  int
	schema  *velocity.SearchSchema // Extracted schema logic
}

func NewTableScanIterator(db *velocity.DB, prefix string, query velocity.SearchQuery) (*TableScanIterator, error) {
	// Execute the search upfront since Velocity's API currently returns an array
	// rather than a streaming cursor. We iterate locally over the slice.
	results, err := db.Search(query)
	if err != nil {
		// Attempt literal scan fallback if search isn't enabled
		return nil, err
	}

	return &TableScanIterator{
		db:      db,
		prefix:  prefix,
		results: results,
		cursor:  0,
	}, nil
}

func (it *TableScanIterator) Next(ctx context.Context) (Row, error) {
	if it.cursor >= len(it.results) {
		return nil, nil // EOF
	}

	res := it.results[it.cursor]
	it.cursor++

	var data map[string]interface{}
	err := json.Unmarshal(res.Value, &data)
	if err != nil {
		data = map[string]interface{}{
			"_key":   string(res.Key),
			"_value": string(res.Value),
		}
	} else {
		data["_key"] = string(res.Key)
	}

	// Optional: We can prefix column names, e.g. "users.name" if requested
	// for proper JOIN disambiguation later.
	aliasedData := make(Row)
	for k, v := range data {
		aliasedData[it.prefix+"."+k] = v
		aliasedData[k] = v // allow flat access too
	}

	return aliasedData, nil
}

func (it *TableScanIterator) Close() error {
	it.cursor = len(it.results)
	return nil
}

// NestedLoopJoinIterator performs a Cartesian product evaluating a condition string
type NestedLoopJoinIterator struct {
	left       Iterator
	right      Iterator
	leftRow    Row
	rightCache []Row // Because velocity doesn't stream, we buffer right side
	rCursor    int
	joinReady  bool
	// ConditionFunc evaluates the JOIN expression logic.
	ConditionFunc func(left, right Row) bool
}

func NewNestedLoopJoinIterator(ctx context.Context, left, right Iterator, condition func(Row, Row) bool) (*NestedLoopJoinIterator, error) {
	it := &NestedLoopJoinIterator{
		left:          left,
		right:         right,
		ConditionFunc: condition,
	}

	// Buffer right side fully since we must loop over it multiple times
	for {
		r, err := right.Next(ctx)
		if err != nil {
			return nil, err
		}
		if r == nil {
			break
		}
		it.rightCache = append(it.rightCache, r)
	}

	// Pre-load first left row
	lr, err := left.Next(ctx)
	if err != nil {
		return nil, err
	}
	it.leftRow = lr
	if it.leftRow != nil {
		it.joinReady = true
	}

	return it, nil
}

func (it *NestedLoopJoinIterator) Next(ctx context.Context) (Row, error) {
	for it.joinReady {
		// exhausted right cache for current left row?
		if it.rCursor >= len(it.rightCache) {
			lr, err := it.left.Next(ctx)
			if err != nil {
				return nil, err
			}
			it.leftRow = lr
			if it.leftRow == nil {
				it.joinReady = false
				return nil, nil // Absolute EOF
			}
			it.rCursor = 0 // reset right cursor
		}

		// Pull right row
		rightRow := it.rightCache[it.rCursor]
		it.rCursor++

		// Evaluate join condition
		if it.ConditionFunc == nil || it.ConditionFunc(it.leftRow, rightRow) {
			// Merge the rows (Cartesian product result)
			merged := make(Row)
			for k, v := range it.leftRow {
				merged[k] = v
			}
			for k, v := range rightRow {
				merged[k] = v // Overwrites ambiguous unqualified keys, aliases remain
			}
			return merged, nil
		}
	}
	return nil, nil
}

func (it *NestedLoopJoinIterator) Close() error {
	it.left.Close()
	it.right.Close()
	return nil
}

// FilterIterator applies an arbitrary function across rows
type FilterIterator struct {
	next Iterator
	cond func(Row) bool
}

func (it *FilterIterator) Next(ctx context.Context) (Row, error) {
	for {
		r, err := it.next.Next(ctx)
		if err != nil || r == nil {
			return nil, err
		}
		if it.cond == nil || it.cond(r) {
			return r, nil
		}
	}
}

func (it *FilterIterator) Close() error {
	return it.next.Close()
}

// MemoryIterator wraps pre-computed rows, used heavily by Subqueries and CTE components
type MemoryIterator struct {
	alias  string
	rows   []velocity.SearchResult
	cursor int
}

func (it *MemoryIterator) Next(ctx context.Context) (Row, error) {
	if it.cursor >= len(it.rows) {
		return nil, nil // EOF
	}

	res := it.rows[it.cursor]
	it.cursor++

	var data map[string]interface{}
	err := json.Unmarshal(res.Value, &data)
	if err != nil {
		data = make(map[string]interface{})
	}
	data["_key"] = string(res.Key)

	aliasedData := make(Row)
	for k, v := range data {
		if it.alias != "" {
			aliasedData[it.alias+"."+k] = v
		}
		aliasedData[k] = v
	}

	return aliasedData, nil
}

func (it *MemoryIterator) Close() error {
	it.cursor = len(it.rows)
	return nil
}
