package sqldriver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/oarkflow/sqlparser/ast"
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
	db        *velocity.DB
	conn      *Conn
	prefix    string
	tableName string
	results   []velocity.SearchResult
	cursor    int
	schema    *velocity.SearchSchema // Extracted schema logic
}

func NewTableScanIterator(db *velocity.DB, prefix string, query velocity.SearchQuery) (*TableScanIterator, error) {
	return newTableScanIterator(db, nil, prefix, query)
}

func NewConnTableScanIterator(conn *Conn, prefix string, query velocity.SearchQuery) (*TableScanIterator, error) {
	if conn == nil {
		return nil, fmt.Errorf("velocity driver: nil connection")
	}
	return newTableScanIterator(conn.db, conn, prefix, query)
}

func newTableScanIterator(db *velocity.DB, conn *Conn, prefix string, query velocity.SearchQuery) (*TableScanIterator, error) {
	// Execute the search upfront since Velocity's API currently returns an array
	// rather than a streaming cursor. We iterate locally over the slice.
	results, err := db.Search(query)
	if err != nil {
		// Attempt literal scan fallback if search isn't enabled
		return nil, err
	}

	if conn != nil && conn.tx != nil {
		results = overlayPendingTableResults(results, conn.PendingTableEntries(query.Prefix))
	}

	return &TableScanIterator{
		db:        db,
		conn:      conn,
		prefix:    prefix,
		tableName: query.Prefix,
		results:   results,
		cursor:    0,
	}, nil
}

func overlayPendingTableResults(committed []velocity.SearchResult, pending []velocity.Entry) []velocity.SearchResult {
	if len(pending) == 0 {
		return committed
	}
	shadowed := make(map[string]velocity.Entry, len(pending))
	for _, entry := range pending {
		shadowed[string(entry.Key)] = entry
	}
	results := make([]velocity.SearchResult, 0, len(committed)+len(pending))
	for _, row := range committed {
		if entry, ok := shadowed[string(row.Key)]; ok {
			if !entry.Deleted {
				results = append(results, velocity.SearchResult{Key: entry.Key, Value: entry.Value})
			}
			delete(shadowed, string(row.Key))
			continue
		}
		results = append(results, row)
	}
	for _, entry := range shadowed {
		if entry.Deleted {
			continue
		}
		results = append(results, velocity.SearchResult{Key: entry.Key, Value: entry.Value})
	}
	return results
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
	left               Iterator
	right              Iterator
	leftRow            Row
	rightCache         []Row // Because velocity doesn't stream, we buffer right side
	rightMatched       []bool
	rCursor            int
	joinReady          bool
	currentLeftMatched bool
	emitRightOnly      bool
	rightOnlyCursor    int
	// ConditionFunc evaluates the JOIN expression logic.
	ConditionFunc func(left, right Row) bool
	kind          ast.JoinKind
}

func NewNestedLoopJoinIterator(ctx context.Context, left, right Iterator, condition func(Row, Row) bool) (*NestedLoopJoinIterator, error) {
	return NewJoinIterator(ctx, left, right, ast.InnerJoin, condition)
}

func NewJoinIterator(ctx context.Context, left, right Iterator, kind ast.JoinKind, condition func(Row, Row) bool) (*NestedLoopJoinIterator, error) {
	it := &NestedLoopJoinIterator{
		left:          left,
		right:         right,
		ConditionFunc: condition,
		kind:          kind,
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
	it.rightMatched = make([]bool, len(it.rightCache))

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
			if !it.currentLeftMatched && (it.kind == ast.LeftJoin || it.kind == ast.FullJoin) {
				it.currentLeftMatched = true
				return copyRow(it.leftRow), nil
			}
			lr, err := it.left.Next(ctx)
			if err != nil {
				return nil, err
			}
			it.leftRow = lr
			if it.leftRow == nil {
				it.joinReady = false
				if it.kind == ast.RightJoin || it.kind == ast.FullJoin {
					it.emitRightOnly = true
					break
				}
				return nil, nil
			}
			it.rCursor = 0
			it.currentLeftMatched = false
		}

		// Pull right row
		if len(it.rightCache) == 0 {
			it.rCursor = len(it.rightCache)
			continue
		}
		rightRow := it.rightCache[it.rCursor]
		rightIdx := it.rCursor
		it.rCursor++

		// Evaluate join condition
		if it.ConditionFunc == nil || it.ConditionFunc(it.leftRow, rightRow) {
			it.currentLeftMatched = true
			if rightIdx >= 0 && rightIdx < len(it.rightMatched) {
				it.rightMatched[rightIdx] = true
			}
			// Merge the rows (Cartesian product result)
			return mergeRows(it.leftRow, rightRow), nil
		}
	}
	for it.emitRightOnly {
		if it.rightOnlyCursor >= len(it.rightCache) {
			it.emitRightOnly = false
			return nil, nil
		}
		idx := it.rightOnlyCursor
		it.rightOnlyCursor++
		if idx < len(it.rightMatched) && it.rightMatched[idx] {
			continue
		}
		return copyRow(it.rightCache[idx]), nil
	}
	return nil, nil
}

func copyRow(row Row) Row {
	out := make(Row, len(row))
	for k, v := range row {
		out[k] = v
	}
	return out
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
