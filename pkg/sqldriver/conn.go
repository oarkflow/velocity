package sqldriver

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/oarkflow/sqlparser"
	"github.com/oarkflow/sqlparser/lexer"
	"github.com/oarkflow/velocity"
)

// Conn is a connection to a Velocity database using database/sql/driver.
// It is not used concurrently by multiple goroutines.
type Conn struct {
	db               *velocity.DB
	path             string
	tx               *velocity.BatchWriter
	txConstraintKeys map[string]struct{}

	stmtMu    sync.RWMutex
	stmtCache map[string]*parsedStatement
	bulkPlans map[string]*bulkInsertPlan
}

type parsedStatement struct {
	stmt   sqlparser.Statement
	parser *sqlparser.Parser
}

type bulkInsertPlan struct {
	table       string
	columns     []string
	encodedCols [][]byte
	fieldPairs  []velocity.IndexFieldValue
	rowScratch  []any
	idIndex     int
}

// Prepare returns a prepared statement, bound to this connection.
func (c *Conn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}

// PrepareContext returns a prepared statement, bound to this connection.
func (c *Conn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	parsed, err := c.getOrParseStatement(query)
	if err != nil {
		return nil, err
	}

	paramOrder := buildParamOrder(query)
	return &StmtV2{
		conn:       c,
		query:      query,
		stmt:       parsed.stmt,
		parser:     parsed.parser,
		paramOrder: paramOrder,
		fastInsert: newSimpleInsertPlan(parsed.stmt, paramOrder),
	}, nil
}

func (c *Conn) getOrParseStatement(query string) (*parsedStatement, error) {
	c.stmtMu.RLock()
	if c.stmtCache != nil {
		if stmt, ok := c.stmtCache[query]; ok {
			c.stmtMu.RUnlock()
			return stmt, nil
		}
	}
	c.stmtMu.RUnlock()

	parser := sqlparser.NewString(query)
	stmt, err := parser.Next()
	if err != nil {
		return nil, err
	}
	parsed := &parsedStatement{stmt: stmt, parser: parser}

	c.stmtMu.Lock()
	if c.stmtCache == nil {
		c.stmtCache = make(map[string]*parsedStatement)
	}
	c.stmtCache[query] = parsed
	c.stmtMu.Unlock()
	return parsed, nil
}

func buildParamOrder(query string) map[int32]int {
	tokens := sqlparser.Tokenize([]byte(query), nil)
	order := make(map[int32]int)
	next := 1
	for _, tok := range tokens {
		if tok.Type != lexer.QUESTION {
			continue
		}
		order[tok.Pos] = next
		next++
	}
	if len(order) == 0 {
		return nil
	}
	return order
}

// Close invalidates and potentially stops any current
// prepared statements and transactions, marking this
// connection as no longer in use.
func (c *Conn) Close() error {
	var err error
	if c.db != nil && c.path != "" {
		enginesMu.Lock()
		state := engines[c.path]
		if state != nil {
			state.refs--
			if state.refs <= 0 {
				delete(engines, c.path)
				enginesMu.Unlock()
				err = state.db.Close()
				enginesMu.Lock()
			}
		}
		enginesMu.Unlock()
	}
	c.db = nil
	c.path = ""
	c.stmtMu.Lock()
	c.stmtCache = nil
	c.stmtMu.Unlock()
	return err
}

// Begin starts and returns a new transaction.
func (c *Conn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

// BeginTx starts and returns a new transaction.
// Velocity uses a BatchWriter to queue up changes transactionally before commit.
func (c *Conn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if c.tx != nil {
		return nil, driver.ErrBadConn
	}
	// Keep ordinary SQL transactions in one storage batch for common bulk loads.
	c.tx = c.db.NewBatchWriter(65536)
	c.txConstraintKeys = make(map[string]struct{})
	return &Tx{conn: c}, nil
}

// Tx represents an active Velocity batch transaction.
type Tx struct {
	conn *Conn
}

func (tx *Tx) Commit() error {
	err := tx.conn.tx.Flush()
	tx.conn.tx = nil
	tx.conn.txConstraintKeys = nil
	return err
}

func (tx *Tx) Rollback() error {
	tx.conn.tx.Cancel()
	tx.conn.tx = nil
	tx.conn.txConstraintKeys = nil
	return nil
}

// Put writes data contextually within a transaction if one is active.
func (c *Conn) Put(key []byte, value []byte) error {
	if c.tx != nil {
		return c.tx.PutUnsafe(key, value)
	}
	return c.db.Put(key, value)
}

func (c *Conn) PutWithIndexFieldPairs(key []byte, value []byte, fields []velocity.IndexFieldValue) error {
	bw := c.tx
	if bw == nil {
		return c.db.PutWithIndexFieldPairs(key, value, fields)
	}
	return bw.PutWithIndexFieldPairsUnsafe(key, value, fields)
}

// Get reads through the transaction write set before falling back to committed
// storage, giving SQL transactions read-your-writes behavior for key lookups.
func (c *Conn) Get(key []byte) ([]byte, error) {
	if c.tx != nil {
		if value, found, deleted := c.tx.PendingGet(key); found {
			if deleted {
				return nil, fmt.Errorf("key not found")
			}
			return value, nil
		}
	}
	return c.db.Get(key)
}

func (c *Conn) PendingTableEntries(table string) []velocity.Entry {
	if c.tx == nil || table == "" {
		return nil
	}
	return c.tx.PendingEntriesWithPrefix([]byte(table + ":"))
}

// Delete removes data contextually within a transaction if one is active.
func (c *Conn) Delete(key []byte) error {
	if c.tx != nil {
		return c.tx.DeleteUnsafe(key)
	}
	return c.db.Delete(key)
}

// BulkInsert inserts many rows through the SQL driver's storage mapping without
// paying database/sql's per-row statement execution overhead.
func (c *Conn) BulkInsert(table string, columns []string, rows [][]any) (int64, error) {
	return c.BulkInsertFunc(table, columns, len(rows), func(i int, dst []any) {
		copy(dst, rows[i])
	})
}

// BulkInsertFunc is the allocation-conscious form of BulkInsert. fill receives
// a reusable row buffer sized to len(columns).
func (c *Conn) BulkInsertFunc(table string, columns []string, count int, fill func(i int, dst []any)) (int64, error) {
	if table == "" || len(columns) == 0 || count <= 0 {
		return 0, nil
	}
	plan := c.bulkInsertPlan(table, columns)

	inserted := int64(0)
	row := make([]any, len(columns))
	batchConstraintKeys := make(map[string]struct{})
	write := func(put func([]byte, []byte, []velocity.IndexFieldValue) error) error {
		for rowIdx := 0; rowIdx < count; rowIdx++ {
			fill(rowIdx, row)
			key, payload, fields := plan.encodeRow(row, rowIdx)
			if err := c.checkRawInsertConstraintsWithSeen(table, columns, row, key, batchConstraintKeys); err != nil {
				return err
			}
			if err := put(key, payload, fields); err != nil {
				return err
			}
			inserted++
		}
		return nil
	}

	if c.tx != nil {
		err := write(c.tx.PutWithIndexFieldPairsUnsafe)
		return inserted, err
	}
	bw := c.db.NewBatchWriter(count)
	if err := write(bw.PutWithIndexFieldPairsUnsafe); err != nil {
		return inserted, err
	}
	if err := bw.Flush(); err != nil {
		return inserted, err
	}
	return inserted, nil
}

func (c *Conn) InsertRow(table string, columns []string, values []any) error {
	if table == "" || len(columns) == 0 {
		return nil
	}
	plan := c.bulkInsertPlan(table, columns)
	key, payload, fields := plan.encodeRow(values, 0)
	if err := c.checkRawInsertConstraints(table, columns, values, key); err != nil {
		return err
	}
	if c.tx != nil {
		return c.tx.PutWithIndexFieldPairsUnsafe(key, payload, fields)
	}
	return c.db.PutWithIndexFieldPairs(key, payload, fields)
}

func (c *Conn) InsertRowFunc(table string, columns []string, fill func(dst []any)) error {
	if table == "" || len(columns) == 0 {
		return nil
	}
	plan := c.bulkInsertPlan(table, columns)
	fill(plan.rowScratch)
	key, payload, fields := plan.encodeRow(plan.rowScratch, 0)
	if err := c.checkRawInsertConstraints(table, columns, plan.rowScratch, key); err != nil {
		return err
	}
	if c.tx != nil {
		return c.tx.PutWithIndexFieldPairsUnsafe(key, payload, fields)
	}
	return c.db.PutWithIndexFieldPairs(key, payload, fields)
}

func (c *Conn) bulkInsertPlan(table string, columns []string) *bulkInsertPlan {
	key := table + "\x00" + strings.Join(columns, "\x00")
	if c.bulkPlans != nil {
		if plan := c.bulkPlans[key]; plan != nil {
			return plan
		}
	} else {
		c.bulkPlans = make(map[string]*bulkInsertPlan)
	}
	plan := &bulkInsertPlan{
		table:       table,
		columns:     append([]string(nil), columns...),
		encodedCols: make([][]byte, len(columns)),
		fieldPairs:  make([]velocity.IndexFieldValue, len(columns)),
		rowScratch:  make([]any, len(columns)),
		idIndex:     -1,
	}
	for i, col := range columns {
		plan.encodedCols[i] = strconv.AppendQuote(nil, col)
		plan.fieldPairs[i].Name = col
		if col == "id" {
			plan.idIndex = i
		}
	}
	c.bulkPlans[key] = plan
	return plan
}

func (p *bulkInsertPlan) encodeRow(row []any, rowIdx int) ([]byte, []byte, []velocity.IndexFieldValue) {
	payload := make([]byte, 0, 96)
	payload = append(payload, '{')
	var keyValue any
	for colIdx, value := range row {
		if colIdx > 0 {
			payload = append(payload, ',')
		}
		payload = append(payload, p.encodedCols[colIdx]...)
		payload = append(payload, ':')
		payload = appendJSONValue(payload, value)
		p.fieldPairs[colIdx].Value = value
		if colIdx == p.idIndex {
			keyValue = value
		}
	}
	payload = append(payload, '}')

	var key []byte
	if keyValue != nil {
		key = appendTableKey(nil, p.table, keyValue)
	} else {
		key = strconv.AppendInt(append(append(key, p.table...), ':'), int64(rowIdx), 10)
	}
	return key, payload, p.fieldPairs
}

func (c *Conn) checkRawInsertConstraints(table string, columns []string, values []any, key []byte) error {
	return c.checkRawInsertConstraintsWithSeen(table, columns, values, key, nil)
}

func (c *Conn) checkRawInsertConstraintsWithSeen(table string, columns []string, values []any, key []byte, seen map[string]struct{}) error {
	meta, found, err := c.loadSchemaMeta(table)
	if err != nil || !found {
		return err
	}
	hasSeen := func(key string) bool {
		if seen != nil {
			if _, exists := seen[key]; exists {
				return true
			}
		}
		if c.txConstraintKeys != nil {
			if _, exists := c.txConstraintKeys[key]; exists {
				return true
			}
		}
		return false
	}
	markSeen := func(key string) {
		if seen != nil {
			seen[key] = struct{}{}
		}
		if c.tx != nil {
			c.txConstraintKeys[key] = struct{}{}
		}
	}
	row := make(map[string]any, len(columns))
	for i, col := range columns {
		if i < len(values) {
			row[col] = values[i]
		}
	}
	for _, col := range meta.NotNull {
		if row[col] == nil {
			return fmt.Errorf("velocity driver: column %s.%s cannot be NULL", table, col)
		}
	}
	if meta.PrimaryKey != "" {
		if value, ok := row[meta.PrimaryKey]; ok {
			if value == nil {
				return fmt.Errorf("velocity driver: primary key %s.%s cannot be NULL", table, meta.PrimaryKey)
			}
			txKey := "pk\x00" + string(key)
			if hasSeen(txKey) {
				return fmt.Errorf("velocity driver: duplicate primary key on %s.%s", table, meta.PrimaryKey)
			}
			if _, err := c.db.Get(key); err == nil {
				return fmt.Errorf("velocity driver: duplicate primary key on %s.%s", table, meta.PrimaryKey)
			}
			markSeen(txKey)
		}
	}
	for _, col := range meta.Unique {
		value, ok := row[col]
		if !ok {
			continue
		}
		if value == nil {
			continue
		}
		txKey := "unique\x00" + table + "\x00" + col + "\x00" + fmt.Sprintf("%v", value)
		if hasSeen(txKey) {
			return fmt.Errorf("velocity driver: duplicate unique value on %s.%s", table, col)
		}
		count, err := c.db.SearchCount(velocity.SearchQuery{
			Prefix: table,
			Filters: []velocity.SearchFilter{{
				Field:    col,
				Op:       "==",
				Value:    value,
				HashOnly: true,
			}},
			Limit: 1,
		})
		if err != nil {
			return err
		}
		if count > 0 {
			return fmt.Errorf("velocity driver: duplicate unique value on %s.%s", table, col)
		}
		markSeen(txKey)
	}
	return nil
}

func (c *Conn) loadSchemaMeta(table string) (tableSchemaMeta, bool, error) {
	raw, err := c.db.Get(schemaStorageKey(table))
	if err != nil {
		return tableSchemaMeta{}, false, nil
	}
	var meta tableSchemaMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return tableSchemaMeta{}, false, err
	}
	return meta, true, nil
}

func (c *Conn) ReadByID(table string, id any, columns []string) ([]any, error) {
	if table == "" || len(columns) == 0 {
		return nil, nil
	}
	raw, err := c.Get(appendTableKey(nil, table, id))
	if err != nil {
		return nil, err
	}
	values := make([]any, len(columns))
	for i, col := range columns {
		value, ok := fastJSONFieldValue(raw, col)
		if !ok {
			values[i] = nil
			continue
		}
		values[i] = value
	}
	return values, nil
}

// ExecContext executes a query that doesn't return rows, such as an INSERT or UPDATE.
func (c *Conn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	stmt, err := c.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	return stmt.(driver.StmtExecContext).ExecContext(ctx, args)
}

// QueryContext executes a query that may return rows, such as a SELECT.
func (c *Conn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	stmt, err := c.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	// We don't defer stmt.Close() here because standard sql package closes it for us after row iteration.
	return stmt.(driver.StmtQueryContext).QueryContext(ctx, args)
}
