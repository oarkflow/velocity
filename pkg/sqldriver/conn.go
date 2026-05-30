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
	db                      *velocity.DB
	path                    string
	rowLocks                *rowLockManager
	queryCache              *SQLQueryCache
	queryCacheCfg           queryCacheConfig
	configuredSearchSchemas map[string]*velocity.SearchSchema
	tx                      *velocity.BatchWriter
	txConstraintKeys        map[string]struct{}
	txRowUnlocks            []func()
	txLockedRows            map[string]struct{}
	txDeferredNewRows       map[string]struct{}
	txQueryCache            *SQLQueryCache
	txHasWrites             bool
	txChangedRows           map[string]struct{}
	txChangedTables         map[string]struct{}
	txSchemaChanged         bool
	txClearQueryCache       bool
	txIndexTables           map[string]struct{}
	schemaVersion           uint64

	stmtMu    sync.RWMutex
	stmtCache map[string]*parsedStatement
	bulkPlans map[string]*bulkInsertPlan
	schemaMu  sync.RWMutex
	schemas   map[string]cachedTableSchema
}

type cachedTableSchema struct {
	meta  tableSchemaMeta
	found bool
}

type parsedStatement struct {
	stmt          sqlparser.Statement
	parser        *sqlparser.Parser
	normalizedSQL string
}

type bulkInsertPlan struct {
	table       string
	columns     []string
	encodedCols [][]byte
	fieldPairs  []velocity.IndexFieldValue
	rowScratch  []any
	idIndex     int
}

type rawInsertConstraintPlan struct {
	table                 string
	meta                  tableSchemaMeta
	found                 bool
	columnIndexes         map[string]int
	primaryKeyIndex       int
	fastPrimaryKeyOnly    bool
	skipPrimaryKeyStorage bool
}

// Prepare returns a prepared statement, bound to this connection.
func (c *Conn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}

func (c *Conn) CheckNamedValue(nv *driver.NamedValue) error {
	return checkCommonNamedValue(nv.Value)
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
		cacheSQL:   parsed.normalizedSQL,
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
	parsed := &parsedStatement{stmt: stmt, parser: parser, normalizedSQL: normalizeSQLForCache(query)}

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
	if c.tx != nil {
		c.tx.Cancel()
		c.tx = nil
		c.txConstraintKeys = nil
		c.clearTxQueryState()
		c.releaseTxRowLocks()
	}
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
	c.rowLocks = nil
	c.queryCache = nil
	c.stmtMu.Lock()
	c.stmtCache = nil
	c.stmtMu.Unlock()
	c.clearSchemaCache()
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
	c.tx = c.db.NewBatchWriter(65536).DisableAutoFlush().Reserve(1024, 4096)
	c.txConstraintKeys = make(map[string]struct{})
	c.txLockedRows = make(map[string]struct{})
	c.txDeferredNewRows = make(map[string]struct{}, 1024)
	c.txQueryCache = newTxSQLQueryCache(c.queryCacheCfg)
	return &Tx{conn: c}, nil
}

// Tx represents an active Velocity batch transaction.
type Tx struct {
	conn *Conn
}

func (tx *Tx) Commit() error {
	conn := tx.conn
	if conn == nil || conn.tx == nil {
		return driver.ErrBadConn
	}
	defer func() {
		conn.tx = nil
		conn.txConstraintKeys = nil
		conn.txDeferredNewRows = nil
		conn.clearTxQueryState()
		conn.releaseTxRowLocks()
	}()

	if err := conn.lockAndValidateDeferredNewRows(context.Background()); err != nil {
		return err
	}
	deferIndexes := conn.shouldDeferTxIndexMaintenance()
	if deferIndexes {
		conn.tx.DisableIndexMaintenance()
	}
	err := conn.tx.Flush()
	if err == nil && deferIndexes {
		err = conn.rebuildDeferredTxIndexes()
	}
	if err == nil {
		conn.flushTxInvalidations()
	}
	return err
}

func (tx *Tx) Rollback() error {
	if tx.conn == nil || tx.conn.tx == nil {
		return driver.ErrBadConn
	}
	tx.conn.tx.Cancel()
	tx.conn.tx = nil
	tx.conn.txConstraintKeys = nil
	tx.conn.txDeferredNewRows = nil
	tx.conn.clearTxQueryState()
	tx.conn.releaseTxRowLocks()
	return nil
}

func (c *Conn) markRowsChanged(keys [][]byte) {
	if c.tx != nil {
		c.rememberTxIndexTables(keys)
	}
	if c.tx != nil && (c.queryCache == nil || !c.queryCache.enabled) {
		c.txHasWrites = true
		if c.txQueryCache != nil && c.txQueryCache.enabled {
			c.txQueryCache.Clear()
		}
		return
	}
	stringKeys := make([]string, 0, len(keys))
	for _, key := range keys {
		keyStr := string(key)
		if keyStr == "" {
			continue
		}
		stringKeys = append(stringKeys, keyStr)
		if c.tx != nil {
			c.txHasWrites = true
			if c.queryCache != nil && c.queryCache.enabled {
				if !c.txClearQueryCache {
					if c.txChangedRows == nil {
						c.txChangedRows = make(map[string]struct{})
					}
					c.txChangedRows[keyStr] = struct{}{}
					if len(c.txChangedRows) > 512 {
						c.txClearQueryCache = true
						c.txChangedRows = nil
					}
				}
			}
			if table := tableNameFromStorageKey(keyStr); table != "" && c.queryCache != nil && c.queryCache.enabled {
				if c.txChangedTables == nil {
					c.txChangedTables = make(map[string]struct{})
				}
				c.txChangedTables[table] = struct{}{}
			}
		}
	}
	if c.tx != nil {
		if c.txQueryCache != nil && c.txQueryCache.enabled {
			c.txQueryCache.Clear()
		}
		return
	}
	if c.queryCache != nil && c.queryCache.enabled {
		if len(stringKeys) > 32 {
			c.queryCache.Clear()
			return
		}
		c.queryCache.BumpRows(stringKeys)
	}
}

func (c *Conn) markTablesChanged(tables []string) {
	if c.tx != nil {
		c.txHasWrites = true
		if c.queryCache != nil && c.queryCache.enabled {
			if c.txChangedTables == nil {
				c.txChangedTables = make(map[string]struct{})
			}
			for _, table := range tables {
				if table != "" {
					c.txChangedTables[table] = struct{}{}
				}
			}
		}
		if c.txQueryCache != nil && c.txQueryCache.enabled {
			c.txQueryCache.Clear()
		}
		return
	}
	if c.queryCache != nil {
		c.queryCache.BumpTables(tables)
	}
}

func (c *Conn) markSchemaChanged() {
	c.clearSchemaCache()
	c.schemaVersion++
	if c.tx != nil {
		c.txHasWrites = true
		if c.queryCache != nil && c.queryCache.enabled {
			c.txSchemaChanged = true
		}
		if c.txQueryCache != nil && c.txQueryCache.enabled {
			c.txQueryCache.Clear()
		}
		return
	}
	if c.queryCache != nil {
		c.queryCache.BumpSchema()
	}
}

func (c *Conn) flushTxInvalidations() {
	if c.queryCache == nil || !c.queryCache.enabled {
		return
	}
	if c.txClearQueryCache {
		c.queryCache.Clear()
		return
	}
	if c.txSchemaChanged {
		c.queryCache.BumpSchema()
	}
	rows := make([]string, 0, len(c.txChangedRows))
	for key := range c.txChangedRows {
		rows = append(rows, key)
	}
	c.queryCache.BumpRows(rows)
	tables := make([]string, 0, len(c.txChangedTables))
	for table := range c.txChangedTables {
		tables = append(tables, table)
	}
	c.queryCache.BumpTables(tables)
}

func (c *Conn) clearTxQueryState() {
	c.txQueryCache = nil
	c.txHasWrites = false
	c.txChangedRows = nil
	c.txChangedTables = nil
	c.txSchemaChanged = false
	c.txClearQueryCache = false
	c.txIndexTables = nil
}

func (c *Conn) markTableRowChanged(table string, key []byte) {
	if c.tx != nil && table != "" {
		c.rememberTxIndexTable(table)
		if c.queryCache == nil || !c.queryCache.enabled {
			c.txHasWrites = true
			if c.txQueryCache != nil && c.txQueryCache.enabled {
				c.txQueryCache.Clear()
			}
			return
		}
	}
	c.markRowsChanged([][]byte{key})
}

func (c *Conn) rememberTxIndexTable(table string) {
	if table == "" {
		return
	}
	if c.txIndexTables == nil {
		c.txIndexTables = make(map[string]struct{})
	}
	c.txIndexTables[table] = struct{}{}
}

func (c *Conn) rememberTxIndexTables(keys [][]byte) {
	for _, key := range keys {
		table := tableNameFromStorageKey(string(key))
		if table == "" {
			continue
		}
		c.rememberTxIndexTable(table)
	}
}

func (c *Conn) shouldDeferTxIndexMaintenance() bool {
	return c.tx != nil && c.tx.Len() >= 10_000 && len(c.txIndexTables) > 0
}

func (c *Conn) rebuildDeferredTxIndexes() error {
	for table := range c.txIndexTables {
		err := c.db.RebuildIndex(table, nil, &velocity.RebuildOptions{
			BatchSize:    50_000,
			NoWAL:        true,
			InMemoryOnly: true,
		})
		if err != nil && !strings.Contains(err.Error(), "search schema not found") {
			return err
		}
	}
	return nil
}

func (c *Conn) lockRows(ctx context.Context, keys []string) (func(), error) {
	if c.rowLocks == nil || len(keys) == 0 {
		return func() {}, nil
	}
	if c.tx != nil {
		if c.txLockedRows == nil {
			c.txLockedRows = make(map[string]struct{})
		}
		newKeys := make([]string, 0, len(keys))
		for _, key := range keys {
			if key == "" {
				continue
			}
			if _, exists := c.txLockedRows[key]; exists {
				continue
			}
			c.txLockedRows[key] = struct{}{}
			newKeys = append(newKeys, key)
		}
		unlock, err := c.rowLocks.acquire(ctx, newKeys)
		if err != nil {
			for _, key := range newKeys {
				delete(c.txLockedRows, key)
			}
			return nil, err
		}
		c.txRowUnlocks = append(c.txRowUnlocks, unlock)
		return func() {}, nil
	}
	return c.rowLocks.acquire(ctx, keys)
}

func (c *Conn) releaseTxRowLocks() {
	for i := len(c.txRowUnlocks) - 1; i >= 0; i-- {
		c.txRowUnlocks[i]()
	}
	c.txRowUnlocks = nil
	c.txLockedRows = nil
}

func (c *Conn) deferTxNewRowLock(key []byte) {
	if c.tx == nil || len(key) == 0 {
		return
	}
	c.deferTxNewRowKeyString(string(key))
}

func (c *Conn) deferTxNewRowKeyString(key string) {
	if c.tx == nil || key == "" {
		return
	}
	if c.txDeferredNewRows == nil {
		c.txDeferredNewRows = make(map[string]struct{})
	}
	c.txDeferredNewRows[key] = struct{}{}
}

func (c *Conn) lockAndValidateDeferredNewRows(ctx context.Context) error {
	if c.tx == nil || len(c.txDeferredNewRows) == 0 {
		return nil
	}
	keys := make([]string, 0, len(c.txDeferredNewRows))
	for key := range c.txDeferredNewRows {
		keys = append(keys, key)
	}
	var unlock func()
	var err error
	if c.rowLocks != nil {
		unlock, err = c.rowLocks.acquireUnique(ctx, keys)
		if err != nil {
			return err
		}
		c.txRowUnlocks = append(c.txRowUnlocks, unlock)
	}
	for _, key := range keys {
		if c.db.HasString(key) {
			return fmt.Errorf("velocity driver: duplicate primary key for %s", key)
		}
	}
	return nil
}

// Put writes data contextually within a transaction if one is active.
func (c *Conn) Put(key []byte, value []byte) error {
	if c.tx != nil {
		if err := c.tx.PutUnsafe(key, value); err != nil {
			return err
		}
		c.markRowsChanged([][]byte{key})
		return nil
	}
	if err := c.db.Put(key, value); err != nil {
		return err
	}
	c.markRowsChanged([][]byte{key})
	return nil
}

func (c *Conn) PutWithIndexFieldPairs(key []byte, value []byte, fields []velocity.IndexFieldValue) error {
	return c.PutTableRowWithIndexFieldPairs("", key, value, fields)
}

func (c *Conn) PutTableRowWithIndexFieldPairs(table string, key []byte, value []byte, fields []velocity.IndexFieldValue) error {
	return c.putTableRowWithIndexFieldPairs(table, key, value, fields, false)
}

func (c *Conn) PutNewTableRowWithIndexFieldPairs(table string, key []byte, value []byte, fields []velocity.IndexFieldValue) error {
	return c.putTableRowWithIndexFieldPairs(table, key, value, fields, true)
}

func (c *Conn) PutNewTableRowWithIndexFieldPairsKeyString(table string, key []byte, keyString string, value []byte, fields []velocity.IndexFieldValue) error {
	return c.putTableRowWithIndexFieldPairsKeyString(table, key, keyString, value, fields, true)
}

func (c *Conn) PutNewOwnedTableRowWithIndexFieldPairsKeyString(table string, key []byte, keyString string, value []byte, fields []velocity.IndexFieldValue) error {
	bw := c.tx
	if bw == nil {
		return c.PutNewTableRowWithIndexFieldPairsKeyString(table, key, keyString, value, fields)
	}
	if err := bw.PutNewOwnedWithIndexFieldPairsKeyStringUnsafe(key, keyString, value, fields); err != nil {
		return err
	}
	if table != "" {
		c.markTableRowChanged(table, key)
	} else {
		c.markRowsChanged([][]byte{key})
	}
	return nil
}

func (c *Conn) putTableRowWithIndexFieldPairs(table string, key []byte, value []byte, fields []velocity.IndexFieldValue, assumeNew bool) error {
	return c.putTableRowWithIndexFieldPairsKeyString(table, key, "", value, fields, assumeNew)
}

func (c *Conn) putTableRowWithIndexFieldPairsKeyString(table string, key []byte, keyString string, value []byte, fields []velocity.IndexFieldValue, assumeNew bool) error {
	bw := c.tx
	if bw == nil {
		if err := c.db.PutWithIndexFieldPairs(key, value, fields); err != nil {
			return err
		}
		c.markRowsChanged([][]byte{key})
		return nil
	}
	var err error
	if assumeNew && keyString != "" {
		err = bw.PutNewWithIndexFieldPairsKeyStringUnsafe(key, keyString, value, fields)
	} else if assumeNew {
		err = bw.PutNewWithIndexFieldPairsUnsafe(key, value, fields)
	} else {
		err = bw.PutWithIndexFieldPairsUnsafe(key, value, fields)
	}
	if err != nil {
		return err
	}
	if table != "" {
		c.markTableRowChanged(table, key)
	} else {
		c.markRowsChanged([][]byte{key})
	}
	return nil
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
		if err := c.tx.DeleteUnsafe(key); err != nil {
			return err
		}
		c.markRowsChanged([][]byte{key})
		return nil
	}
	if err := c.db.Delete(key); err != nil {
		return err
	}
	c.markRowsChanged([][]byte{key})
	return nil
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
	return c.BulkInsertFuncBatchSize(table, columns, count, 50_000, fill)
}

// BulkInsertFuncBatchSize is BulkInsertFunc with an explicit storage flush size.
// Constraint checks are planned once for the whole logical bulk insert, so an
// initially empty primary-key table can still be loaded in bounded write batches.
func (c *Conn) BulkInsertFuncBatchSize(table string, columns []string, count int, batchSize int, fill func(i int, dst []any)) (int64, error) {
	if table == "" || len(columns) == 0 || count <= 0 {
		return 0, nil
	}
	if batchSize <= 0 || batchSize > count {
		batchSize = count
	}
	plan := c.bulkInsertPlan(table, columns)
	constraints, err := c.rawInsertConstraintPlan(table, columns)
	if err != nil {
		return 0, err
	}

	inserted := int64(0)
	row := make([]any, len(columns))
	batchConstraintKeys := make(map[string]struct{})
	write := func(put func([]byte, []byte, []velocity.IndexFieldValue) error) error {
		for rowIdx := 0; rowIdx < count; rowIdx++ {
			fill(rowIdx, row)
			key, payload, fields := plan.encodeRow(row, rowIdx)
			if err := c.checkRawInsertConstraintPlan(constraints, row, key, batchConstraintKeys); err != nil {
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
		if err == nil {
			c.rememberTxIndexTable(table)
			c.markTablesChanged([]string{table})
		}
		return inserted, err
	}
	deferIndex := count >= 10_000
	if deferIndex {
		if err := c.db.ClearIndexForPrefix(table); err != nil {
			return inserted, err
		}
	}
	bw := c.db.NewBatchWriter(batchSize)
	if deferIndex {
		bw.DisableIndexMaintenance()
	}
	if err := write(bw.PutWithIndexFieldPairsUnsafe); err != nil {
		return inserted, err
	}
	if err := bw.Flush(); err != nil {
		return inserted, err
	}
	if deferIndex {
		err := c.db.RebuildIndex(table, nil, &velocity.RebuildOptions{
			BatchSize:    batchSize,
			NoWAL:        true,
			InMemoryOnly: true,
		})
		if err != nil && !strings.Contains(err.Error(), "search schema not found") {
			return inserted, err
		}
	}
	c.markTablesChanged([]string{table})
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
	return c.PutTableRowWithIndexFieldPairs(table, key, payload, fields)
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
	return c.PutTableRowWithIndexFieldPairs(table, key, payload, fields)
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
	plan := rawInsertConstraintPlan{
		table:           table,
		meta:            meta,
		found:           true,
		columnIndexes:   make(map[string]int, len(columns)),
		primaryKeyIndex: -1,
	}
	for i, col := range columns {
		plan.columnIndexes[col] = i
	}
	plan.finish()
	return c.checkRawInsertConstraintPlan(plan, values, key, seen)
}

func (c *Conn) rawInsertConstraintPlan(table string, columns []string) (rawInsertConstraintPlan, error) {
	meta, found, err := c.loadSchemaMeta(table)
	if err != nil || !found {
		return rawInsertConstraintPlan{}, err
	}
	plan := rawInsertConstraintPlan{
		table:           table,
		meta:            meta,
		found:           true,
		columnIndexes:   make(map[string]int, len(columns)),
		primaryKeyIndex: -1,
	}
	for i, col := range columns {
		plan.columnIndexes[col] = i
	}
	plan.finish()
	if meta.PrimaryKey != "" && c.tx == nil {
		count, err := c.db.SearchCount(velocity.SearchQuery{Prefix: table, Limit: 1})
		if err != nil {
			return rawInsertConstraintPlan{}, err
		}
		plan.skipPrimaryKeyStorage = count == 0
	}
	return plan, nil
}

func (c *Conn) checkRawInsertConstraintPlan(plan rawInsertConstraintPlan, values []any, key []byte, seen map[string]struct{}) error {
	return c.checkRawInsertConstraintPlanKeyString(plan, values, key, "", seen)
}

func (c *Conn) checkRawInsertConstraintPlanKeyString(plan rawInsertConstraintPlan, values []any, key []byte, keyString string, seen map[string]struct{}) error {
	if !plan.found {
		return nil
	}
	table := plan.table
	meta := plan.meta
	if plan.fastPrimaryKeyOnly {
		value := values[plan.primaryKeyIndex]
		if value == nil {
			return fmt.Errorf("velocity driver: primary key %s.%s cannot be NULL", table, meta.PrimaryKey)
		}
		if c.tx != nil && seen == nil {
			keyStr := keyString
			if keyStr == "" {
				keyStr = string(key)
			}
			if _, exists := c.txDeferredNewRows[keyStr]; exists {
				return fmt.Errorf("velocity driver: duplicate primary key on %s.%s", table, meta.PrimaryKey)
			}
			c.deferTxNewRowKeyString(keyStr)
			return nil
		}
		if c.tx == nil && seen == nil {
			if !plan.skipPrimaryKeyStorage && c.db.Has(key) {
				return fmt.Errorf("velocity driver: duplicate primary key on %s.%s", table, meta.PrimaryKey)
			}
			return nil
		}
		txKey := "pk\x00" + string(key)
		if seen != nil {
			if _, exists := seen[txKey]; exists {
				return fmt.Errorf("velocity driver: duplicate primary key on %s.%s", table, meta.PrimaryKey)
			}
		}
		if c.txConstraintKeys != nil {
			if _, exists := c.txConstraintKeys[txKey]; exists {
				return fmt.Errorf("velocity driver: duplicate primary key on %s.%s", table, meta.PrimaryKey)
			}
		}
		if !plan.skipPrimaryKeyStorage {
			if c.db.Has(key) {
				return fmt.Errorf("velocity driver: duplicate primary key on %s.%s", table, meta.PrimaryKey)
			}
		}
		if seen != nil {
			seen[txKey] = struct{}{}
		}
		if c.tx != nil {
			c.txConstraintKeys[txKey] = struct{}{}
		}
		return nil
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
	valueFor := func(col string) (any, bool) {
		idx, ok := plan.columnIndexes[col]
		if !ok || idx >= len(values) {
			return nil, false
		}
		return values[idx], true
	}
	for _, col := range meta.NotNull {
		value, ok := valueFor(col)
		if !ok || value == nil {
			return fmt.Errorf("velocity driver: column %s.%s cannot be NULL", table, col)
		}
	}
	if meta.PrimaryKey != "" {
		if value, ok := valueFor(meta.PrimaryKey); ok {
			if value == nil {
				return fmt.Errorf("velocity driver: primary key %s.%s cannot be NULL", table, meta.PrimaryKey)
			}
			txKey := "pk\x00" + string(key)
			if hasSeen(txKey) {
				return fmt.Errorf("velocity driver: duplicate primary key on %s.%s", table, meta.PrimaryKey)
			}
			if !plan.skipPrimaryKeyStorage {
				if c.db.Has(key) {
					return fmt.Errorf("velocity driver: duplicate primary key on %s.%s", table, meta.PrimaryKey)
				}
			}
			markSeen(txKey)
		}
	}
	for _, col := range meta.Unique {
		if col == meta.PrimaryKey {
			continue
		}
		value, ok := valueFor(col)
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

func (p *rawInsertConstraintPlan) finish() {
	p.primaryKeyIndex = -1
	if !p.found || p.meta.PrimaryKey == "" {
		return
	}
	idx, ok := p.columnIndexes[p.meta.PrimaryKey]
	if !ok {
		return
	}
	p.primaryKeyIndex = idx
	if len(p.meta.NotNull) != 1 || p.meta.NotNull[0] != p.meta.PrimaryKey {
		return
	}
	for _, col := range p.meta.Unique {
		if col != p.meta.PrimaryKey {
			return
		}
	}
	p.fastPrimaryKeyOnly = true
}

func (c *Conn) loadSchemaMeta(table string) (tableSchemaMeta, bool, error) {
	c.schemaMu.RLock()
	if c.schemas != nil {
		if cached, ok := c.schemas[table]; ok {
			c.schemaMu.RUnlock()
			return cached.meta, cached.found, nil
		}
	}
	c.schemaMu.RUnlock()

	raw, err := c.db.Get(schemaStorageKey(table))
	if err != nil {
		c.storeSchemaCache(table, tableSchemaMeta{}, false)
		return tableSchemaMeta{}, false, nil
	}
	var meta tableSchemaMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return tableSchemaMeta{}, false, err
	}
	c.storeSchemaCache(table, meta, true)
	return meta, true, nil
}

func (c *Conn) storeSchemaCache(table string, meta tableSchemaMeta, found bool) {
	c.schemaMu.Lock()
	if c.schemas == nil {
		c.schemas = make(map[string]cachedTableSchema)
	}
	c.schemas[table] = cachedTableSchema{meta: meta, found: found}
	c.schemaMu.Unlock()
}

func (c *Conn) clearSchemaCache() {
	c.schemaMu.Lock()
	c.schemas = nil
	c.schemaMu.Unlock()
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
