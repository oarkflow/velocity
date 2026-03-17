package sqldriver

import (
	"context"
	"database/sql/driver"
	"sync"

	"github.com/oarkflow/velocity"
	"github.com/xwb1989/sqlparser"
)

// Conn is a connection to a Velocity database using database/sql/driver.
// It is not used concurrently by multiple goroutines.
type Conn struct {
	db *velocity.DB
	tx *velocity.BatchWriter

	stmtMu    sync.RWMutex
	stmtCache map[string]sqlparser.Statement
}

// Prepare returns a prepared statement, bound to this connection.
func (c *Conn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}

// PrepareContext returns a prepared statement, bound to this connection.
func (c *Conn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	stmt, err := c.getOrParseStatement(query)
	if err != nil {
		return nil, err
	}

	return &StmtV2{
		conn:  c,
		query: query,
		stmt:  stmt,
	}, nil
}

func (c *Conn) getOrParseStatement(query string) (sqlparser.Statement, error) {
	c.stmtMu.RLock()
	if c.stmtCache != nil {
		if stmt, ok := c.stmtCache[query]; ok {
			c.stmtMu.RUnlock()
			return stmt, nil
		}
	}
	c.stmtMu.RUnlock()

	stmt, err := sqlparser.Parse(query)
	if err != nil {
		return nil, err
	}

	c.stmtMu.Lock()
	if c.stmtCache == nil {
		c.stmtCache = make(map[string]sqlparser.Statement)
	}
	c.stmtCache[query] = stmt
	c.stmtMu.Unlock()
	return stmt, nil
}

// Close invalidates and potentially stops any current
// prepared statements and transactions, marking this
// connection as no longer in use.
func (c *Conn) Close() error {
	c.db = nil
	c.stmtMu.Lock()
	c.stmtCache = nil
	c.stmtMu.Unlock()
	return nil
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
	// Default to a 1000-item batch buffer for transactional writes
	c.tx = c.db.NewBatchWriter(1000)
	return &Tx{conn: c}, nil
}

// Tx represents an active Velocity batch transaction.
type Tx struct {
	conn *Conn
}

func (tx *Tx) Commit() error {
	err := tx.conn.tx.Flush()
	tx.conn.tx = nil
	return err
}

func (tx *Tx) Rollback() error {
	tx.conn.tx.Cancel()
	tx.conn.tx = nil
	return nil
}

// Put writes data contextually within a transaction if one is active.
func (c *Conn) Put(key []byte, value []byte) error {
	if c.tx != nil {
		return c.tx.Put(key, value)
	}
	return c.db.Put(key, value)
}

// Delete removes data contextually within a transaction if one is active.
func (c *Conn) Delete(key []byte) error {
	if c.tx != nil {
		return c.tx.Delete(key)
	}
	return c.db.Delete(key)
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
