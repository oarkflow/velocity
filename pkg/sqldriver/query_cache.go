package sqldriver

import (
	"container/list"
	"database/sql/driver"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/sqlparser/ast"
	"github.com/oarkflow/sqlparser/lexer"
	"github.com/oarkflow/velocity"
)

const (
	defaultQueryCacheMaxBytes       = 32 * 1024 * 1024
	defaultQueryCacheTTL            = 30 * time.Second
	defaultQueryCacheMaxResultBytes = 4 * 1024 * 1024
	defaultQueryCacheMaxRows        = 0
)

type queryCacheConfig struct {
	enabled        bool
	maxBytes       int64
	ttl            time.Duration
	maxResultBytes int64
	maxRows        int
}

func newQueryCacheConfig(cfg *velocity.Config) queryCacheConfig {
	out := queryCacheConfig{
		enabled:        true,
		maxBytes:       defaultQueryCacheMaxBytes,
		ttl:            defaultQueryCacheTTL,
		maxResultBytes: defaultQueryCacheMaxResultBytes,
		maxRows:        defaultQueryCacheMaxRows,
	}
	if cfg == nil {
		return out
	}
	if cfg.SQLQueryCacheDisabled {
		out.enabled = false
	}
	if cfg.SQLQueryCacheMaxBytes > 0 {
		out.maxBytes = cfg.SQLQueryCacheMaxBytes
	}
	if cfg.SQLQueryCacheTTL > 0 {
		out.ttl = cfg.SQLQueryCacheTTL
	}
	if cfg.SQLQueryCacheMaxResultBytes > 0 {
		out.maxResultBytes = cfg.SQLQueryCacheMaxResultBytes
	}
	if cfg.SQLQueryCacheMaxRows > 0 {
		out.maxRows = cfg.SQLQueryCacheMaxRows
	}
	return out
}

type SQLQueryCache struct {
	mu            sync.Mutex
	enabled       bool
	maxBytes      int64
	ttl           time.Duration
	currentBytes  int64
	items         map[string]*queryCacheEntry
	lru           *list.List
	tableVersions map[string]uint64
	rowVersions   map[string]uint64
	schemaVersion uint64
}

type queryCacheEntry struct {
	key       string
	rows      *Rows
	deps      queryDependencies
	createdAt time.Time
	sizeBytes int64
	element   *list.Element
}

type queryDependencies struct {
	tables        map[string]uint64
	rows          map[string]uint64
	schemaVersion uint64
}

func newSQLQueryCache(cfg queryCacheConfig) *SQLQueryCache {
	return &SQLQueryCache{
		enabled:       cfg.enabled && cfg.maxBytes > 0,
		maxBytes:      cfg.maxBytes,
		ttl:           cfg.ttl,
		items:         make(map[string]*queryCacheEntry),
		lru:           list.New(),
		tableVersions: make(map[string]uint64),
		rowVersions:   make(map[string]uint64),
	}
}

func newTxSQLQueryCache(cfg queryCacheConfig) *SQLQueryCache {
	cfg.maxBytes = minPositiveInt64(cfg.maxBytes, 4*1024*1024)
	cfg.ttl = minPositiveDuration(cfg.ttl, 5*time.Second)
	return newSQLQueryCache(cfg)
}

func minPositiveInt64(a, b int64) int64 {
	if a <= 0 {
		return b
	}
	if b <= 0 || a < b {
		return a
	}
	return b
}

func minPositiveDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 || a < b {
		return a
	}
	return b
}

func (c *SQLQueryCache) Get(key string) (*Rows, bool) {
	if c == nil || !c.enabled {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.items[key]
	if entry == nil {
		return nil, false
	}
	if c.ttl > 0 && time.Since(entry.createdAt) > c.ttl {
		c.removeEntry(entry)
		return nil, false
	}
	if !c.depsValidLocked(entry.deps) {
		c.removeEntry(entry)
		return nil, false
	}
	c.lru.MoveToFront(entry.element)
	return entry.rows.CacheView(), true
}

func (c *SQLQueryCache) Put(key string, rows *Rows, deps queryDependencies, maxRows int, maxResultBytes int64) {
	if c == nil || !c.enabled || key == "" || rows == nil {
		return
	}
	rowCount := rows.RowCount()
	if maxRows > 0 && rowCount > maxRows {
		return
	}
	size := rows.EstimatedSize()
	if maxResultBytes > 0 && size > maxResultBytes {
		return
	}
	if size > c.maxBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old := c.items[key]; old != nil {
		c.removeEntry(old)
	}
	entry := &queryCacheEntry{
		key:       key,
		rows:      rows.Clone(),
		deps:      c.snapshotDepsLocked(deps),
		createdAt: time.Now(),
		sizeBytes: size,
	}
	entry.element = c.lru.PushFront(entry)
	c.items[key] = entry
	c.currentBytes += size
	for c.currentBytes > c.maxBytes {
		back := c.lru.Back()
		if back == nil {
			break
		}
		c.removeEntry(back.Value.(*queryCacheEntry))
	}
}

func (c *SQLQueryCache) BumpRows(keys []string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	seenTables := make(map[string]struct{})
	for _, key := range keys {
		if key == "" || isSQLMetaKey(key) {
			continue
		}
		c.rowVersions[key]++
		if table := tableNameFromStorageKey(key); table != "" {
			seenTables[table] = struct{}{}
		}
	}
	for table := range seenTables {
		c.tableVersions[table]++
	}
}

func (c *SQLQueryCache) BumpTables(tables []string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, table := range tables {
		if table != "" {
			c.tableVersions[table]++
		}
	}
}

func (c *SQLQueryCache) BumpSchema() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.schemaVersion++
}

func (c *SQLQueryCache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*queryCacheEntry)
	c.lru.Init()
	c.currentBytes = 0
}

func (c *SQLQueryCache) removeEntry(entry *queryCacheEntry) {
	delete(c.items, entry.key)
	if entry.element != nil {
		c.lru.Remove(entry.element)
	}
	c.currentBytes -= entry.sizeBytes
	if c.currentBytes < 0 {
		c.currentBytes = 0
	}
}

func (c *SQLQueryCache) depsValidLocked(deps queryDependencies) bool {
	if deps.schemaVersion != c.schemaVersion {
		return false
	}
	for table, version := range deps.tables {
		if c.tableVersions[table] != version {
			return false
		}
	}
	for key, version := range deps.rows {
		if c.rowVersions[key] != version {
			return false
		}
	}
	return true
}

func (c *SQLQueryCache) snapshotDepsLocked(deps queryDependencies) queryDependencies {
	out := queryDependencies{
		tables:        make(map[string]uint64, len(deps.tables)),
		rows:          make(map[string]uint64, len(deps.rows)),
		schemaVersion: c.schemaVersion,
	}
	for table := range deps.tables {
		out.tables[table] = c.tableVersions[table]
	}
	for key := range deps.rows {
		out.rows[key] = c.rowVersions[key]
	}
	return out
}

func queryCacheKey(rawSQL string, args []driver.NamedValue, txLocal bool) string {
	return queryCacheKeyFromNormalized(normalizeSQLForCache(rawSQL), args, txLocal)
}

func queryCacheKeyFromNormalized(normalizedSQL string, args []driver.NamedValue, txLocal bool) string {
	var b strings.Builder
	b.Grow(len(normalizedSQL) + 16 + len(args)*24)
	b.WriteString(normalizedSQL)
	if txLocal {
		b.WriteString("\x00tx")
	} else {
		b.WriteString("\x00global")
	}
	for _, arg := range args {
		b.WriteByte('\x00')
		b.WriteString(strconv.Itoa(arg.Ordinal))
		b.WriteByte('=')
		writeCacheArg(&b, arg.Value)
	}
	return b.String()
}

func normalizeSQLForCache(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	inSpace := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch c {
		case ' ', '\n', '\r', '\t':
			inSpace = true
			continue
		}
		if inSpace && b.Len() > 0 {
			b.WriteByte(' ')
		}
		inSpace = false
		b.WriteByte(c)
	}
	return b.String()
}

func writeCacheArg(b *strings.Builder, value any) {
	switch v := value.(type) {
	case nil:
		b.WriteString("<nil>")
	case int:
		b.WriteString(strconv.Itoa(v))
	case int8:
		b.WriteString(strconv.FormatInt(int64(v), 10))
	case int16:
		b.WriteString(strconv.FormatInt(int64(v), 10))
	case int32:
		b.WriteString(strconv.FormatInt(int64(v), 10))
	case int64:
		b.WriteString(strconv.FormatInt(v, 10))
	case uint:
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	case uint8:
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	case uint16:
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	case uint32:
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	case uint64:
		b.WriteString(strconv.FormatUint(v, 10))
	case float32:
		b.WriteString(strconv.FormatFloat(float64(v), 'g', -1, 32))
	case float64:
		b.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
	case bool:
		b.WriteString(strconv.FormatBool(v))
	case string:
		b.WriteString(strconv.Quote(v))
	case []byte:
		b.WriteString(strconv.Quote(string(v)))
	case time.Time:
		b.WriteString(v.UTC().Format(time.RFC3339Nano))
	default:
		b.WriteString(strconv.Quote(fmt.Sprint(v)))
	}
}

func queryDependenciesForSelect(e *ExecutorV2, stmt *ast.SelectStmt, args []driver.NamedValue) queryDependencies {
	deps := queryDependencies{tables: make(map[string]uint64), rows: make(map[string]uint64)}
	if stmt == nil {
		return deps
	}
	tables := collectSelectTables(e, stmt, make(map[string]struct{}))
	for _, table := range tables {
		deps.tables[table] = 0
	}
	if rowKey, ok := pointSelectRowKey(e, stmt, args); ok {
		deps.rows[rowKey] = 0
		if table := tableNameFromStorageKey(rowKey); table != "" {
			delete(deps.tables, table)
		}
	}
	return deps
}

func collectSelectTables(e *ExecutorV2, stmt *ast.SelectStmt, seen map[string]struct{}) []string {
	if stmt == nil {
		return nil
	}
	set := make(map[string]struct{})
	var walk func(*ast.SelectStmt)
	walk = func(sel *ast.SelectStmt) {
		if sel == nil {
			return
		}
		for _, ref := range sel.From {
			collectTablesFromRef(e, ref, seen, set)
		}
		if sel.With != nil {
			for _, cte := range sel.With.CTEs {
				walk(cte.Subq)
			}
		}
		for op := sel.SetOp; op != nil; op = op.Right.SetOp {
			walk(op.Right)
		}
	}
	walk(stmt)
	out := make([]string, 0, len(set))
	for table := range set {
		out = append(out, table)
	}
	sort.Strings(out)
	return out
}

func collectTablesFromRef(e *ExecutorV2, ref ast.TableRef, seen map[string]struct{}, out map[string]struct{}) {
	switch t := ref.(type) {
	case *ast.SimpleTable:
		name := qualifiedIdentToString(t.Name)
		if name == "" {
			return
		}
		if _, viewFound, _ := e.loadViewMeta(name); viewFound {
			if _, exists := seen["view:"+name]; exists {
				return
			}
			seen["view:"+name] = struct{}{}
			out["__view:"+name] = struct{}{}
			view, _, _ := e.loadViewMeta(name)
			if parsed, err := parseViewSelect(view.Select); err == nil {
				for _, table := range collectSelectTables(e, parsed, seen) {
					out[table] = struct{}{}
				}
			}
			return
		}
		out[name] = struct{}{}
	case *ast.JoinTable:
		collectTablesFromRef(e, t.Left, seen, out)
		collectTablesFromRef(e, t.Right, seen, out)
	case *ast.SubqueryTable:
		if t.Subq != nil {
			for _, table := range collectSelectTables(e, t.Subq, seen) {
				out[table] = struct{}{}
			}
		}
	}
}

func pointSelectRowKey(e *ExecutorV2, sel *ast.SelectStmt, args []driver.NamedValue) (string, bool) {
	if sel == nil || sel.Where == nil || sel.Distinct || len(sel.GroupBy) > 0 || len(sel.OrderBy) > 0 || sel.Having != nil || sel.Limit != nil || sel.SetOp != nil {
		return "", false
	}
	if len(sel.From) != 1 || hasJoinRef(sel.From) {
		return "", false
	}
	table, ok := sel.From[0].(*ast.SimpleTable)
	if !ok || table.Alias != nil {
		return "", false
	}
	tableName := qualifiedIdentToString(table.Name)
	if tableName == "" {
		return "", false
	}
	if _, found, _ := e.loadViewMeta(tableName); found {
		return "", false
	}
	binary, ok := sel.Where.(*ast.BinaryExpr)
	if !ok || binary.Op != lexer.EQ || exprColumnName(binary.Left) != "id" {
		return "", false
	}
	eval := &Evaluator{Args: args, ParamOrder: e.paramOrder}
	id, err := eval.Eval(binary.Right, nil)
	if err != nil || id == nil {
		return "", false
	}
	return string(appendTableKey(nil, tableName, id)), true
}

func tableNameFromStorageKey(key string) string {
	if key == "" || strings.HasPrefix(key, tableSchemaPrefix) || strings.HasPrefix(key, viewPrefix) || strings.HasPrefix(key, "_") {
		return ""
	}
	idx := strings.IndexByte(key, ':')
	if idx <= 0 {
		return ""
	}
	return key[:idx]
}

func isSQLMetaKey(key string) bool {
	return strings.HasPrefix(key, tableSchemaPrefix) || strings.HasPrefix(key, viewPrefix)
}
