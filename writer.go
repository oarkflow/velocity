package velocity

import (
	"sync"
	"time"
)

// BatchWriter for high-throughput writes
type BatchWriter struct {
	db      *DB
	entries []*Entry
	mutex   sync.Mutex
	size    int
	maxSize int
}

func (db *DB) NewBatchWriter(maxSize int) *BatchWriter {
	return &BatchWriter{
		db:      db,
		entries: make([]*Entry, 0, maxSize),
		maxSize: maxSize,
	}
}

func (bw *BatchWriter) Put(key, value []byte) error {
	bw.mutex.Lock()
	defer bw.mutex.Unlock()

	entry := &Entry{
		Key:       append([]byte{}, key...),
		Value:     append([]byte{}, value...),
		Timestamp: uint64(time.Now().UnixNano()),
		Deleted:   false,
	}

	bw.entries = append(bw.entries, entry)
	bw.size++

	if bw.size >= bw.maxSize {
		return bw.flushUnsafe()
	}

	return nil
}

func (bw *BatchWriter) Flush() error {
	bw.mutex.Lock()
	defer bw.mutex.Unlock()
	return bw.flushUnsafe()
}

func (bw *BatchWriter) flushUnsafe() error {
	if bw.size == 0 {
		return nil
	}

	// Batch write to WAL
	for _, entry := range bw.entries {
		if err := bw.db.wal.Write(entry); err != nil {
			return err
		}
	}

	// Batch write to memtable
	for _, entry := range bw.entries {
		bw.db.memTable.Put(entry.Key, entry.Value)
	}

	// Reset batch
	bw.entries = bw.entries[:0]
	bw.size = 0

	return nil
}
