package velocity

import (
	"hash/crc32"
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
	// compute checksum early so it's present even if flush occurs immediately
	entry.checksum = crc32.ChecksumIEEE(append(entry.Key, entry.Value...))

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

	// Ensure checksums are computed for each entry before writing to WAL
	for _, entry := range bw.entries {
		if entry.checksum == 0 {
			if entry.Deleted {
				entry.checksum = crc32.ChecksumIEEE(entry.Key)
			} else {
				entry.checksum = crc32.ChecksumIEEE(append(entry.Key, entry.Value...))
			}
		}
	}

	// Batch write to WAL
	for _, entry := range bw.entries {
		if err := bw.db.wal.Write(entry); err != nil {
			return err
		}
	}
	// Ensure WAL buffer is flushed to disk before proceeding
	if err := bw.db.wal.Sync(); err != nil {
		return err
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
