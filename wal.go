package velocity

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// WAL (Write-Ahead Log) for durability
type WAL struct {
	file     *os.File
	buffer   *bytes.Buffer
	mutex    sync.Mutex
	ticker   *time.Ticker
	stopChan chan struct{}
	closed   bool
	crypto   *CryptoProvider
}

func NewWAL(path string, crypto *CryptoProvider) (*WAL, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	if crypto == nil {
		return nil, fmt.Errorf("encryption provider is required for WAL")
	}

	wal := &WAL{
		file:     file,
		buffer:   bytes.NewBuffer(make([]byte, 0, WALBufferSize)),
		ticker:   time.NewTicker(WALSyncInterval),
		stopChan: make(chan struct{}),
		crypto:   crypto,
	}

	// Background sync goroutine
	go wal.syncLoop()

	return wal, nil
}

func (w *WAL) Write(entry *Entry) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	// Encrypt value using AEAD with entry metadata as AAD
	nonce, ciphertext, err := w.crypto.Encrypt(entry.Value, buildEntryAAD(entry.Key, entry.Timestamp, entry.Deleted))
	if err != nil {
		return err
	}

	keyLen := uint32(len(entry.Key))
	nonceLen := uint16(len(nonce))
	valueLen := uint32(len(ciphertext))

	binary.Write(w.buffer, binary.LittleEndian, keyLen)
	w.buffer.Write(entry.Key)
	binary.Write(w.buffer, binary.LittleEndian, nonceLen)
	w.buffer.Write(nonce)
	binary.Write(w.buffer, binary.LittleEndian, valueLen)
	w.buffer.Write(ciphertext)
	binary.Write(w.buffer, binary.LittleEndian, entry.Timestamp)

	var deleted uint8
	if entry.Deleted {
		deleted = 1
	}
	binary.Write(w.buffer, binary.LittleEndian, deleted)
	binary.Write(w.buffer, binary.LittleEndian, entry.checksum)

	// Sync if buffer is full
	if w.buffer.Len() >= WALBufferSize {
		return w.syncUnsafe()
	}

	return nil
}

func (w *WAL) syncLoop() {
	for {
		select {
		case <-w.ticker.C:
			w.mutex.Lock()
			w.syncUnsafe()
			w.mutex.Unlock()
		case <-w.stopChan:
			return
		}
	}
}

func (w *WAL) syncUnsafe() error {
	if w.buffer.Len() == 0 {
		return nil
	}

	_, err := w.file.Write(w.buffer.Bytes())
	if err != nil {
		return err
	}

	err = w.file.Sync()
	if err != nil {
		return err
	}

	w.buffer.Reset()
	return nil
}

func (w *WAL) Close() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	// Prevent double-closing
	if w.closed {
		return nil
	}
	w.closed = true

	defer func() {
		if r := recover(); r != nil {
			log.Printf("WAL.Close() panic recovered: %v", r)
		}
	}()

	close(w.stopChan)
	w.ticker.Stop()

	w.syncUnsafe()
	return w.file.Close()
}
