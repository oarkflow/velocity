package velocity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Hash algorithm for integrity verification
type HashAlgorithm int

const (
	// HashSHA256 uses SHA-256 (default, available in stdlib)
	HashSHA256 HashAlgorithm = iota
	// HashHighwayHash placeholder for future HighwayHash support
	HashHighwayHash
	// HashXXHash placeholder for future xxHash support
	HashXXHash
)

const (
	integrityPrefix = "obj:integrity:"
	scanPrefix      = "obj:scan:"
)

// BitRotDetector scans stored objects for silent data corruption
type BitRotDetector struct {
	db           *DB
	scanInterval time.Duration
	algorithm    HashAlgorithm
	running      atomic.Bool
	stopCh       chan struct{}
	stats        BitRotStats
}

// BitRotStats tracks scanning statistics
type BitRotStats struct {
	ObjectsScanned   int64
	CorruptionFound  int64
	ObjectsHealed    int64
	LastScanTime     time.Time
	LastScanDuration time.Duration
	mu               sync.Mutex
}

// BitRotResult is the result of scanning a single object
type BitRotResult struct {
	Path           string    `json:"path"`
	Healthy        bool      `json:"healthy"`
	StoredHash     string    `json:"stored_hash"`
	ComputedHash   string    `json:"computed_hash"`
	Algorithm      string    `json:"algorithm"`
	ScannedAt      time.Time `json:"scanned_at"`
	ObjectSize     int64     `json:"object_size"`
	ErrorMessage   string    `json:"error_message,omitempty"`
}

// BitRotScanReport is the result of a full scan
type BitRotScanReport struct {
	StartedAt       time.Time      `json:"started_at"`
	CompletedAt     time.Time      `json:"completed_at"`
	Duration        time.Duration  `json:"duration"`
	ObjectsScanned  int            `json:"objects_scanned"`
	CorruptionFound int            `json:"corruption_found"`
	HealthyObjects  int            `json:"healthy_objects"`
	ErrorObjects    int            `json:"error_objects"`
	Results         []BitRotResult `json:"results,omitempty"`
}

// IntegrityRecord stores the integrity hash for an object
type IntegrityRecord struct {
	Path         string    `json:"path"`
	Hash         string    `json:"hash"`
	Algorithm    string    `json:"algorithm"`
	ObjectSize   int64     `json:"object_size"`
	ComputedAt   time.Time `json:"computed_at"`
	ObjectID     string    `json:"object_id"`
	VersionID    string    `json:"version_id"`
}

// NewBitRotDetector creates a new bit-rot detector
func NewBitRotDetector(db *DB, interval time.Duration, algo HashAlgorithm) *BitRotDetector {
	if interval == 0 {
		interval = 24 * time.Hour // Default: daily scans
	}
	return &BitRotDetector{
		db:           db,
		scanInterval: interval,
		algorithm:    algo,
		stopCh:       make(chan struct{}),
	}
}

// Start begins background scanning
func (brd *BitRotDetector) Start(ctx context.Context) {
	if !brd.running.CompareAndSwap(false, true) {
		return
	}

	go func() {
		ticker := time.NewTicker(brd.scanInterval)
		defer ticker.Stop()
		defer brd.running.Store(false)

		for {
			select {
			case <-ctx.Done():
				return
			case <-brd.stopCh:
				return
			case <-ticker.C:
				brd.ScanAll(ctx)
			}
		}
	}()
}

// Stop stops the background scanner
func (brd *BitRotDetector) Stop() {
	if brd.running.Load() {
		close(brd.stopCh)
	}
}

// ScanObject checks integrity of a single object
func (brd *BitRotDetector) ScanObject(path string) (*BitRotResult, error) {
	result := &BitRotResult{
		Path:      path,
		ScannedAt: time.Now().UTC(),
		Algorithm: brd.algorithmName(),
	}

	// Get object metadata
	meta, err := brd.db.GetObjectMetadata(path)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to get metadata: %v", err)
		return result, err
	}

	result.ObjectSize = meta.Size

	// Read object data from disk
	objectsDir := filepath.Join(brd.db.filesDir, "objects")
	filePath := filepath.Join(objectsDir, meta.ObjectID, meta.VersionID)

	f, err := os.Open(filePath)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to open object file: %v", err)
		return result, err
	}
	defer f.Close()

	// Compute hash of file on disk
	computedHash, err := brd.computeFileHash(f)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to compute hash: %v", err)
		return result, err
	}
	result.ComputedHash = computedHash

	// Get stored integrity hash
	storedRecord, err := brd.getIntegrityRecord(path)
	if err != nil {
		// No stored hash - store current one as baseline
		record := &IntegrityRecord{
			Path:       path,
			Hash:       computedHash,
			Algorithm:  brd.algorithmName(),
			ObjectSize: meta.Size,
			ComputedAt: time.Now().UTC(),
			ObjectID:   meta.ObjectID,
			VersionID:  meta.VersionID,
		}
		brd.saveIntegrityRecord(record)
		result.StoredHash = computedHash
		result.Healthy = true
		return result, nil
	}

	result.StoredHash = storedRecord.Hash

	// Compare hashes
	if computedHash == storedRecord.Hash {
		result.Healthy = true
	} else {
		result.Healthy = false
		result.ErrorMessage = "data corruption detected: hash mismatch"
		atomic.AddInt64(&brd.stats.CorruptionFound, 1)
	}

	atomic.AddInt64(&brd.stats.ObjectsScanned, 1)

	// Save scan result
	brd.saveScanResult(result)

	return result, nil
}

// ScanAll scans all objects for integrity
func (brd *BitRotDetector) ScanAll(ctx context.Context) (*BitRotScanReport, error) {
	report := &BitRotScanReport{
		StartedAt: time.Now().UTC(),
	}

	objects, err := brd.db.ListObjects(ObjectListOptions{
		Recursive: true,
		MaxKeys:   100000,
	})
	if err != nil {
		return nil, err
	}

	for _, obj := range objects {
		select {
		case <-ctx.Done():
			report.CompletedAt = time.Now().UTC()
			report.Duration = report.CompletedAt.Sub(report.StartedAt)
			return report, ctx.Err()
		default:
		}

		result, err := brd.ScanObject(obj.Path)
		report.ObjectsScanned++
		if err != nil {
			report.ErrorObjects++
		} else if result.Healthy {
			report.HealthyObjects++
		} else {
			report.CorruptionFound++
		}
		report.Results = append(report.Results, *result)
	}

	report.CompletedAt = time.Now().UTC()
	report.Duration = report.CompletedAt.Sub(report.StartedAt)

	brd.stats.mu.Lock()
	brd.stats.LastScanTime = report.CompletedAt
	brd.stats.LastScanDuration = report.Duration
	brd.stats.mu.Unlock()

	return report, nil
}

// GetStats returns current scanning statistics
func (brd *BitRotDetector) GetStats() BitRotStats {
	brd.stats.mu.Lock()
	defer brd.stats.mu.Unlock()
	return BitRotStats{
		ObjectsScanned:   atomic.LoadInt64(&brd.stats.ObjectsScanned),
		CorruptionFound:  atomic.LoadInt64(&brd.stats.CorruptionFound),
		ObjectsHealed:    atomic.LoadInt64(&brd.stats.ObjectsHealed),
		LastScanTime:     brd.stats.LastScanTime,
		LastScanDuration: brd.stats.LastScanDuration,
	}
}

// ComputeHash computes integrity hash for data
func ComputeHash(data []byte, algo HashAlgorithm) []byte {
	switch algo {
	case HashSHA256, HashHighwayHash, HashXXHash:
		h := sha256.Sum256(data)
		return h[:]
	default:
		h := sha256.Sum256(data)
		return h[:]
	}
}

func (brd *BitRotDetector) computeFileHash(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (brd *BitRotDetector) algorithmName() string {
	switch brd.algorithm {
	case HashSHA256:
		return "SHA-256"
	case HashHighwayHash:
		return "HighwayHash"
	case HashXXHash:
		return "xxHash"
	default:
		return "SHA-256"
	}
}

func (brd *BitRotDetector) getIntegrityRecord(path string) (*IntegrityRecord, error) {
	data, err := brd.db.Get([]byte(integrityPrefix + path))
	if err != nil {
		return nil, err
	}

	var record IntegrityRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}

	return &record, nil
}

func (brd *BitRotDetector) saveIntegrityRecord(record *IntegrityRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return brd.db.PutWithTTL([]byte(integrityPrefix+record.Path), data, 0)
}

func (brd *BitRotDetector) saveScanResult(result *BitRotResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%s%s:%d", scanPrefix, result.Path, result.ScannedAt.UnixNano())
	return brd.db.PutWithTTL([]byte(key), data, 0)
}

// UpdateIntegrityHash updates the stored integrity hash (after healing)
func (brd *BitRotDetector) UpdateIntegrityHash(path string, hash string, meta *ObjectMetadata) error {
	record := &IntegrityRecord{
		Path:       path,
		Hash:       hash,
		Algorithm:  brd.algorithmName(),
		ObjectSize: meta.Size,
		ComputedAt: time.Now().UTC(),
		ObjectID:   meta.ObjectID,
		VersionID:  meta.VersionID,
	}
	return brd.saveIntegrityRecord(record)
}

// GetIntegrityHash retrieves the stored hash for a path
func (brd *BitRotDetector) GetIntegrityHash(path string) (string, error) {
	record, err := brd.getIntegrityRecord(path)
	if err != nil {
		return "", err
	}
	return record.Hash, nil
}

// PurgeOldScans removes scan results older than the given duration
func (brd *BitRotDetector) PurgeOldScans(maxAge time.Duration) (int, error) {
	keys, err := brd.db.Keys(scanPrefix + "*")
	if err != nil {
		return 0, err
	}

	purged := 0
	cutoff := time.Now().Add(-maxAge)

	for _, key := range keys {
		data, err := brd.db.Get([]byte(key))
		if err != nil {
			continue
		}

		var result BitRotResult
		if err := json.Unmarshal(data, &result); err != nil {
			continue
		}

		if result.ScannedAt.Before(cutoff) {
			brd.db.Delete([]byte(key))
			purged++
		}
	}

	return purged, nil
}

// VerifyObjectIntegrity verifies an object's integrity by comparing its hash with the stored hash
func (brd *BitRotDetector) VerifyObjectIntegrity(path string) (bool, string, error) {
	// Get stored integrity record
	record, err := brd.getIntegrityRecord(path)
	if err != nil {
		return false, "", fmt.Errorf("no integrity record found for %s", path)
	}

	// Get object metadata
	meta, err := brd.db.GetObjectMetadata(path)
	if err != nil {
		return false, "", err
	}

	// Read and hash current file
	objectsDir := filepath.Join(brd.db.filesDir, "objects")
	filePath := filepath.Join(objectsDir, meta.ObjectID, meta.VersionID)

	f, err := os.Open(filePath)
	if err != nil {
		return false, "", err
	}
	defer f.Close()

	currentHash, err := brd.computeFileHash(f)
	if err != nil {
		return false, currentHash, err
	}

	match := currentHash == record.Hash
	if !match {
		// Check if it matches path-level stored hash
		pathParts := strings.SplitN(path, "/", 2)
		if len(pathParts) == 2 {
			altPath := pathParts[1]
			altRecord, err := brd.getIntegrityRecord(altPath)
			if err == nil && altRecord.Hash == currentHash {
				match = true
			}
		}
	}

	return match, currentHash, nil
}
