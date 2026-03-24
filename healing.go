package velocity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// HealingManager manages automatic data repair
type HealingManager struct {
	db           *DB
	erasure      *ErasureEncoder
	bitrot       *BitRotDetector
	running      atomic.Bool
	stopCh       chan struct{}
	healInterval time.Duration
	stats        HealingStats
}

// HealingStats tracks healing statistics
type HealingStats struct {
	ObjectsChecked int64
	ObjectsHealed  int64
	ShardsRepaired int64
	HealFailures   int64
	LastHealTime   time.Time
	mu             sync.Mutex
}

// HealResult is the result of healing a single object
type HealResult struct {
	Path          string    `json:"path"`
	Healed        bool      `json:"healed"`
	Method        string    `json:"method"` // "erasure", "backup", "none"
	ShardsRepaired int      `json:"shards_repaired"`
	ErrorMessage  string    `json:"error_message,omitempty"`
	HealedAt      time.Time `json:"healed_at"`
}

// HealReport is the result of healing all objects
type HealReport struct {
	StartedAt      time.Time    `json:"started_at"`
	CompletedAt    time.Time    `json:"completed_at"`
	Duration       time.Duration `json:"duration"`
	ObjectsChecked int          `json:"objects_checked"`
	ObjectsHealed  int          `json:"objects_healed"`
	HealFailures   int          `json:"heal_failures"`
	Results        []HealResult `json:"results,omitempty"`
}

// NewHealingManager creates a new healing manager
func NewHealingManager(db *DB, erasure *ErasureEncoder, bitrot *BitRotDetector) *HealingManager {
	return &HealingManager{
		db:           db,
		erasure:      erasure,
		bitrot:       bitrot,
		healInterval: 6 * time.Hour, // Default: every 6 hours
		stopCh:       make(chan struct{}),
	}
}

// Start begins background healing
func (hm *HealingManager) Start(ctx context.Context) {
	if !hm.running.CompareAndSwap(false, true) {
		return
	}

	go func() {
		ticker := time.NewTicker(hm.healInterval)
		defer ticker.Stop()
		defer hm.running.Store(false)

		for {
			select {
			case <-ctx.Done():
				return
			case <-hm.stopCh:
				return
			case <-ticker.C:
				hm.HealAll(ctx)
			}
		}
	}()
}

// Stop stops the background healer
func (hm *HealingManager) Stop() {
	if hm.running.Load() {
		close(hm.stopCh)
	}
}

// HealObject attempts to heal a single corrupted object
func (hm *HealingManager) HealObject(path string) (*HealResult, error) {
	result := &HealResult{
		Path:     path,
		HealedAt: time.Now().UTC(),
	}

	atomic.AddInt64(&hm.stats.ObjectsChecked, 1)

	// First check if the object is actually corrupt
	if hm.bitrot != nil {
		scanResult, err := hm.bitrot.ScanObject(path)
		if err != nil {
			result.ErrorMessage = fmt.Sprintf("scan failed: %v", err)
			atomic.AddInt64(&hm.stats.HealFailures, 1)
			return result, err
		}

		if scanResult.Healthy {
			result.Method = "none"
			result.Healed = true
			return result, nil
		}
	}

	// Try to heal using erasure coding
	if hm.erasure != nil {
		healed, shardsRepaired, err := hm.healWithErasure(path)
		if err == nil && healed {
			result.Healed = true
			result.Method = "erasure"
			result.ShardsRepaired = shardsRepaired
			atomic.AddInt64(&hm.stats.ObjectsHealed, 1)
			atomic.AddInt64(&hm.stats.ShardsRepaired, int64(shardsRepaired))
			return result, nil
		}
	}

	// Cannot heal - mark as corrupt
	result.Healed = false
	result.Method = "none"
	result.ErrorMessage = "unable to heal: no valid erasure coding shards available"
	atomic.AddInt64(&hm.stats.HealFailures, 1)

	// Mark the object as corrupt in metadata
	hm.markCorrupt(path)

	return result, fmt.Errorf("unable to heal object %s", path)
}

// HealAll scans and heals all objects
func (hm *HealingManager) HealAll(ctx context.Context) (*HealReport, error) {
	report := &HealReport{
		StartedAt: time.Now().UTC(),
	}

	objects, err := hm.db.ListObjects(ObjectListOptions{
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

		result, _ := hm.HealObject(obj.Path)
		report.ObjectsChecked++
		if result.Healed && result.Method != "none" {
			report.ObjectsHealed++
		} else if !result.Healed {
			report.HealFailures++
		}
		report.Results = append(report.Results, *result)
	}

	report.CompletedAt = time.Now().UTC()
	report.Duration = report.CompletedAt.Sub(report.StartedAt)

	hm.stats.mu.Lock()
	hm.stats.LastHealTime = report.CompletedAt
	hm.stats.mu.Unlock()

	return report, nil
}

// GetStats returns healing statistics
func (hm *HealingManager) GetStats() HealingStats {
	hm.stats.mu.Lock()
	defer hm.stats.mu.Unlock()
	return HealingStats{
		ObjectsChecked: atomic.LoadInt64(&hm.stats.ObjectsChecked),
		ObjectsHealed:  atomic.LoadInt64(&hm.stats.ObjectsHealed),
		ShardsRepaired: atomic.LoadInt64(&hm.stats.ShardsRepaired),
		HealFailures:   atomic.LoadInt64(&hm.stats.HealFailures),
		LastHealTime:   hm.stats.LastHealTime,
	}
}

func (hm *HealingManager) healWithErasure(path string) (bool, int, error) {
	meta, err := hm.db.GetObjectMetadata(path)
	if err != nil {
		return false, 0, err
	}

	objectsDir := filepath.Join(hm.db.filesDir, "objects")
	totalShards := hm.erasure.config.DataShards + hm.erasure.config.ParityShards

	// Read all available shards
	shards := make([][]byte, totalShards)
	missingCount := 0

	for i := 0; i < totalShards; i++ {
		shardPath := filepath.Join(objectsDir, meta.ObjectID, fmt.Sprintf("%s.shard.%d", meta.VersionID, i))
		data, err := os.ReadFile(shardPath)
		if err != nil {
			shards[i] = nil
			missingCount++
		} else {
			shards[i] = data
		}
	}

	// Check if we have enough shards to recover
	if missingCount > hm.erasure.config.ParityShards {
		return false, 0, fmt.Errorf("too many missing shards: %d (max recoverable: %d)", missingCount, hm.erasure.config.ParityShards)
	}

	if missingCount == 0 {
		// All shards present - verify them
		ok := hm.erasure.Verify(shards)
		if ok {
			return true, 0, nil
		}
	}

	// Reconstruct data from available shards
	reconstructed, err := hm.erasure.Decode(shards, int(meta.Size))
	if err != nil {
		return false, 0, fmt.Errorf("erasure decode failed: %w", err)
	}

	// Re-encode and write all shards
	newShards, err := hm.erasure.Encode(reconstructed)
	if err != nil {
		return false, 0, err
	}

	shardsRepaired := 0
	for i, shard := range newShards {
		shardPath := filepath.Join(objectsDir, meta.ObjectID, fmt.Sprintf("%s.shard.%d", meta.VersionID, i))
		if err := os.WriteFile(shardPath, shard, 0600); err != nil {
			return false, shardsRepaired, err
		}
		shardsRepaired++
	}

	// Also write the reconstructed main file
	mainPath := filepath.Join(objectsDir, meta.ObjectID, meta.VersionID)
	if err := os.WriteFile(mainPath, reconstructed, 0600); err != nil {
		return false, shardsRepaired, err
	}

	// Update integrity hash
	if hm.bitrot != nil {
		h := sha256.New()
		f, err := os.Open(mainPath)
		if err == nil {
			io.Copy(h, f)
			f.Close()
			hash := hex.EncodeToString(h.Sum(nil))
			hm.bitrot.UpdateIntegrityHash(path, hash, meta)
		}
	}

	return true, shardsRepaired, nil
}

func (hm *HealingManager) markCorrupt(path string) {
	meta, err := hm.db.GetObjectMetadata(path)
	if err != nil {
		return
	}

	if meta.CustomMetadata == nil {
		meta.CustomMetadata = make(map[string]string)
	}
	meta.CustomMetadata["_corrupt"] = "true"
	meta.CustomMetadata["_corrupt_detected"] = time.Now().UTC().Format(time.RFC3339)
	hm.db.saveObjectMetadata(meta)
}
