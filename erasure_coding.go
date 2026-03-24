package velocity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Galois Field GF(2^8) arithmetic with irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d)
const gfPoly = 0x11d
const gfSize = 256

var (
	gfLogTable [gfSize]int
	gfExpTable [gfSize * 2]byte
	gfInitOnce sync.Once
)

// initGaloisField precomputes log and exp tables for GF(2^8).
func initGaloisField() {
	gfInitOnce.Do(func() {
		x := 1
		for i := 0; i < gfSize-1; i++ {
			gfExpTable[i] = byte(x)
			gfLogTable[x] = i
			x <<= 1
			if x >= gfSize {
				x ^= gfPoly
			}
		}
		// gfLogTable[0] is undefined (log(0) doesn't exist), set to 0 by convention
		gfLogTable[0] = 0
		// Extend exp table for easy modular access
		for i := gfSize - 1; i < 2*(gfSize-1); i++ {
			gfExpTable[i] = gfExpTable[i-(gfSize-1)]
		}
	})
}

// gfMul multiplies two elements in GF(2^8).
func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	initGaloisField()
	logA := gfLogTable[a]
	logB := gfLogTable[b]
	return gfExpTable[logA+logB]
}

// gfDiv divides two elements in GF(2^8).
func gfDiv(a, b byte) byte {
	if b == 0 {
		panic("division by zero in GF(2^8)")
	}
	if a == 0 {
		return 0
	}
	initGaloisField()
	logA := gfLogTable[a]
	logB := gfLogTable[b]
	diff := logA - logB
	if diff < 0 {
		diff += gfSize - 1
	}
	return gfExpTable[diff]
}

// gfAdd adds two elements in GF(2^8) (XOR).
func gfAdd(a, b byte) byte {
	return a ^ b
}

// gfSub subtracts two elements in GF(2^8) (XOR, same as add in GF(2^8)).
func gfSub(a, b byte) byte {
	return a ^ b
}

// gfInverse returns the multiplicative inverse in GF(2^8).
func gfInverse(a byte) byte {
	if a == 0 {
		panic("inverse of zero in GF(2^8)")
	}
	initGaloisField()
	return gfExpTable[(gfSize-1)-gfLogTable[a]]
}

// gfMatrix represents a matrix over GF(2^8).
type gfMatrix struct {
	rows, cols int
	data       [][]byte
}

// newGFMatrix creates a new zero-filled matrix.
func newGFMatrix(rows, cols int) *gfMatrix {
	m := &gfMatrix{rows: rows, cols: cols}
	m.data = make([][]byte, rows)
	for i := range m.data {
		m.data[i] = make([]byte, cols)
	}
	return m
}

// newVandermondeMatrix creates a Vandermonde matrix with totalRows rows and dataCols columns.
// Row i contains [1, x, x^2, ..., x^(dataCols-1)] for x = i+1 in GF(2^8).
func newVandermondeMatrix(totalRows, dataCols int) *gfMatrix {
	initGaloisField()
	m := newGFMatrix(totalRows, dataCols)
	for r := 0; r < totalRows; r++ {
		x := byte(r + 1)
		val := byte(1)
		for c := 0; c < dataCols; c++ {
			m.data[r][c] = val
			val = gfMul(val, x)
		}
	}
	return m
}

// subMatrix extracts rows [startRow, endRow).
func (m *gfMatrix) subMatrix(startRow, endRow int) *gfMatrix {
	sub := newGFMatrix(endRow-startRow, m.cols)
	for i := startRow; i < endRow; i++ {
		copy(sub.data[i-startRow], m.data[i])
	}
	return sub
}

// multiply multiplies matrix m by matrix b.
func (m *gfMatrix) multiply(b *gfMatrix) *gfMatrix {
	if m.cols != b.rows {
		panic("matrix dimension mismatch for multiplication")
	}
	result := newGFMatrix(m.rows, b.cols)
	for i := 0; i < m.rows; i++ {
		for j := 0; j < b.cols; j++ {
			var val byte
			for k := 0; k < m.cols; k++ {
				val = gfAdd(val, gfMul(m.data[i][k], b.data[k][j]))
			}
			result.data[i][j] = val
		}
	}
	return result
}

// invert computes the inverse of a square matrix using Gauss-Jordan elimination in GF(2^8).
func (m *gfMatrix) invert() (*gfMatrix, error) {
	if m.rows != m.cols {
		return nil, errors.New("cannot invert non-square matrix")
	}
	n := m.rows
	// Augmented matrix [m | I]
	aug := newGFMatrix(n, 2*n)
	for i := 0; i < n; i++ {
		copy(aug.data[i][:n], m.data[i])
		aug.data[i][n+i] = 1
	}

	// Forward elimination with partial pivoting
	for col := 0; col < n; col++ {
		pivotRow := -1
		for row := col; row < n; row++ {
			if aug.data[row][col] != 0 {
				pivotRow = row
				break
			}
		}
		if pivotRow == -1 {
			return nil, errors.New("matrix is singular and cannot be inverted")
		}
		if pivotRow != col {
			aug.data[col], aug.data[pivotRow] = aug.data[pivotRow], aug.data[col]
		}
		// Scale pivot row so pivot element becomes 1
		inv := gfInverse(aug.data[col][col])
		for j := 0; j < 2*n; j++ {
			aug.data[col][j] = gfMul(aug.data[col][j], inv)
		}
		// Eliminate column in all other rows
		for row := 0; row < n; row++ {
			if row == col {
				continue
			}
			factor := aug.data[row][col]
			if factor != 0 {
				for j := 0; j < 2*n; j++ {
					aug.data[row][j] = gfSub(aug.data[row][j], gfMul(factor, aug.data[col][j]))
				}
			}
		}
	}

	// Extract the inverse from the right half
	result := newGFMatrix(n, n)
	for i := 0; i < n; i++ {
		copy(result.data[i], aug.data[i][n:2*n])
	}
	return result, nil
}

// ErasureConfig holds configuration for erasure coding.
type ErasureConfig struct {
	DataShards   int `json:"data_shards"`
	ParityShards int `json:"parity_shards"`
}

// DefaultErasureConfig returns the default 4+2 erasure coding configuration.
func DefaultErasureConfig() ErasureConfig {
	return ErasureConfig{
		DataShards:   4,
		ParityShards: 2,
	}
}

// TotalShards returns total number of shards (data + parity).
func (c ErasureConfig) TotalShards() int {
	return c.DataShards + c.ParityShards
}

// ErasureEncoder performs Reed-Solomon erasure coding over GF(2^8).
type ErasureEncoder struct {
	config     ErasureConfig
	encMatrix  *gfMatrix // full encoding matrix (totalShards x dataShards), systematic form
	parityRows *gfMatrix // parity rows only (parityShards x dataShards)
}

// NewErasureEncoder creates a new encoder with the given configuration.
func NewErasureEncoder(config ErasureConfig) (*ErasureEncoder, error) {
	if config.DataShards <= 0 || config.ParityShards <= 0 {
		return nil, errors.New("data and parity shards must be positive")
	}
	if config.TotalShards() > 255 {
		return nil, errors.New("total shards cannot exceed 255 for GF(2^8)")
	}
	initGaloisField()

	// Build a Vandermonde matrix and convert to systematic form.
	vand := newVandermondeMatrix(config.TotalShards(), config.DataShards)

	// Extract and invert the top square (dataShards x dataShards) sub-matrix
	topSquare := vand.subMatrix(0, config.DataShards)
	topInv, err := topSquare.invert()
	if err != nil {
		return nil, fmt.Errorf("failed to build systematic encoding matrix: %w", err)
	}

	// Multiply to get systematic form: top rows become identity, bottom rows are parity
	encMatrix := vand.multiply(topInv)
	parityRows := encMatrix.subMatrix(config.DataShards, config.TotalShards())

	return &ErasureEncoder{
		config:     config,
		encMatrix:  encMatrix,
		parityRows: parityRows,
	}, nil
}

// Encode splits data into data shards and computes parity shards.
// Returns totalShards slices, each of equal length.
func (e *ErasureEncoder) Encode(data []byte) ([][]byte, error) {
	dataLen := len(data)
	shardSize := (dataLen + e.config.DataShards - 1) / e.config.DataShards

	// Pad data so it's evenly divisible into data shards
	padded := make([]byte, shardSize*e.config.DataShards)
	copy(padded, data)

	// Split into data shards
	shards := make([][]byte, e.config.TotalShards())
	for i := 0; i < e.config.DataShards; i++ {
		shards[i] = make([]byte, shardSize)
		copy(shards[i], padded[i*shardSize:(i+1)*shardSize])
	}

	// Compute parity shards using the parity rows of the encoding matrix
	for i := 0; i < e.config.ParityShards; i++ {
		shards[e.config.DataShards+i] = make([]byte, shardSize)
		for byteIdx := 0; byteIdx < shardSize; byteIdx++ {
			var val byte
			for j := 0; j < e.config.DataShards; j++ {
				val = gfAdd(val, gfMul(e.parityRows.data[i][j], shards[j][byteIdx]))
			}
			shards[e.config.DataShards+i][byteIdx] = val
		}
	}

	return shards, nil
}

// Decode reconstructs original data from available shards.
// Missing/corrupted shards should be set to nil.
// originalSize is the original data length before padding.
func (e *ErasureEncoder) Decode(shards [][]byte, originalSize int) ([]byte, error) {
	if len(shards) != e.config.TotalShards() {
		return nil, fmt.Errorf("expected %d shards, got %d", e.config.TotalShards(), len(shards))
	}

	available := 0
	shardSize := 0
	for _, s := range shards {
		if s != nil {
			available++
			if shardSize == 0 {
				shardSize = len(s)
			}
		}
	}

	if available < e.config.DataShards {
		return nil, fmt.Errorf("need at least %d shards to reconstruct, only %d available",
			e.config.DataShards, available)
	}
	if shardSize == 0 {
		return nil, errors.New("no valid shards found")
	}

	// Fast path: all data shards present
	allDataPresent := true
	for i := 0; i < e.config.DataShards; i++ {
		if shards[i] == nil {
			allDataPresent = false
			break
		}
	}
	if allDataPresent {
		result := make([]byte, 0, shardSize*e.config.DataShards)
		for i := 0; i < e.config.DataShards; i++ {
			result = append(result, shards[i]...)
		}
		if originalSize > 0 && originalSize < len(result) {
			result = result[:originalSize]
		}
		return result, nil
	}

	// Reconstruction path: pick dataShards available shards
	subMatrixRows := make([]int, 0, e.config.DataShards)
	for i := 0; i < e.config.TotalShards() && len(subMatrixRows) < e.config.DataShards; i++ {
		if shards[i] != nil {
			subMatrixRows = append(subMatrixRows, i)
		}
	}

	// Build sub-matrix from encoding matrix rows corresponding to available shards
	subMatrix := newGFMatrix(e.config.DataShards, e.config.DataShards)
	for i, row := range subMatrixRows {
		copy(subMatrix.data[i], e.encMatrix.data[row])
	}

	// Invert to get the decoding matrix
	decMatrix, err := subMatrix.invert()
	if err != nil {
		return nil, fmt.Errorf("failed to build decoding matrix: %w", err)
	}

	// Reconstruct data shards
	reconstructed := make([][]byte, e.config.DataShards)
	for i := 0; i < e.config.DataShards; i++ {
		reconstructed[i] = make([]byte, shardSize)
		for byteIdx := 0; byteIdx < shardSize; byteIdx++ {
			var val byte
			for j := 0; j < e.config.DataShards; j++ {
				val = gfAdd(val, gfMul(decMatrix.data[i][j], shards[subMatrixRows[j]][byteIdx]))
			}
			reconstructed[i][byteIdx] = val
		}
	}

	result := make([]byte, 0, shardSize*e.config.DataShards)
	for i := 0; i < e.config.DataShards; i++ {
		result = append(result, reconstructed[i]...)
	}
	if originalSize > 0 && originalSize < len(result) {
		result = result[:originalSize]
	}
	return result, nil
}

// Verify checks that parity shards are consistent with data shards.
func (e *ErasureEncoder) Verify(shards [][]byte) bool {
	if len(shards) != e.config.TotalShards() {
		return false
	}
	shardSize := 0
	for _, s := range shards {
		if s == nil {
			return false
		}
		if shardSize == 0 {
			shardSize = len(s)
		} else if len(s) != shardSize {
			return false
		}
	}
	if shardSize == 0 {
		return false
	}

	// Recompute each parity shard and compare
	for i := 0; i < e.config.ParityShards; i++ {
		for byteIdx := 0; byteIdx < shardSize; byteIdx++ {
			var val byte
			for j := 0; j < e.config.DataShards; j++ {
				val = gfAdd(val, gfMul(e.parityRows.data[i][j], shards[j][byteIdx]))
			}
			if val != shards[e.config.DataShards+i][byteIdx] {
				return false
			}
		}
	}
	return true
}

// ShardMetadata stores information about erasure-coded shards for an object.
type ShardMetadata struct {
	ObjectID     string        `json:"object_id"`
	VersionID    string        `json:"version_id"`
	Path         string        `json:"path"`
	OriginalSize int           `json:"original_size"`
	ShardSize    int           `json:"shard_size"`
	Config       ErasureConfig `json:"config"`
	ShardHashes  []string      `json:"shard_hashes"` // SHA256 of each shard
}

// ErasureStore wraps a DB for erasure-coded object storage.
type ErasureStore struct {
	db      *DB
	encoder *ErasureEncoder
	config  ErasureConfig
	mu      sync.RWMutex
}

// NewErasureStore creates a new erasure-coded store.
func NewErasureStore(db *DB, config ErasureConfig) (*ErasureStore, error) {
	encoder, err := NewErasureEncoder(config)
	if err != nil {
		return nil, err
	}
	return &ErasureStore{
		db:      db,
		encoder: encoder,
		config:  config,
	}, nil
}

// erasureObjectsDir returns the objects directory path.
func (es *ErasureStore) erasureObjectsDir() string {
	if es.db.filesDir == "" {
		es.db.filesDir = filepath.Join(es.db.path, "files")
	}
	return filepath.Join(es.db.filesDir, "objects")
}

// StoreErasureCoded stores data with erasure coding, writing individual shard files.
func (es *ErasureStore) StoreErasureCoded(objectID, versionID, path string, data []byte) (*ShardMetadata, error) {
	es.mu.Lock()
	defer es.mu.Unlock()

	shards, err := es.encoder.Encode(data)
	if err != nil {
		return nil, fmt.Errorf("erasure encode failed: %w", err)
	}

	objDir := filepath.Join(es.erasureObjectsDir(), objectID)
	if err := os.MkdirAll(objDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create shard directory: %w", err)
	}

	shardHashes := make([]string, len(shards))
	for i, shard := range shards {
		shardPath := filepath.Join(objDir, fmt.Sprintf("%s.shard.%d", versionID, i))
		if err := os.WriteFile(shardPath, shard, 0600); err != nil {
			return nil, fmt.Errorf("failed to write shard %d: %w", i, err)
		}
		h := sha256.Sum256(shard)
		shardHashes[i] = hex.EncodeToString(h[:])
	}

	meta := &ShardMetadata{
		ObjectID:     objectID,
		VersionID:    versionID,
		Path:         path,
		OriginalSize: len(data),
		ShardSize:    len(shards[0]),
		Config:       es.config,
		ShardHashes:  shardHashes,
	}

	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal shard metadata: %w", err)
	}
	metaKey := fmt.Sprintf("erasure:meta:%s:%s", path, versionID)
	if err := es.db.Put([]byte(metaKey), metaBytes); err != nil {
		return nil, fmt.Errorf("failed to store shard metadata: %w", err)
	}

	return meta, nil
}

// ReadErasureCoded reads and reconstructs erasure-coded data, handling missing/corrupt shards.
func (es *ErasureStore) ReadErasureCoded(objectID, versionID, path string) ([]byte, error) {
	es.mu.RLock()
	defer es.mu.RUnlock()

	metaKey := fmt.Sprintf("erasure:meta:%s:%s", path, versionID)
	metaBytes, err := es.db.Get([]byte(metaKey))
	if err != nil {
		return nil, fmt.Errorf("shard metadata not found: %w", err)
	}

	var meta ShardMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal shard metadata: %w", err)
	}

	objDir := filepath.Join(es.erasureObjectsDir(), objectID)
	totalShards := meta.Config.TotalShards()
	shards := make([][]byte, totalShards)

	for i := 0; i < totalShards; i++ {
		shardPath := filepath.Join(objDir, fmt.Sprintf("%s.shard.%d", versionID, i))
		data, readErr := os.ReadFile(shardPath)
		if readErr != nil {
			shards[i] = nil
			continue
		}
		h := sha256.Sum256(data)
		if hex.EncodeToString(h[:]) != meta.ShardHashes[i] {
			shards[i] = nil
			continue
		}
		shards[i] = data
	}

	return es.encoder.Decode(shards, meta.OriginalSize)
}

// VerifyErasureCoded checks integrity of all shards for an object version.
func (es *ErasureStore) VerifyErasureCoded(objectID, versionID, path string) (bool, error) {
	es.mu.RLock()
	defer es.mu.RUnlock()

	metaKey := fmt.Sprintf("erasure:meta:%s:%s", path, versionID)
	metaBytes, err := es.db.Get([]byte(metaKey))
	if err != nil {
		return false, fmt.Errorf("shard metadata not found: %w", err)
	}

	var meta ShardMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return false, fmt.Errorf("failed to unmarshal shard metadata: %w", err)
	}

	objDir := filepath.Join(es.erasureObjectsDir(), objectID)
	totalShards := meta.Config.TotalShards()
	shards := make([][]byte, totalShards)

	for i := 0; i < totalShards; i++ {
		shardPath := filepath.Join(objDir, fmt.Sprintf("%s.shard.%d", versionID, i))
		data, readErr := os.ReadFile(shardPath)
		if readErr != nil {
			return false, nil
		}
		h := sha256.Sum256(data)
		if hex.EncodeToString(h[:]) != meta.ShardHashes[i] {
			return false, nil
		}
		shards[i] = data
	}

	return es.encoder.Verify(shards), nil
}

// GetShardMetadata retrieves shard metadata for an object version.
func (es *ErasureStore) GetShardMetadata(path, versionID string) (*ShardMetadata, error) {
	metaKey := fmt.Sprintf("erasure:meta:%s:%s", path, versionID)
	metaBytes, err := es.db.Get([]byte(metaKey))
	if err != nil {
		return nil, fmt.Errorf("shard metadata not found: %w", err)
	}

	var meta ShardMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal shard metadata: %w", err)
	}
	return &meta, nil
}

// RepairShards reconstructs any missing or corrupt shards and rewrites them.
// Returns the number of shards repaired.
func (es *ErasureStore) RepairShards(objectID, versionID, path string) (int, error) {
	es.mu.Lock()
	defer es.mu.Unlock()

	metaKey := fmt.Sprintf("erasure:meta:%s:%s", path, versionID)
	metaBytes, err := es.db.Get([]byte(metaKey))
	if err != nil {
		return 0, fmt.Errorf("shard metadata not found: %w", err)
	}

	var meta ShardMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return 0, fmt.Errorf("failed to unmarshal shard metadata: %w", err)
	}

	objDir := filepath.Join(es.erasureObjectsDir(), objectID)
	totalShards := meta.Config.TotalShards()
	shards := make([][]byte, totalShards)
	damaged := make([]int, 0)

	for i := 0; i < totalShards; i++ {
		shardPath := filepath.Join(objDir, fmt.Sprintf("%s.shard.%d", versionID, i))
		data, readErr := os.ReadFile(shardPath)
		if readErr != nil {
			shards[i] = nil
			damaged = append(damaged, i)
			continue
		}
		h := sha256.Sum256(data)
		if hex.EncodeToString(h[:]) != meta.ShardHashes[i] {
			shards[i] = nil
			damaged = append(damaged, i)
			continue
		}
		shards[i] = data
	}

	if len(damaged) == 0 {
		return 0, nil
	}

	// Reconstruct original data from available shards
	originalData, err := es.encoder.Decode(shards, meta.OriginalSize)
	if err != nil {
		return 0, fmt.Errorf("cannot reconstruct data for repair: %w", err)
	}

	// Re-encode to get all correct shards
	newShards, err := es.encoder.Encode(originalData)
	if err != nil {
		return 0, fmt.Errorf("re-encode failed during repair: %w", err)
	}

	// Rewrite only the damaged shards
	repaired := 0
	for _, idx := range damaged {
		shardPath := filepath.Join(objDir, fmt.Sprintf("%s.shard.%d", versionID, idx))
		if err := os.WriteFile(shardPath, newShards[idx], 0600); err != nil {
			return repaired, fmt.Errorf("failed to write repaired shard %d: %w", idx, err)
		}
		repaired++
	}

	return repaired, nil
}
