package erasure

import (
	"errors"
	"fmt"
	"sync"
)

// Galois Field GF(2^8) arithmetic, ported verbatim from v1's
// erasure_coding.go (irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1,
// 0x11d) — this is the algorithmically critical part and must not be
// reinvented; it is copied faithfully rather than rewritten.
const gfPoly = 0x11d
const gfSize = 256

var (
	gfLogTable [gfSize]int
	gfExpTable [gfSize * 2]byte
	gfInitOnce sync.Once
)

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
		gfLogTable[0] = 0
		for i := gfSize - 1; i < 2*(gfSize-1); i++ {
			gfExpTable[i] = gfExpTable[i-(gfSize-1)]
		}
	})
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	initGaloisField()
	return gfExpTable[gfLogTable[a]+gfLogTable[b]]
}

func gfInverse(a byte) byte {
	if a == 0 {
		panic("inverse of zero in GF(2^8)")
	}
	initGaloisField()
	return gfExpTable[(gfSize-1)-gfLogTable[a]]
}

func gfAdd(a, b byte) byte { return a ^ b }
func gfSub(a, b byte) byte { return a ^ b }

type gfMatrix struct {
	rows, cols int
	data       [][]byte
}

func newGFMatrix(rows, cols int) *gfMatrix {
	m := &gfMatrix{rows: rows, cols: cols}
	m.data = make([][]byte, rows)
	for i := range m.data {
		m.data[i] = make([]byte, cols)
	}
	return m
}

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

func (m *gfMatrix) subMatrix(startRow, endRow int) *gfMatrix {
	sub := newGFMatrix(endRow-startRow, m.cols)
	for i := startRow; i < endRow; i++ {
		copy(sub.data[i-startRow], m.data[i])
	}
	return sub
}

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

// invert computes the inverse of a square matrix via Gauss-Jordan
// elimination in GF(2^8).
func (m *gfMatrix) invert() (*gfMatrix, error) {
	if m.rows != m.cols {
		return nil, errors.New("cannot invert non-square matrix")
	}
	n := m.rows
	aug := newGFMatrix(n, 2*n)
	for i := 0; i < n; i++ {
		copy(aug.data[i][:n], m.data[i])
		aug.data[i][n+i] = 1
	}
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
		inv := gfInverse(aug.data[col][col])
		for j := 0; j < 2*n; j++ {
			aug.data[col][j] = gfMul(aug.data[col][j], inv)
		}
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
	result := newGFMatrix(n, n)
	for i := 0; i < n; i++ {
		copy(result.data[i], aug.data[i][n:2*n])
	}
	return result, nil
}

// Config is the data/parity shard split. Total shards = DataShards +
// ParityShards, and up to ParityShards missing/corrupt shards can be
// reconstructed.
type Config struct {
	DataShards   int
	ParityShards int
}

// DefaultConfig matches v1's default 4+2 split.
func DefaultConfig() Config { return Config{DataShards: 4, ParityShards: 2} }

func (c Config) TotalShards() int { return c.DataShards + c.ParityShards }

// Codec performs Reed-Solomon-style erasure coding over GF(2^8), ported
// from v1's ErasureEncoder.
type Codec struct {
	config     Config
	encMatrix  *gfMatrix
	parityRows *gfMatrix
}

// NewCodec builds a systematic Vandermonde-based encoder for config.
func NewCodec(config Config) (*Codec, error) {
	if config.DataShards <= 0 || config.ParityShards <= 0 {
		return nil, errors.New("data and parity shards must be positive")
	}
	if config.TotalShards() > 255 {
		return nil, errors.New("total shards cannot exceed 255 for GF(2^8)")
	}
	initGaloisField()

	vand := newVandermondeMatrix(config.TotalShards(), config.DataShards)
	topSquare := vand.subMatrix(0, config.DataShards)
	topInv, err := topSquare.invert()
	if err != nil {
		return nil, fmt.Errorf("failed to build systematic encoding matrix: %w", err)
	}
	encMatrix := vand.multiply(topInv)
	parityRows := encMatrix.subMatrix(config.DataShards, config.TotalShards())

	return &Codec{config: config, encMatrix: encMatrix, parityRows: parityRows}, nil
}

// Encode splits data into DataShards equal-size shards (zero-padded) and
// computes ParityShards parity shards, returning TotalShards() slices.
func (c *Codec) Encode(data []byte) ([][]byte, error) {
	dataLen := len(data)
	shardSize := (dataLen + c.config.DataShards - 1) / c.config.DataShards
	if shardSize == 0 {
		shardSize = 1
	}
	padded := make([]byte, shardSize*c.config.DataShards)
	copy(padded, data)

	shards := make([][]byte, c.config.TotalShards())
	for i := 0; i < c.config.DataShards; i++ {
		shards[i] = make([]byte, shardSize)
		copy(shards[i], padded[i*shardSize:(i+1)*shardSize])
	}
	for i := 0; i < c.config.ParityShards; i++ {
		shards[c.config.DataShards+i] = make([]byte, shardSize)
		for b := 0; b < shardSize; b++ {
			var val byte
			for j := 0; j < c.config.DataShards; j++ {
				val = gfAdd(val, gfMul(c.parityRows.data[i][j], shards[j][b]))
			}
			shards[c.config.DataShards+i][b] = val
		}
	}
	return shards, nil
}

// Decode reconstructs the original data (truncated to originalSize) from
// shards, where a missing/corrupt shard is represented by a nil entry.
// Returns an error if fewer than DataShards shards are present.
func (c *Codec) Decode(shards [][]byte, originalSize int) ([]byte, error) {
	if len(shards) != c.config.TotalShards() {
		return nil, fmt.Errorf("expected %d shards, got %d", c.config.TotalShards(), len(shards))
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
	if available < c.config.DataShards {
		return nil, fmt.Errorf("need at least %d shards to reconstruct, only %d available", c.config.DataShards, available)
	}
	if shardSize == 0 {
		return nil, errors.New("no valid shards found")
	}

	allDataPresent := true
	for i := 0; i < c.config.DataShards; i++ {
		if shards[i] == nil {
			allDataPresent = false
			break
		}
	}
	if allDataPresent {
		result := make([]byte, 0, shardSize*c.config.DataShards)
		for i := 0; i < c.config.DataShards; i++ {
			result = append(result, shards[i]...)
		}
		if originalSize > 0 && originalSize < len(result) {
			result = result[:originalSize]
		}
		return result, nil
	}

	subMatrixRows := make([]int, 0, c.config.DataShards)
	for i := 0; i < c.config.TotalShards() && len(subMatrixRows) < c.config.DataShards; i++ {
		if shards[i] != nil {
			subMatrixRows = append(subMatrixRows, i)
		}
	}
	subMatrix := newGFMatrix(c.config.DataShards, c.config.DataShards)
	for i, row := range subMatrixRows {
		copy(subMatrix.data[i], c.encMatrix.data[row])
	}
	decMatrix, err := subMatrix.invert()
	if err != nil {
		return nil, fmt.Errorf("failed to build decoding matrix: %w", err)
	}

	reconstructed := make([][]byte, c.config.DataShards)
	for i := 0; i < c.config.DataShards; i++ {
		reconstructed[i] = make([]byte, shardSize)
		for b := 0; b < shardSize; b++ {
			var val byte
			for j := 0; j < c.config.DataShards; j++ {
				val = gfAdd(val, gfMul(decMatrix.data[i][j], shards[subMatrixRows[j]][b]))
			}
			reconstructed[i][b] = val
		}
	}
	result := make([]byte, 0, shardSize*c.config.DataShards)
	for i := 0; i < c.config.DataShards; i++ {
		result = append(result, reconstructed[i]...)
	}
	if originalSize > 0 && originalSize < len(result) {
		result = result[:originalSize]
	}
	return result, nil
}

// Verify recomputes parity from the data shards and compares against the
// stored parity shards; all shards must be present and equal-length.
func (c *Codec) Verify(shards [][]byte) (bool, error) {
	if len(shards) != c.config.TotalShards() {
		return false, fmt.Errorf("expected %d shards, got %d", c.config.TotalShards(), len(shards))
	}
	shardSize := 0
	for _, s := range shards {
		if s == nil {
			return false, nil
		}
		if shardSize == 0 {
			shardSize = len(s)
		} else if len(s) != shardSize {
			return false, nil
		}
	}
	if shardSize == 0 {
		return false, errors.New("empty shards")
	}
	for i := 0; i < c.config.ParityShards; i++ {
		for b := 0; b < shardSize; b++ {
			var val byte
			for j := 0; j < c.config.DataShards; j++ {
				val = gfAdd(val, gfMul(c.parityRows.data[i][j], shards[j][b]))
			}
			if val != shards[c.config.DataShards+i][b] {
				return false, nil
			}
		}
	}
	return true, nil
}
