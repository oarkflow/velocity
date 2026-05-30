package velocity

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"sort"
	"sync"
	"time"
)

// KGEmbedder generates vector embeddings from text.
type KGEmbedder interface {
	Embed(ctx context.Context, text string) ([]float32, error)
	EmbedBatch(ctx context.Context, texts []string) ([][]float32, error)
	Dimension() int
}

// HTTPEmbedder calls an external embedding API via HTTP POST.
type HTTPEmbedder struct {
	Endpoint  string
	Model     string
	Dim       int
	BatchSize int
	client    *http.Client
}

type embeddingRequest struct {
	Texts []string `json:"texts"`
	Model string   `json:"model,omitempty"`
	Input []string `json:"input,omitempty"`
}

type embeddingResponse struct {
	Embeddings [][]float32 `json:"embeddings,omitempty"`
	Data       []struct {
		Embedding []float32 `json:"embedding"`
	} `json:"data,omitempty"`
}

func NewHTTPEmbedder(endpoint, model string, dim int) *HTTPEmbedder {
	batchSize := 32
	if batchSize <= 0 {
		batchSize = 32
	}
	return &HTTPEmbedder{
		Endpoint:  endpoint,
		Model:     model,
		Dim:       dim,
		BatchSize: batchSize,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (e *HTTPEmbedder) Dimension() int { return e.Dim }

func (e *HTTPEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	results, err := e.EmbedBatch(ctx, []string{text})
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("empty embedding response")
	}
	return results[0], nil
}

func (e *HTTPEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, nil
	}

	var allResults [][]float32
	for i := 0; i < len(texts); i += e.BatchSize {
		end := i + e.BatchSize
		if end > len(texts) {
			end = len(texts)
		}
		batch := texts[i:end]

		req := embeddingRequest{
			Texts: batch,
			Input: batch,
			Model: e.Model,
		}
		body, err := json.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("marshal embedding request: %w", err)
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("create embedding request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := e.client.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("embedding request failed: %w", err)
		}

		var embResp embeddingResponse
		if err := json.NewDecoder(resp.Body).Decode(&embResp); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decode embedding response: %w", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("embedding API returned status %d", resp.StatusCode)
		}

		// Support both response formats
		if len(embResp.Embeddings) > 0 {
			allResults = append(allResults, embResp.Embeddings...)
		} else if len(embResp.Data) > 0 {
			for _, d := range embResp.Data {
				allResults = append(allResults, d.Embedding)
			}
		} else {
			return nil, fmt.Errorf("no embeddings in response")
		}
	}

	return allResults, nil
}

// --- HNSW Index ---

// HNSWConfig controls HNSW graph parameters.
type HNSWConfig struct {
	M              int // max connections per layer (default 16)
	EfConstruction int // beam width during insertion (default 200)
	EfSearch       int // beam width during search (default 50)
	Dimension      int // vector dimensionality
}

func (c *HNSWConfig) defaults() {
	if c.M <= 0 {
		c.M = 16
	}
	if c.EfConstruction <= 0 {
		c.EfConstruction = 200
	}
	if c.EfSearch <= 0 {
		c.EfSearch = 50
	}
}

type hnswNode struct {
	id      string
	vector  []float32
	level   int
	friends [][]string // friends[layer] = list of neighbor IDs
}

type hnswMeta struct {
	EntryPoint string `json:"entry_point"`
	MaxLevel   int    `json:"max_level"`
	NodeCount  int    `json:"node_count"`
	Dimension  int    `json:"dimension"`
}

// HNSWIndex is an in-memory HNSW graph backed by LSM-tree persistence.
type HNSWIndex struct {
	db     *DB
	config HNSWConfig
	ml     float64 // level multiplier: 1/ln(M)
	rng    *rand.Rand

	mu         sync.RWMutex
	nodes      map[string]*hnswNode
	entryPoint string
	maxLevel   int
	nodeCount  int
}

func NewHNSWIndex(db *DB, config HNSWConfig) (*HNSWIndex, error) {
	config.defaults()
	if config.Dimension <= 0 {
		return nil, fmt.Errorf("HNSW dimension must be > 0")
	}

	idx := &HNSWIndex{
		db:     db,
		config: config,
		ml:     1.0 / math.Log(float64(config.M)),
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
		nodes:  make(map[string]*hnswNode),
	}

	// Load metadata from LSM if exists
	if err := idx.loadMeta(); err != nil {
		// Fresh index, no metadata yet
		idx.entryPoint = ""
		idx.maxLevel = 0
		idx.nodeCount = 0
	}

	return idx, nil
}

func (idx *HNSWIndex) loadMeta() error {
	data, err := idx.db.Get([]byte(kgHNSWMeta))
	if err != nil {
		return err
	}
	var meta hnswMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return err
	}
	idx.entryPoint = meta.EntryPoint
	idx.maxLevel = meta.MaxLevel
	idx.nodeCount = meta.NodeCount
	return nil
}

func (idx *HNSWIndex) saveMeta() error {
	meta := hnswMeta{
		EntryPoint: idx.entryPoint,
		MaxLevel:   idx.maxLevel,
		NodeCount:  idx.nodeCount,
		Dimension:  idx.config.Dimension,
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return idx.db.Put([]byte(kgHNSWMeta), data)
}

func (idx *HNSWIndex) randomLevel() int {
	level := 0
	for idx.rng.Float64() < 1.0/float64(idx.config.M) && level < 32 {
		level++
	}
	return level
}

// Insert adds a vector to the HNSW index.
func (idx *HNSWIndex) Insert(chunkID string, vector []float32) error {
	if len(vector) != idx.config.Dimension {
		return fmt.Errorf("vector dimension %d != expected %d", len(vector), idx.config.Dimension)
	}

	idx.mu.Lock()
	defer idx.mu.Unlock()

	level := idx.randomLevel()
	node := &hnswNode{
		id:      chunkID,
		vector:  vector,
		level:   level,
		friends: make([][]string, level+1),
	}

	// Store vector in LSM
	if err := idx.persistVector(chunkID, vector); err != nil {
		return err
	}

	// First node
	if idx.nodeCount == 0 {
		idx.nodes[chunkID] = node
		idx.entryPoint = chunkID
		idx.maxLevel = level
		idx.nodeCount = 1
		return idx.saveMeta()
	}

	// Ensure entry point node is loaded
	if err := idx.ensureLoaded(idx.entryPoint); err != nil {
		return err
	}

	ep := idx.entryPoint

	// Phase 1: greedily descend from top level to insertion level+1
	for l := idx.maxLevel; l > level; l-- {
		ep = idx.greedyClosest(vector, ep, l)
	}

	// Phase 2: at each level from insertion level down to 0, find and connect neighbors
	for l := min(level, idx.maxLevel); l >= 0; l-- {
		neighbors := idx.searchLayer(vector, ep, idx.config.EfConstruction, l)
		// Select M closest
		if len(neighbors) > idx.config.M {
			neighbors = neighbors[:idx.config.M]
		}

		node.friends[l] = make([]string, len(neighbors))
		for i, n := range neighbors {
			node.friends[l][i] = n.id
		}

		// Bidirectional connections
		for _, neighbor := range neighbors {
			nNode, err := idx.getNode(neighbor.id)
			if err != nil {
				continue
			}
			if l < len(nNode.friends) {
				nNode.friends[l] = append(nNode.friends[l], chunkID)
				// Prune if exceeded M
				if len(nNode.friends[l]) > idx.config.M*2 {
					nNode.friends[l] = idx.pruneNeighbors(nNode.vector, nNode.friends[l], idx.config.M)
				}
			}
		}

		if len(neighbors) > 0 {
			ep = neighbors[0].id
		}
	}

	idx.nodes[chunkID] = node
	idx.nodeCount++

	if level > idx.maxLevel {
		idx.maxLevel = level
		idx.entryPoint = chunkID
	}

	return idx.saveMeta()
}

// Search finds the k nearest neighbors to the query vector.
func (idx *HNSWIndex) Search(query []float32, k int) ([]ScoredChunk, error) {
	if len(query) != idx.config.Dimension {
		return nil, fmt.Errorf("query dimension %d != expected %d", len(query), idx.config.Dimension)
	}

	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if idx.nodeCount == 0 || idx.entryPoint == "" {
		return nil, nil
	}

	// Ensure entry point is loaded
	if err := idx.ensureLoaded(idx.entryPoint); err != nil {
		return nil, err
	}

	ep := idx.entryPoint

	// Greedy descend from top level to layer 1
	for l := idx.maxLevel; l > 0; l-- {
		ep = idx.greedyClosest(query, ep, l)
	}

	// Beam search at layer 0
	results := idx.searchLayer(query, ep, idx.config.EfSearch, 0)

	if len(results) > k {
		results = results[:k]
	}

	scored := make([]ScoredChunk, len(results))
	for i, r := range results {
		scored[i] = ScoredChunk{
			ChunkID: r.id,
			Score:   r.dist,
			Rank:    i + 1,
		}
	}
	return scored, nil
}

// Delete removes a node from the HNSW index.
func (idx *HNSWIndex) Delete(chunkID string) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	node, ok := idx.nodes[chunkID]
	if !ok {
		return nil
	}

	// Remove from all neighbor lists
	for l := 0; l <= node.level && l < len(node.friends); l++ {
		for _, friendID := range node.friends[l] {
			if fn, ok := idx.nodes[friendID]; ok && l < len(fn.friends) {
				fn.friends[l] = removeString(fn.friends[l], chunkID)
			}
		}
	}

	delete(idx.nodes, chunkID)
	idx.nodeCount--

	// Delete vector from LSM
	_ = idx.db.Delete([]byte(kgVecPrefix + chunkID))
	_ = idx.db.Delete([]byte(kgHNSWPrefix + chunkID))

	// Update entry point if needed
	if idx.entryPoint == chunkID {
		idx.entryPoint = ""
		idx.maxLevel = 0
		for id, n := range idx.nodes {
			if n.level >= idx.maxLevel {
				idx.entryPoint = id
				idx.maxLevel = n.level
			}
		}
	}

	return idx.saveMeta()
}

// NodeCount returns the number of nodes in the index.
func (idx *HNSWIndex) NodeCount() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.nodeCount
}

// --- Internal helpers ---

type hnswCandidate struct {
	id   string
	dist float64 // cosine similarity (higher = more similar)
}

func (idx *HNSWIndex) greedyClosest(query []float32, epID string, level int) string {
	best := epID
	bestNode, err := idx.getNode(epID)
	if err != nil {
		return epID
	}
	bestDist := cosineSimilarity(query, bestNode.vector)

	changed := true
	for changed {
		changed = false
		node, err := idx.getNode(best)
		if err != nil || level >= len(node.friends) {
			break
		}
		for _, friendID := range node.friends[level] {
			fn, err := idx.getNode(friendID)
			if err != nil {
				continue
			}
			d := cosineSimilarity(query, fn.vector)
			if d > bestDist {
				bestDist = d
				best = friendID
				changed = true
			}
		}
	}
	return best
}

func (idx *HNSWIndex) searchLayer(query []float32, epID string, ef int, level int) []hnswCandidate {
	visited := make(map[string]bool)
	visited[epID] = true

	epNode, err := idx.getNode(epID)
	if err != nil {
		return nil
	}

	epDist := cosineSimilarity(query, epNode.vector)
	candidates := []hnswCandidate{{id: epID, dist: epDist}}
	results := []hnswCandidate{{id: epID, dist: epDist}}

	for len(candidates) > 0 {
		// Pop best candidate (highest similarity)
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].dist > candidates[j].dist
		})
		current := candidates[0]
		candidates = candidates[1:]

		// Worst result so far
		worstResult := results[len(results)-1].dist

		if current.dist < worstResult && len(results) >= ef {
			break
		}

		cNode, err := idx.getNode(current.id)
		if err != nil || level >= len(cNode.friends) {
			continue
		}

		for _, friendID := range cNode.friends[level] {
			if visited[friendID] {
				continue
			}
			visited[friendID] = true

			fn, err := idx.getNode(friendID)
			if err != nil {
				continue
			}
			d := cosineSimilarity(query, fn.vector)

			if len(results) < ef || d > results[len(results)-1].dist {
				candidates = append(candidates, hnswCandidate{id: friendID, dist: d})
				results = append(results, hnswCandidate{id: friendID, dist: d})
				sort.Slice(results, func(i, j int) bool {
					return results[i].dist > results[j].dist
				})
				if len(results) > ef {
					results = results[:ef]
				}
			}
		}
	}

	return results
}

func (idx *HNSWIndex) pruneNeighbors(nodeVec []float32, friendIDs []string, maxM int) []string {
	type scored struct {
		id   string
		dist float64
	}
	var scoredFriends []scored
	for _, fid := range friendIDs {
		fn, err := idx.getNode(fid)
		if err != nil {
			continue
		}
		scoredFriends = append(scoredFriends, scored{id: fid, dist: cosineSimilarity(nodeVec, fn.vector)})
	}
	sort.Slice(scoredFriends, func(i, j int) bool {
		return scoredFriends[i].dist > scoredFriends[j].dist
	})
	if len(scoredFriends) > maxM {
		scoredFriends = scoredFriends[:maxM]
	}
	result := make([]string, len(scoredFriends))
	for i, s := range scoredFriends {
		result[i] = s.id
	}
	return result
}

func (idx *HNSWIndex) getNode(id string) (*hnswNode, error) {
	if n, ok := idx.nodes[id]; ok {
		return n, nil
	}
	// Lazy load from LSM
	return idx.loadNode(id)
}

func (idx *HNSWIndex) ensureLoaded(id string) error {
	if _, ok := idx.nodes[id]; ok {
		return nil
	}
	_, err := idx.loadNode(id)
	return err
}

func (idx *HNSWIndex) loadNode(id string) (*hnswNode, error) {
	// Load vector
	vecData, err := idx.db.Get([]byte(kgVecPrefix + id))
	if err != nil {
		return nil, fmt.Errorf("load vector for %s: %w", id, err)
	}
	vec := decodeFloat32s(vecData)

	// Load adjacency list
	var friends [][]string
	adjData, err := idx.db.Get([]byte(kgHNSWPrefix + id))
	if err == nil && len(adjData) > 0 {
		_ = json.Unmarshal(adjData, &friends)
	}

	level := 0
	if len(friends) > 0 {
		level = len(friends) - 1
	}

	node := &hnswNode{
		id:      id,
		vector:  vec,
		level:   level,
		friends: friends,
	}
	idx.nodes[id] = node
	return node, nil
}

func (idx *HNSWIndex) persistVector(id string, vec []float32) error {
	return idx.db.Put([]byte(kgVecPrefix+id), encodeFloat32s(vec))
}

func (idx *HNSWIndex) persistAdjacency(id string, friends [][]string) error {
	data, err := json.Marshal(friends)
	if err != nil {
		return err
	}
	return idx.db.Put([]byte(kgHNSWPrefix+id), data)
}

// FlushAdjacency persists all in-memory adjacency lists to the LSM-tree.
func (idx *HNSWIndex) FlushAdjacency() error {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	for id, node := range idx.nodes {
		if err := idx.persistAdjacency(id, node.friends); err != nil {
			return err
		}
	}
	return nil
}

// --- Vector encoding ---

func encodeFloat32s(v []float32) []byte {
	buf := make([]byte, len(v)*4)
	for i, f := range v {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(f))
	}
	return buf
}

func decodeFloat32s(data []byte) []float32 {
	n := len(data) / 4
	v := make([]float32, n)
	for i := 0; i < n; i++ {
		v[i] = math.Float32frombits(binary.LittleEndian.Uint32(data[i*4:]))
	}
	return v
}

// --- Cosine similarity ---

func cosineSimilarity(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, normA, normB float64
	for i := range a {
		ai, bi := float64(a[i]), float64(b[i])
		dot += ai * bi
		normA += ai * ai
		normB += bi * bi
	}
	denom := math.Sqrt(normA) * math.Sqrt(normB)
	if denom == 0 {
		return 0
	}
	return dot / denom
}

// --- String helpers ---

func removeString(ss []string, target string) []string {
	result := ss[:0]
	for _, s := range ss {
		if s != target {
			result = append(result, s)
		}
	}
	return result
}
