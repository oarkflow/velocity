package search

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// hnswConfig controls the HNSW graph parameters, ported from v1's
// pkg/kg/hnsw.go HNSWConfig.
type hnswConfig struct {
	Dimension      int
	M              int // max connections per layer
	EfConstruction int // beam width during insertion
	EfSearch       int // beam width during search
}

func (c *hnswConfig) defaults() {
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
	friends [][]string // friends[layer] = neighbor IDs
}

type hnswMeta struct {
	EntryPoint string `json:"entry_point"`
	MaxLevel   int    `json:"max_level"`
	NodeCount  int    `json:"node_count"`
	Dimension  int    `json:"dimension"`
}

const (
	vecMetaKey    = "search/vec/meta"
	vecVectorPfx  = "search/vec/vec/"
	vecAdjacency  = "search/vec/adj/"
	vecMetaDocPfx = "search/vec/meta_doc/"
)

// vectorIndex is a real multi-layer HNSW graph, ported from v1's
// pkg/kg/hnsw.go HNSWIndex, persisted through api.KVService instead of
// v1's internal Store interface.
type vectorIndex struct {
	kv     api.KVService
	config hnswConfig
	ml     float64
	rng    *rand.Rand

	mu         sync.RWMutex
	nodes      map[string]*hnswNode
	entryPoint string
	maxLevel   int
	nodeCount  int
}

func newVectorIndex(kv api.KVService, cfg hnswConfig) *vectorIndex {
	cfg.defaults()
	if cfg.Dimension <= 0 {
		cfg.Dimension = 128
	}
	return &vectorIndex{
		kv:     kv,
		config: cfg,
		ml:     1.0 / math.Log(float64(cfg.M)),
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
		nodes:  make(map[string]*hnswNode),
	}
}

func (idx *vectorIndex) loadMeta(ctx context.Context) error {
	data, found, err := idx.kv.Get(ctx, vecMetaKey)
	if err != nil {
		return err
	}
	if !found {
		return nil // fresh index
	}
	var meta hnswMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return fmt.Errorf("decode hnsw meta: %w", err)
	}
	idx.entryPoint = meta.EntryPoint
	idx.maxLevel = meta.MaxLevel
	idx.nodeCount = meta.NodeCount
	if meta.Dimension > 0 {
		idx.config.Dimension = meta.Dimension
	}
	return nil
}

func (idx *vectorIndex) saveMeta(ctx context.Context) error {
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
	return idx.kv.Put(ctx, vecMetaKey, data)
}

func (idx *vectorIndex) randomLevel() int {
	level := 0
	for idx.rng.Float64() < 1.0/float64(idx.config.M) && level < 32 {
		level++
	}
	return level
}

// Upsert inserts a new vector, or replaces an existing one (delete +
// reinsert — simple, correct, not optimized for high-churn workloads).
func (idx *vectorIndex) Upsert(ctx context.Context, id string, vec []float32, meta map[string]any) error {
	if len(vec) != idx.config.Dimension {
		return fmt.Errorf("search: vector dimension %d != expected %d", len(vec), idx.config.Dimension)
	}

	idx.mu.RLock()
	_, exists := idx.nodes[id]
	idx.mu.RUnlock()
	if !exists {
		if _, found, err := idx.kv.Get(ctx, vecVectorPfx+id); err != nil {
			return err
		} else if found {
			exists = true
		}
	}
	if exists {
		if err := idx.Delete(ctx, id); err != nil {
			return fmt.Errorf("search: upsert replace of %q: %w", id, err)
		}
	}

	if meta != nil {
		if data, err := json.Marshal(meta); err == nil {
			_ = idx.kv.Put(ctx, vecMetaDocPfx+id, data)
		}
	}

	return idx.insert(ctx, id, vec)
}

func (idx *vectorIndex) insert(ctx context.Context, chunkID string, vector []float32) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	level := idx.randomLevel()
	node := &hnswNode{id: chunkID, vector: vector, friends: make([][]string, level+1)}

	if err := idx.persistVector(ctx, chunkID, vector); err != nil {
		return err
	}

	if idx.nodeCount == 0 {
		idx.nodes[chunkID] = node
		idx.entryPoint = chunkID
		idx.maxLevel = level
		idx.nodeCount = 1
		return idx.saveMeta(ctx)
	}

	if err := idx.ensureLoaded(ctx, idx.entryPoint); err != nil {
		return err
	}

	ep := idx.entryPoint

	for l := idx.maxLevel; l > level; l-- {
		ep = idx.greedyClosest(ctx, vector, ep, l)
	}

	for l := min(level, idx.maxLevel); l >= 0; l-- {
		neighbors := idx.searchLayer(ctx, vector, ep, idx.config.EfConstruction, l)
		if len(neighbors) > idx.config.M {
			neighbors = neighbors[:idx.config.M]
		}

		node.friends[l] = make([]string, len(neighbors))
		for i, n := range neighbors {
			node.friends[l][i] = n.id
		}

		for _, neighbor := range neighbors {
			nNode, err := idx.getNode(ctx, neighbor.id)
			if err != nil {
				continue
			}
			if l < len(nNode.friends) {
				nNode.friends[l] = append(nNode.friends[l], chunkID)
				if len(nNode.friends[l]) > idx.config.M*2 {
					nNode.friends[l] = idx.pruneNeighbors(ctx, nNode.vector, nNode.friends[l], idx.config.M)
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

	return idx.saveMeta(ctx)
}

// Search performs real HNSW greedy-descent + beam search (not a linear
// scan) for the k nearest neighbors by cosine similarity.
func (idx *vectorIndex) Search(ctx context.Context, query []float32, k int) ([]api.SearchHit, error) {
	if len(query) != idx.config.Dimension {
		return nil, fmt.Errorf("search: query dimension %d != expected %d", len(query), idx.config.Dimension)
	}

	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if idx.nodeCount == 0 || idx.entryPoint == "" {
		return nil, nil
	}

	if err := idx.ensureLoaded(ctx, idx.entryPoint); err != nil {
		return nil, err
	}

	ep := idx.entryPoint
	for l := idx.maxLevel; l > 0; l-- {
		ep = idx.greedyClosest(ctx, query, ep, l)
	}

	results := idx.searchLayer(ctx, query, ep, idx.config.EfSearch, 0)
	if len(results) > k {
		results = results[:k]
	}

	hits := make([]api.SearchHit, len(results))
	for i, r := range results {
		hits[i] = api.SearchHit{Key: r.id, Score: r.dist}
	}
	return hits, nil
}

// Delete removes a node from the HNSW graph, repairing neighbor lists in
// every layer it participated in (not just tombstoning).
func (idx *vectorIndex) Delete(ctx context.Context, chunkID string) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	node, err := idx.getNodeLocked(ctx, chunkID)
	if err != nil || node == nil {
		return nil
	}

	for l := 0; l < len(node.friends); l++ {
		for _, friendID := range node.friends[l] {
			if fn, err := idx.getNodeLocked(ctx, friendID); err == nil && fn != nil && l < len(fn.friends) {
				fn.friends[l] = removeString(fn.friends[l], chunkID)
				_ = idx.persistAdjacency(ctx, fn.id, fn.friends)
			}
		}
	}

	delete(idx.nodes, chunkID)
	idx.nodeCount--
	_ = idx.kv.Delete(ctx, vecVectorPfx+chunkID)
	_ = idx.kv.Delete(ctx, vecAdjacency+chunkID)
	_ = idx.kv.Delete(ctx, vecMetaDocPfx+chunkID)

	if idx.entryPoint == chunkID {
		idx.entryPoint = ""
		idx.maxLevel = 0
		for id, n := range idx.nodes {
			level := len(n.friends) - 1
			if level >= idx.maxLevel {
				idx.entryPoint = id
				idx.maxLevel = level
			}
		}
	}

	return idx.saveMeta(ctx)
}

// --- internal helpers ---

type hnswCandidate struct {
	id   string
	dist float64 // cosine similarity, higher = more similar
}

func (idx *vectorIndex) greedyClosest(ctx context.Context, query []float32, epID string, level int) string {
	best := epID
	bestNode, err := idx.getNode(ctx, epID)
	if err != nil {
		return epID
	}
	bestDist := cosineSimilarity(query, bestNode.vector)

	changed := true
	for changed {
		changed = false
		node, err := idx.getNode(ctx, best)
		if err != nil || level >= len(node.friends) {
			break
		}
		for _, friendID := range node.friends[level] {
			fn, err := idx.getNode(ctx, friendID)
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

func (idx *vectorIndex) searchLayer(ctx context.Context, query []float32, epID string, ef int, level int) []hnswCandidate {
	visited := map[string]bool{epID: true}

	epNode, err := idx.getNode(ctx, epID)
	if err != nil {
		return nil
	}

	epDist := cosineSimilarity(query, epNode.vector)
	candidates := []hnswCandidate{{id: epID, dist: epDist}}
	results := []hnswCandidate{{id: epID, dist: epDist}}

	for len(candidates) > 0 {
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].dist > candidates[j].dist })
		current := candidates[0]
		candidates = candidates[1:]

		worstResult := results[len(results)-1].dist
		if current.dist < worstResult && len(results) >= ef {
			break
		}

		cNode, err := idx.getNode(ctx, current.id)
		if err != nil || level >= len(cNode.friends) {
			continue
		}

		for _, friendID := range cNode.friends[level] {
			if visited[friendID] {
				continue
			}
			visited[friendID] = true

			fn, err := idx.getNode(ctx, friendID)
			if err != nil {
				continue
			}
			d := cosineSimilarity(query, fn.vector)

			if len(results) < ef || d > results[len(results)-1].dist {
				candidates = append(candidates, hnswCandidate{id: friendID, dist: d})
				results = append(results, hnswCandidate{id: friendID, dist: d})
				sort.Slice(results, func(i, j int) bool { return results[i].dist > results[j].dist })
				if len(results) > ef {
					results = results[:ef]
				}
			}
		}
	}

	return results
}

func (idx *vectorIndex) pruneNeighbors(ctx context.Context, nodeVec []float32, friendIDs []string, maxM int) []string {
	type scored struct {
		id   string
		dist float64
	}
	var scoredFriends []scored
	for _, fid := range friendIDs {
		fn, err := idx.getNode(ctx, fid)
		if err != nil {
			continue
		}
		scoredFriends = append(scoredFriends, scored{id: fid, dist: cosineSimilarity(nodeVec, fn.vector)})
	}
	sort.Slice(scoredFriends, func(i, j int) bool { return scoredFriends[i].dist > scoredFriends[j].dist })
	if len(scoredFriends) > maxM {
		scoredFriends = scoredFriends[:maxM]
	}
	result := make([]string, len(scoredFriends))
	for i, s := range scoredFriends {
		result[i] = s.id
	}
	return result
}

// getNode assumes the caller holds idx.mu (read or write).
func (idx *vectorIndex) getNode(ctx context.Context, id string) (*hnswNode, error) {
	if n, ok := idx.nodes[id]; ok {
		return n, nil
	}
	return idx.loadNode(ctx, id)
}

func (idx *vectorIndex) getNodeLocked(ctx context.Context, id string) (*hnswNode, error) {
	return idx.getNode(ctx, id)
}

func (idx *vectorIndex) ensureLoaded(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	if _, ok := idx.nodes[id]; ok {
		return nil
	}
	_, err := idx.loadNode(ctx, id)
	return err
}

func (idx *vectorIndex) loadNode(ctx context.Context, id string) (*hnswNode, error) {
	vecData, found, err := idx.kv.Get(ctx, vecVectorPfx+id)
	if err != nil {
		return nil, fmt.Errorf("search: load vector for %s: %w", id, err)
	}
	if !found {
		return nil, fmt.Errorf("search: no such vector node %s", id)
	}
	vec := decodeFloat32s(vecData)

	var friends [][]string
	adjData, adjFound, err := idx.kv.Get(ctx, vecAdjacency+id)
	if err == nil && adjFound && len(adjData) > 0 {
		_ = json.Unmarshal(adjData, &friends)
	}

	node := &hnswNode{id: id, vector: vec, friends: friends}
	idx.nodes[id] = node
	return node, nil
}

func (idx *vectorIndex) persistVector(ctx context.Context, id string, vec []float32) error {
	return idx.kv.Put(ctx, vecVectorPfx+id, encodeFloat32s(vec))
}

func (idx *vectorIndex) persistAdjacency(ctx context.Context, id string, friends [][]string) error {
	data, err := json.Marshal(friends)
	if err != nil {
		return err
	}
	return idx.kv.Put(ctx, vecAdjacency+id, data)
}

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
	for i := range n {
		v[i] = math.Float32frombits(binary.LittleEndian.Uint32(data[i*4:]))
	}
	return v
}

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

func removeString(ss []string, target string) []string {
	out := ss[:0]
	for _, s := range ss {
		if s != target {
			out = append(out, s)
		}
	}
	return out
}

var _ api.VectorIndex = (*vectorIndex)(nil)
