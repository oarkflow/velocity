package main

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"strings"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/kg"
)

type textExtractor struct{}

func (textExtractor) Supports(mediaType string) bool { return true }
func (textExtractor) Extract(content []byte, mediaType string) (string, error) {
	return strings.TrimSpace(string(content)), nil
}

type ruleNER struct{}

func (ruleNER) Extract(text string) []kg.KGEntity {
	if strings.Contains(text, "Ada") {
		return []kg.KGEntity{{Surface: "Ada", Canonical: "ada lovelace", Type: "PERSON", Confidence: 0.99}}
	}
	return nil
}

type deterministicEmbedder struct{ dim int }

func (e deterministicEmbedder) Dimension() int { return e.dim }
func (e deterministicEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(text)))
	base := h.Sum32()
	vec := make([]float32, e.dim)
	for i := range vec {
		vec[i] = float32((base>>uint(i%16))&0xff) / 255
	}
	return vec, nil
}
func (e deterministicEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i, text := range texts {
		vec, err := e.Embed(ctx, text)
		if err != nil {
			return nil, err
		}
		out[i] = vec
	}
	return out, nil
}

type reverseReranker struct{}

func (reverseReranker) Rerank(ctx context.Context, query string, hits []kg.KGSearchHit) ([]kg.KGSearchHit, error) {
	for i, j := 0, len(hits)-1; i < j; i, j = i+1, j-1 {
		hits[i], hits[j] = hits[j], hits[i]
	}
	return hits, nil
}

func main() {
	ctx := context.Background()
	dir := mustTempDir()
	defer os.RemoveAll(dir)

	db, err := velocity.NewWithConfig(velocity.Config{Path: dir, DisableEncryption: true, DisableWAL: true, DisableIndexPersistence: true})
	check(err)
	defer db.Close()

	embedder := deterministicEmbedder{dim: 8}
	hnsw, err := kg.NewHNSWIndex(db, kg.HNSWConfig{M: 8, EfConstruction: 40, EfSearch: 20, Dimension: embedder.Dimension()})
	check(err)
	pipeline := kg.NewKGIngestPipeline(
		db,
		kg.WithExtractor(textExtractor{}),
		kg.WithChunker(kg.NewSlidingWindowChunker(12, 3)),
		kg.WithNER(ruleNER{}),
		kg.WithEmbedder(embedder),
		kg.WithHNSW(hnsw),
		kg.WithIngestConfig(kg.IngestConfig{Workers: 2, BatchSize: 4, SkipDuplicate: true}),
	)

	resp, err := pipeline.Ingest(ctx, &kg.KGIngestRequest{
		Source:    "memory://ada",
		MediaType: "text/plain",
		Title:     "Ada Notes",
		Content:   []byte("Ada designed analytical engine notes. Search and graph retrieval can combine keyword and vector signals."),
		Metadata:  map[string]string{"topic": "computing"},
	})
	check(err)

	search := kg.NewKGSearchEngine(db, hnsw, embedder, nil)
	search.SetReranker(reverseReranker{})
	keyword := mustKGSearch(ctx, search, &kg.KGSearchRequest{Query: "analytical engine", Mode: kg.KGSearchModeKeyword, Limit: 3})
	semantic := mustKGSearch(ctx, search, &kg.KGSearchRequest{Query: "vector retrieval", Mode: kg.KGSearchModeSemantic, EnableVector: true, Limit: 3})
	hybrid := mustKGSearch(ctx, search, &kg.KGSearchRequest{
		Query: "search retrieval", Mode: kg.KGSearchModeHybrid, EnableVector: true, EnableGraph: true,
		GraphDepth: 1, Filters: map[string]string{"topic": "computing"}, BM25Weight: 0.7, VectorWeight: 0.3, Limit: 3,
	})

	stats := pipeline.GetStats()
	doc, err := pipeline.GetDocument(resp.DocID)
	check(err)

	fmt.Printf("ingested doc=%s chunks=%d entities=%d title=%s\n", resp.DocID[:8], resp.ChunkCount, resp.EntityCount, doc.Title)
	fmt.Printf("keyword=%d semantic=%d hybrid=%d graph_nodes=%d corpus_docs=%d\n", keyword.TotalHits, semantic.TotalHits, hybrid.TotalHits, hybrid.GraphNodes, stats.Documents)
}

func mustKGSearch(ctx context.Context, engine *kg.KGSearchEngine, req *kg.KGSearchRequest) *kg.KGSearchResponse {
	resp, err := engine.Search(ctx, req)
	check(err)
	return resp
}

func mustTempDir() string {
	dir, err := os.MkdirTemp("", "velocity_kg_cookbook_")
	check(err)
	return dir
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
