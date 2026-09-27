package search

import (
	"context"

	"github.com/oarkflow/velocity/v2/api"
)

// entityExtraction implements api.EntityExtractionService atop the
// pattern-based NER, Jaro-Winkler resolver, and sliding-window chunker in
// this package. It has no storage dependency of its own — extraction,
// resolution, and chunking are pure text-mining transforms; a caller
// persists whatever it decides to keep via a GraphStore (see graph.go).
type entityExtraction struct {
	resolveThreshold float64
}

func newEntityExtraction(resolveThreshold float64) *entityExtraction {
	if resolveThreshold <= 0 || resolveThreshold > 1 {
		resolveThreshold = defaultResolveThreshold
	}
	return &entityExtraction{resolveThreshold: resolveThreshold}
}

func (e *entityExtraction) ExtractEntities(ctx context.Context, text string) ([]api.ExtractedEntity, error) {
	found := extractEntities(text)
	out := make([]api.ExtractedEntity, len(found))
	for i, f := range found {
		out[i] = api.ExtractedEntity{Text: f.Text, Type: f.Type, Start: f.Start, End: f.End}
	}
	return out, nil
}

// ResolveEntities clusters entityIDs by Jaro-Winkler similarity of the ID
// strings themselves (see resolver.go's doc comment for why: api.GraphStore
// entities have no mandated "surface form" field beyond their ID).
func (e *entityExtraction) ResolveEntities(ctx context.Context, entityIDs []string) ([]api.EntityResolution, error) {
	clusters := resolveClusters(entityIDs, e.resolveThreshold)
	out := make([]api.EntityResolution, 0, len(clusters))
	for _, cluster := range clusters {
		out = append(out, api.EntityResolution{
			CanonicalID: pickCanonical(cluster),
			MergedIDs:   cluster,
		})
	}
	return out, nil
}

func (e *entityExtraction) ChunkText(ctx context.Context, text string, maxWords int) ([]string, error) {
	return chunkText(text, maxWords), nil
}

var _ api.EntityExtractionService = (*entityExtraction)(nil)
