package api

import (
	"context"
	"io"
)

// ExtractedContent is the result of running ExtractorService.Extract over
// raw content of a known media type.
type ExtractedContent struct {
	Text     string
	Metadata map[string]any
}

// ExtractorService extracts plain text from raw content, ported from v1's
// pkg/extractor. See plugins/extractor's package doc for exactly which
// media types are supported in this pass and which v1 had that were
// deliberately deferred.
type ExtractorService interface {
	Extract(ctx context.Context, contentType string, r io.Reader) (ExtractedContent, error)
	SupportedTypes(ctx context.Context) ([]string, error)
}
