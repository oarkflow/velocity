// Package extractor provides a pluggable content extraction system.
// Each media type is handled by a dedicated Extractor implementation
// registered in the global Registry. Callers use Extract() as the single
// entry point; the registry dispatches to the best matching extractor.
package extractor

import (
	"fmt"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// Core interface
// ---------------------------------------------------------------------------

// KGExtractor extracts plain text from raw content.
type KGExtractor interface {
	// Extract returns plain text for the given content and media type.
	// Implementations must be safe for concurrent use.
	Extract(content []byte, mediaType string) (string, error)
	// Supports reports whether this extractor handles the given (normalised)
	// media type.
	Supports(mediaType string) bool
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

// Registry holds a prioritised list of extractors. The first extractor that
// reports Supports(mediaType) == true is used.
type Registry struct {
	mu         sync.RWMutex
	extractors []KGExtractor
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register appends an extractor. Extractors registered last have lowest priority.
// To prepend (highest priority) use RegisterFront.
func (r *Registry) Register(e KGExtractor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.extractors = append(r.extractors, e)
}

// RegisterFront prepends an extractor, giving it the highest priority.
func (r *Registry) RegisterFront(e KGExtractor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.extractors = append([]KGExtractor{e}, r.extractors...)
}

// Extract dispatches to the first matching extractor.
func (r *Registry) Extract(content []byte, mediaType string) (string, error) {
	norm := NormalizeMediaType(mediaType)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.extractors {
		if e.Supports(norm) {
			return e.Extract(content, norm)
		}
	}
	return "", fmt.Errorf("kg: no extractor for media type %q", norm)
}

// Supports reports whether any registered extractor handles mediaType.
func (r *Registry) Supports(mediaType string) bool {
	norm := NormalizeMediaType(mediaType)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.extractors {
		if e.Supports(norm) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Default global registry
// ---------------------------------------------------------------------------

var defaultRegistry = buildDefaultRegistry()

func buildDefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(NewPlainTextExtractor())
	r.Register(NewHTMLExtractor())
	r.Register(NewJSONExtractor())
	r.Register(NewCSVExtractor())
	r.Register(NewEmailExtractor())
	r.Register(NewPDFExtractor())           // uses pdftotext via os/exec
	r.Register(NewOfficeExtractor())        // OOXML + legacy Office via unzip
	r.Register(NewPrintableTextExtractor()) // last-resort binary scrape
	return r
}

// Extract extracts text using the default registry.
func Extract(content []byte, mediaType string) (string, error) {
	return defaultRegistry.Extract(content, mediaType)
}

// Supports reports whether the default registry handles mediaType.
func Supports(mediaType string) bool {
	return defaultRegistry.Supports(mediaType)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// NormalizeMediaType strips parameters (e.g. "; charset=utf-8") and
// lowercases the type.
func NormalizeMediaType(mt string) string {
	mt = strings.ToLower(strings.TrimSpace(mt))
	if idx := strings.Index(mt, ";"); idx >= 0 {
		mt = mt[:idx]
	}
	return strings.TrimSpace(mt)
}
