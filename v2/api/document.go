package api

import (
	"context"
	"encoding/json"
)

// DocumentService stores JSON documents under KVService-style keys and
// allows reading/writing a single field by dot-notation path (e.g.
// "profile.address.city", or "tags.0" for an array index), without the
// caller having to load, mutate, and re-save the whole document by hand.
// Service name: "document".
type DocumentService interface {
	// SetJSON replaces the entire document at key.
	SetJSON(ctx context.Context, key string, doc json.RawMessage) error
	// GetJSON returns the entire document at key.
	GetJSON(ctx context.Context, key string) (json.RawMessage, bool, error)

	// Get resolves a dot-notation path within the document at key (e.g.
	// "user.address.city"). A missing intermediate object, or a path that
	// doesn't exist, returns (nil, false, nil) — not an error. A numeric
	// path segment (e.g. "tags.0") indexes into a JSON array.
	Get(ctx context.Context, key, path string) (value any, ok bool, err error)

	// Set writes value at path within the document at key, creating
	// intermediate objects as needed (matching common "set a nested field"
	// semantics, e.g. lodash/jq-style path assignment). If the document at
	// key doesn't exist yet, Set creates one. Arrays are only indexed, not
	// auto-extended — writing to an out-of-range array index is an error.
	Set(ctx context.Context, key, path string, value any) error

	// Delete removes the field at path within the document at key. Deleting
	// a path that doesn't exist is not an error (idempotent).
	Delete(ctx context.Context, key, path string) error
}
