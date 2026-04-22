package velocity

import (
	"strings"
	"testing"
)

func TestSlidingWindowChunker_Basic(t *testing.T) {
	chunker := NewSlidingWindowChunker(10, 3)
	// 25 words
	text := "one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twentyone twentytwo twentythree twentyfour twentyfive"
	chunks := chunker.Chunk("doc1", text)

	if len(chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}

	// Each chunk should have a unique ID
	ids := make(map[string]bool)
	for _, c := range chunks {
		if ids[c.ID] {
			t.Fatalf("duplicate chunk ID: %s", c.ID)
		}
		ids[c.ID] = true

		if c.DocID != "doc1" {
			t.Fatalf("expected DocID 'doc1', got %q", c.DocID)
		}

		words := strings.Fields(c.Text)
		if len(words) > 10 {
			t.Fatalf("chunk %d has %d words, expected <= 10", c.Index, len(words))
		}
	}
}

func TestSlidingWindowChunker_SmallText(t *testing.T) {
	chunker := NewSlidingWindowChunker(256, 64)
	text := "just a few words"
	chunks := chunker.Chunk("doc2", text)

	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk for short text, got %d", len(chunks))
	}
	if chunks[0].Text != text {
		t.Fatalf("expected chunk text to match input")
	}
}

func TestSlidingWindowChunker_EmptyText(t *testing.T) {
	chunker := NewSlidingWindowChunker(256, 64)
	chunks := chunker.Chunk("doc3", "")
	if len(chunks) != 0 {
		t.Fatal("expected no chunks for empty text")
	}
}

func TestSlidingWindowChunker_ByteOffsets(t *testing.T) {
	chunker := NewSlidingWindowChunker(3, 1)
	text := "alpha beta gamma delta epsilon"
	chunks := chunker.Chunk("doc4", text)

	for _, c := range chunks {
		if c.StartByte < 0 || c.EndByte > len(text) || c.StartByte >= c.EndByte {
			t.Fatalf("invalid byte offsets: start=%d end=%d for text len=%d", c.StartByte, c.EndByte, len(text))
		}
	}
}
