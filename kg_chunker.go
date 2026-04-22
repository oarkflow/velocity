package velocity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// KGChunker splits document text into overlapping chunks.
type KGChunker interface {
	Chunk(docID, text string) []KGChunk
}

// SlidingWindowChunker splits text using a word-based sliding window.
type SlidingWindowChunker struct {
	MaxWords int // words per chunk (default 256)
	Overlap  int // overlap in words (default 64)
}

func NewSlidingWindowChunker(maxWords, overlap int) *SlidingWindowChunker {
	if maxWords <= 0 {
		maxWords = 256
	}
	if overlap <= 0 {
		overlap = 64
	}
	if overlap >= maxWords {
		overlap = maxWords / 4
	}
	return &SlidingWindowChunker{MaxWords: maxWords, Overlap: overlap}
}

func (c *SlidingWindowChunker) Chunk(docID, text string) []KGChunk {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}

	step := c.MaxWords - c.Overlap
	if step <= 0 {
		step = 1
	}

	var chunks []KGChunk
	idx := 0

	for start := 0; start < len(words); start += step {
		end := start + c.MaxWords
		if end > len(words) {
			end = len(words)
		}

		chunkText := strings.Join(words[start:end], " ")
		startByte, endByte := findByteOffsets(text, words, start, end)

		chunkID := generateChunkID(docID, idx)
		chunks = append(chunks, KGChunk{
			ID:        chunkID,
			DocID:     docID,
			Index:     idx,
			Text:      chunkText,
			StartByte: startByte,
			EndByte:   endByte,
		})
		idx++

		if end >= len(words) {
			break
		}
	}

	return chunks
}

func generateChunkID(docID string, index int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", docID, index)))
	return "chk-" + hex.EncodeToString(h[:8])
}

func findByteOffsets(text string, words []string, startWord, endWord int) (int, int) {
	// Walk through the text to find byte offsets for the word range
	pos := 0
	startByte := 0
	endByte := len(text)

	for i := 0; i < endWord && i < len(words); i++ {
		// Find this word in text starting from pos
		idx := strings.Index(text[pos:], words[i])
		if idx < 0 {
			break
		}
		wordStart := pos + idx
		wordEnd := wordStart + len(words[i])

		if i == startWord {
			startByte = wordStart
		}
		if i == endWord-1 {
			endByte = wordEnd
		}
		pos = wordEnd
	}

	return startByte, endByte
}
