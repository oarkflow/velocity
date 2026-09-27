package search

import "strings"

const (
	defaultMaxWords = 256
	defaultOverlap  = 64
)

// chunkText splits text into overlapping chunks using a word-count
// sliding window, ported faithfully from v1's pkg/kg/chunker.go
// (SlidingWindowChunker) — a word-count window with overlap, not a
// byte/character size and not sentence-boundary detection, matching what
// v1 actually implements. overlap is fixed at defaultOverlap (64 words,
// v1's default) unless maxWords is small enough that v1's own
// "overlap >= maxWords" guard would trigger, in which case overlap is
// reduced to maxWords/4, exactly as v1 does.
func chunkText(text string, maxWords int) []string {
	if maxWords <= 0 {
		maxWords = defaultMaxWords
	}
	overlap := defaultOverlap
	if overlap >= maxWords {
		overlap = maxWords / 4
	}

	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	if len(words) <= maxWords {
		return []string{text}
	}

	step := maxWords - overlap
	if step <= 0 {
		step = 1
	}

	var chunks []string
	for start := 0; start < len(words); start += step {
		end := start + maxWords
		if end > len(words) {
			end = len(words)
		}
		chunks = append(chunks, strings.Join(words[start:end], " "))
		if end >= len(words) {
			break
		}
	}
	return chunks
}
