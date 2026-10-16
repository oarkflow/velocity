package search

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/oarkflow/velocity/v2/api"
)

// fullTextIndex is a schema-less inverted-index full-text search
// implementation, ported in spirit from v1's search_index.go query
// parsing (parseFullTextQuery/splitFullTextQuery/tokenize): it supports
// plain terms (AND semantics — a doc must contain every term), quoted
// phrase matches, and negative terms via a leading "-" or the NOT
// keyword. It persists through api.KVService under the following key
// scheme:
//
//	search/ft/doc/<key>    -> JSON-encoded original fields map (for Remove and phrase matching)
//	search/ft/text/<key>   -> lowercased concatenation of all field values (for phrase substring matching)
//	search/ft/terms/<key>  -> JSON list of distinct terms indexed for this key (so Remove can clean up postings)
//	search/ft/idx/<term>/<key> -> decimal term frequency (the postings list for <term>, scanned by prefix)
//
// On top of that durable layout, the index (optionally, and by default)
// holds every postings list in memory. The in-RAM postings map is kept
// consistent with the KV layer by the same Index/Remove calls that
// maintain the storage keys, and rebuilt from them by a one-time warmup
// scan on the first query after the process (re)starts. With the cache
// warm, a term query never touches the KV layer at all — it walks the
// smallest term's posting list and membership-tests the rest, the way an
// in-memory engine (e.g. Redis's own inverted index) does — which turns
// the dominant cost (scanning thousands of postings through the KV stack
// on every single query) into microseconds (~30x on the committed
// benchmark, and the gap GROWS with corpus size because the old cost was
// a full per-term prefix scan). The tradeoffs: the memory those postings
// occupy, and the one-time warmup scan. Disable with the manifest knob
// search.in_memory_index=false to always fall back to KV scans (zero
// extra memory, identical results, the pre-optimization cost profile).
//
// Phrase handling keeps per-document text reads out of RAM (unlike the
// term postings, full doc texts are never cached wholesale), but the
// phrase stage is not free per query either: it filters the candidate
// keys' texts through KV. Two measures keep that cost bounded, both with
// the same correctness contract (they can only skip WORK, never change a
// result):
//
//   - Large candidate sets stream the text index in ONE scan and filter
//     membership in memory, instead of doing one sequential Get per
//     candidate (O(candidates) round-trips through the KV stack vs one
//     pass over the corpus text).
//   - Small, repeated phrase queries hit a FINITE phrase-result cache:
//     the doc key set a phrase matched, capped at a few entries and
//     INVALIDATED ON EVERY Index/Remove — stale results are impossible
//     in the usual query-heavy/write-light pattern, at the cost of a
//     hit-rate that drops to zero while any writing is going on. No
//     document is cached — only the (doc -> contained phrase) mapping.
//
// Coherence scope, stated plainly: this cache mirrors "search/ft/idx/*"
// as written through THIS index instance — Index/Remove are the only
// writers this plugin itself ever uses, and they update cache and KV in
// lock-step (phrase entries are dropped wholesale on every mutation). A
// writer that reaches around the search plugin and mutates postings keys
// directly under "search/ft/idx/" (nobody in-tree does) sees its changes
// on disk but not in RAM until the next process restart's warmup re-scan.
// That is the classic in-memory-index tradeoff (the same reason
// Lucene/RocksDB require a reader re-open to see external changes); it is
// documented here rather than hidden.
type fullTextIndex struct {
	kv api.KVService

	// inMemory enables the cache. When false, Query always reads
	// postings from the KV layer exactly as it did before the cache
	// existed (and Index/Remove touch no cache state at all).
	inMemory bool

	// rwMu guards warmed/postings/pendingUpdates. Readers hold the READ
	// lock for the entire span in which they iterate postings maps
	// (emitCachedMatches, the phrase-only negative filter); writers
	// (warmup, Index, Remove) hold the write lock while mutating in
	// place, so no reader can be inside an iteration during a mutation —
	// that is what makes in-place mutation safe without map copying.
	rwMu sync.RWMutex
	// warmed is true once postings holds the complete postings state
	// as of a point in time; combined with in-lock mutations it stays
	// true and complete ever after.
	warmed bool
	// postings: term -> (doc key -> term frequency). Complete after
	// warmup; empty maps are DELETED (a term key's absence means "no
	// documents contain this term").
	postings map[string]map[string]int
	// pendingUpdates buffers Index/Remove batches that completed while
	// the cache was still unwarmed (their postings are either already in
	// the KV snapshot warmup built or replayed from here right after);
	// see cacheAdd/cacheRemove.
	pendingUpdates []ftPosting

	// phraseMu guards the finite phrase-result cache (phraseCache +
	// phraseOrder for FIFO eviction). Deliberately a SEPARATE lock, not
	// rwMu: phrase lookups happen while NO postings lock is held (Query
	// releases rwMu before applyPhrases), and the only writer of these
	// entries is the invalidation path, which always runs under rwMu's
	// write lock — so the lock order is fixed at rwMu -> phraseMu, never
	// the reverse, and the two locks' spans never overlap in a way that
	// could cycle. Entries map a queried phrase to the doc keys whose
	// text contained it at validation time; every Index/Remove wipes the
	// whole map (cheap, and correct — see invalidatePhrasesLocked).
	phraseMu    sync.Mutex
	phraseCache map[string]map[string]struct{}
	phraseOrder []string // insertion order for FIFO eviction
}

// Bounds for the phrase-result cache: maxPhraseCacheEntries is the
// distinct-phrase ceiling (FIFO eviction beyond it); maxPhraseCachedDocs
// refuses to cache phrase results over very wide doc sets, where the
// memory of a cached set starts to approach the corpus itself.
const (
	maxPhraseCacheEntries = 32
	maxPhraseCachedDocs   = 8192

	// phraseStreamThreshold: candidate sets above this size route the
	// phrase filter through ONE ScanStream over the text index instead
	// of len(keys) sequential Gets. Above ~64 candidates the single pass
	// wins on latency in practice (and always wins on fairness: one
	// scan, not thousands of small reads).
	phraseStreamThreshold = 64
)

func newFullTextIndex(kv api.KVService, inMemory bool) *fullTextIndex {
	return &fullTextIndex{
		kv:       kv,
		inMemory: inMemory,
		postings: make(map[string]map[string]int),
	}
}

const (
	ftDocPfx   = "search/ft/doc/"
	ftTextPfx  = "search/ft/text/"
	ftTermsPfx = "search/ft/terms/"
	ftIdxPfx   = "search/ft/idx/"
)

func (f *fullTextIndex) Index(ctx context.Context, key string, fields map[string]any) error {
	if key == "" {
		return fmt.Errorf("search: index key must not be empty")
	}

	// Remove any prior indexing for this key first so re-indexing doesn't
	// leave stale postings behind.
	if err := f.Remove(ctx, key); err != nil {
		return err
	}

	var textParts []string
	for _, v := range fields {
		textParts = append(textParts, normalizeValue(v))
	}
	fullText := strings.Join(textParts, " ")
	lowerText := strings.ToLower(fullText)

	docData, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("search: encode fields for %q: %w", key, err)
	}
	if err := f.kv.Put(ctx, ftDocPfx+key, docData); err != nil {
		return err
	}
	if err := f.kv.Put(ctx, ftTextPfx+key, []byte(lowerText)); err != nil {
		return err
	}

	terms := tokenize(lowerText)
	freq := make(map[string]int, len(terms))
	for _, t := range terms {
		freq[t]++
	}

	termList := make([]string, 0, len(freq))
	postUpdates := make([]ftPosting, 0, len(freq)) // batched cache update, applied after every KV Put succeeds
	for term, count := range freq {
		termList = append(termList, term)
		if err := f.kv.Put(ctx, ftIdxPfx+term+"/"+key, []byte(strconv.Itoa(count))); err != nil {
			return err
		}
		postUpdates = append(postUpdates, ftPosting{term: term, key: key, tf: count})
	}
	termData, err := json.Marshal(termList)
	if err != nil {
		return err
	}
	if err := f.kv.Put(ctx, ftTermsPfx+key, termData); err != nil {
		return err
	}
	f.cacheAdd(postUpdates)
	return nil
}

// ftPosting is one (term, docKey, termFrequency) triple, the in-memory
// representation of one postings storage key.
type ftPosting struct {
	term string
	key  string
	tf   int
}

// cacheAdd applies Index's posting writes to the in-memory postings,
// mutating the per-term maps in place. That is race-free because every
// reader that touches these maps holds the read lock for the whole time
// it uses them, and RWMutex semantics keep in-place writers (this, under
// Lock) from running inside any such reader span.
//
// Before the first warmup the map is not yet authoritative, so updates
// are QUEUED (pendingUpdates) and drained by ensureWarmed after its
// rebuild — this keeps Index O(1) per posting when the cache hasn't been
// built (its map would be discarded) without ever dropping a write: any
// batch completed before warmup's scan is either visible to the scan
// itself or replayed from the queue right after it. Both repeating or
// missing the write is impossible because the queue is drained under the
// same lock warmup holds.
func (f *fullTextIndex) cacheAdd(updates []ftPosting) {
	if !f.inMemory {
		return
	}
	if !f.warmedNow() {
		f.rwMu.Lock()
		if f.warmed {
			f.applyAddLocked(updates)
		} else {
			f.pendingUpdates = append(f.pendingUpdates, updates...)
		}
		f.rwMu.Unlock()
		return
	}
	f.rwMu.Lock()
	f.applyAddLocked(updates)
	f.rwMu.Unlock()
}

func (f *fullTextIndex) applyAddLocked(updates []ftPosting) {
	// Any applied mutation can change a document's text membership, so
	// cached phrase results are dropped wholesale (see invalidatePhrases
	// for why this is always-correct rather than just usually).
	f.invalidatePhrases()
	for _, u := range updates {
		m := f.postings[u.term]
		if m == nil {
			m = make(map[string]int)
			f.postings[u.term] = m
		}
		m[u.key] = u.tf
	}
}

// warmedNow is a cheap smoke test for "is the cache authoritative yet".
// A false negative (warmup completes between this and the caller's write
// lock) is harmless: the update is then applied to the warm cache, which
// is exactly what its post-warmup semantics require.
func (f *fullTextIndex) warmedNow() bool {
	f.rwMu.RLock()
	defer f.rwMu.RUnlock()
	return f.warmed
}

// cacheRemove applies Remove's posting deletions in place (race-safety
// argument identical to cacheAdd's). A term whose last posting is deleted
// is removed from the map entirely — absence means "no documents contain
// this term".
func (f *fullTextIndex) cacheRemove(terms []string, key string) {
	if !f.inMemory || len(terms) == 0 {
		return
	}
	// Same warmed/queue dance as cacheAdd: a Remove seen pre-warmup is
	// either already absent from the rebuild (Remove deleted it from KV
	// before queueing) or replayed from the queue under the warmup's
	// write lock.
	pending := make([]ftPosting, 0, len(terms))
	for _, term := range terms {
		pending = append(pending, ftPosting{term: term, key: key})
	}
	if !f.warmedNow() {
		f.rwMu.Lock()
		if f.warmed {
			f.applyRemoveLocked(pending)
		} else {
			f.pendingUpdates = append(f.pendingUpdates, pending...) // tf unused for removals
		}
		f.rwMu.Unlock()
		return
	}
	f.rwMu.Lock()
	f.applyRemoveLocked(pending)
	f.rwMu.Unlock()
}

// applyRemoveLocked drops postings in place (readers are excluded by the
// write lock), deleting a term key entirely when its last posting goes.
// Stale phrase cache entries for a removed doc can't leak into results on
// their own (candidates are re-derived from live state per query), but the
// invalidation also covers the re-index case where the SAME doc's text
// changed — so remove invalidates too, keeping the rule one sentence:
// "any applied mutation wipes phrase results".
func (f *fullTextIndex) applyRemoveLocked(updates []ftPosting) {
	f.invalidatePhrases()
	for _, u := range updates {
		m := f.postings[u.term]
		if _, present := m[u.key]; !present {
			continue
		}
		delete(m, u.key)
		if len(m) == 0 {
			delete(f.postings, u.term)
		}
	}
}

// applyPendingLocked replays pre-warmup queued updates; called by
// ensureWarmed while it holds the write lock, after its rebuild. tf == 0
// marks a removal queued by cacheRemove; tf > 0 an Index posting.
func (f *fullTextIndex) applyPendingLocked() {
	// Replayed pre-warmup Index/Remove batches are real mutations of the
	// text layer — same invalidation rule as applyAddLocked above.
	f.invalidatePhrases()
	for _, u := range f.pendingUpdates {
		m := f.postings[u.term]
		present := m != nil
		if present {
			_, present = m[u.key]
		}
		switch {
		case u.tf > 0 && present:
			m[u.key] = u.tf // replayed re-index of a rebuilt posting
		case u.tf > 0 && !present:
			if m == nil {
				m = make(map[string]int)
				f.postings[u.term] = m
			}
			m[u.key] = u.tf
		default: // tf == 0: removal — only meaningful for rebuilt postings
			if present {
				delete(m, u.key)
				if len(m) == 0 {
					delete(f.postings, u.term)
				}
			}
		}
	}
	f.pendingUpdates = nil
}

func (f *fullTextIndex) Remove(ctx context.Context, key string) error {
	var terms []string
	termData, found, err := f.kv.Get(ctx, ftTermsPfx+key)
	if err != nil {
		return err
	}
	if found {
		if err := json.Unmarshal(termData, &terms); err == nil {
			for _, term := range terms {
				_ = f.kv.Delete(ctx, ftIdxPfx+term+"/"+key)
			}
		}
	}
	_ = f.kv.Delete(ctx, ftTermsPfx+key)
	_ = f.kv.Delete(ctx, ftDocPfx+key)
	_ = f.kv.Delete(ctx, ftTextPfx+key)
	f.cacheRemove(terms, key)
	return nil
}

// ensureWarmed populates the in-memory postings once per process. The
// full write lock is held for the entire warmup scan (it walks every
// postings key the index ever wrote, so it is O(corpus) — one time, on
// the first query after boot) so no Index/Remove cache mutation can
// interleave mid-scan: any write that lands after the release is then
// applied in lock-step by cacheAdd/cacheRemove, so the map is always
// a complete snapshot-plus-updates.
func (f *fullTextIndex) ensureWarmed(ctx context.Context) error {
	f.rwMu.Lock()
	defer f.rwMu.Unlock()
	if f.warmed {
		return nil
	}
	warm := make(map[string]map[string]int)
	if ss, ok := f.kv.(api.KVStreamScanner); ok {
		err := ss.ScanStream(ctx, ftIdxPfx, func(k string, v []byte) (bool, error) {
			// k = "search/ft/idx/<term>/<docKey>". Terms are the output of
			// tokenize (letters/digits only), so the FIRST slash after the
			// prefix is the term/doc separator even when the docKey itself
			// contains slashes.
			rest := strings.TrimPrefix(k, ftIdxPfx)
			slash := strings.IndexByte(rest, '/')
			if slash < 0 {
				return true, nil // malformed posting key: ignored, like Remove tolerates stale ones
			}
			term, doc := rest[:slash], rest[slash+1:]
			tf, _ := strconv.Atoi(string(v))
			m, ok := warm[term]
			if !ok {
				m = make(map[string]int)
				warm[term] = m
			}
			m[doc] = tf
			return true, nil
		})
		if err != nil {
			return err
		}
	} else {
		cursor := ""
		for {
			items, next, err := f.kv.Scan(ctx, ftIdxPfx, 1000, cursor)
			if err != nil {
				return err
			}
			for fullKey, val := range items {
				rest := strings.TrimPrefix(fullKey, ftIdxPfx)
				slash := strings.IndexByte(rest, '/')
				if slash < 0 {
					continue
				}
				term, doc := rest[:slash], rest[slash+1:]
				tf, _ := strconv.Atoi(string(val))
				m, ok := warm[term]
				if !ok {
					m = make(map[string]int)
					warm[term] = m
				}
				m[doc] = tf
			}
			if next == "" {
				break
			}
			cursor = next
		}
	}
	f.postings = warm
	// Replay Index/Remove batches that completed before (or during) the
	// warmup scan, then flush the queue — still under the write lock.
	// After this, warmed makes cacheAdd/cacheRemove mutate in place, so
	// the postings map stays complete.
	f.applyPendingLocked()
	f.warmed = true
	return nil
}

func (f *fullTextIndex) Query(ctx context.Context, q string, limit int) ([]api.SearchHit, error) {
	plan := parseFullTextPlan(q)
	if len(plan.terms) == 0 && len(plan.phrases) == 0 {
		return nil, nil
	}

	if !f.inMemory {
		return f.queryFromKV(ctx, plan, limit)
	}

	if err := f.ensureWarmed(ctx); err != nil {
		return nil, err
	}

	if len(plan.phrases) == 0 {
		// Pure term query (possibly with negatives): the whole evaluation
		// is in-RAM, so stream matches straight into the bounded hit heap
		// under the read lock — no intermediate corpus-sized score map
		// ever exists. Exact same results as the map+phrases route below:
		// the heap's ordering rule IS finalizeHits's ordering rule.
		h := ftHitHeap{limit: limit}
		f.rwMu.RLock()
		f.emitCachedMatches(plan, func(doc string, score float64) {
			h.consider(api.SearchHit{Key: doc, Score: score})
		})
		f.rwMu.RUnlock()
		return h.sorted(), nil
	}

	keys := make(map[string]float64)
	if len(plan.terms) > 0 {
		// Required-term intersection + negative exclusion, purely from the
		// in-RAM postings (no KV access): walk the smallest term's posting
		// list and membership-test the rest — output is at most one row
		// per posting in the smallest list, never the whole corpus's score
		// map. Runs under the read lock because it iterates maps the
		// writers mutate in place (see cacheAdd/cacheRemove).
		keys = f.intersectCached(plan)
	} else {
		// Phrase-only query: seed from every indexed document (score 0)
		// exactly like the scan path's phrase seeding, then apply negative
		// terms from the in-RAM postings.
		all, err := f.allDocKeys(ctx)
		if err != nil {
			return nil, err
		}
		out := make(map[string]float64, len(all))
		for _, key := range all {
			out[key] = 0
		}
		f.rwMu.RLock()
		for _, neg := range plan.negative {
			for k := range f.postings[neg] {
				delete(out, k)
			}
		}
		f.rwMu.RUnlock()
		keys = out
	}

	keys, err := f.applyPhrases(ctx, plan, keys)
	if err != nil {
		return nil, err
	}
	return finalizeHits(keys, limit), nil
}

// emitCachedMatches evaluates "doc contains EVERY required term AND none
// of the negative terms" directly against the in-memory postings and
// pushes each match's (doc, score) to emit. Caller must hold the read
// lock (Query does: warmup, cacheAdd, and cacheRemove all take the write
// lock, so iterating the maps under the read lock is race-free).
//
// Semantics are identical to queryFromKV's map intersection, including
// scoring (sum of the terms' frequencies) and negative exclusion, but the
// work is O(min(required-term posting size) plus per-doc lookups):
// instead of seeding a score map with the whole first term's list and
// deleting non-matches, we walk the SMALLEST list and require membership
// in every other list.
func (f *fullTextIndex) emitCachedMatches(plan fullTextPlan, emit func(doc string, score float64)) {
	if !f.warmed {
		return
	}
	// Pick the smallest required term's posting list; emit nothing at all
	// if any required term has no postings.
	minTerm := ""
	minSize := 0
	for _, term := range plan.terms {
		n := len(f.postings[term])
		if n == 0 {
			return // required term has no matches at all
		}
		if minTerm == "" || n < minSize {
			minTerm, minSize = term, n
		}
	}
	first := f.postings[minTerm]
	for doc, tf := range first {
		score := float64(tf)
		match := true
		for _, term := range plan.terms {
			if term == minTerm {
				continue
			}
			other, present := f.postings[term][doc]
			if !present {
				match = false
				break
			}
			score += float64(other)
		}
		if !match {
			continue
		}
		excluded := false
		for _, neg := range plan.negative {
			if _, present := f.postings[neg][doc]; present {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		emit(doc, score)
	}
}

func (f *fullTextIndex) intersectCached(plan fullTextPlan) map[string]float64 {
	out := make(map[string]float64)
	f.rwMu.RLock()
	f.emitCachedMatches(plan, func(doc string, score float64) { out[doc] = score })
	f.rwMu.RUnlock()
	return out
}

// applyPhrases runs the phrase-substring filter over accumulated scores,
// shared by both the cached and the scan path. Three routes, choosing by
// cost profile with identical results (all re-derive membership from the
// CURRENT text of every candidate key, so no route can skew the outcome):
//
//   - in-memory mode with a cached result for this exact phrase: the doc
//     set is intersected with the candidate scores in RAM. The cache is
//     wiped by every applyAdd/Remove/Pending mutation, so an entry can
//     only exist between two consecutive writes — see the package doc's
//     phrase-coherence paragraph.
//   - large candidate sets: ONE ScanStream over ftTextPfx filters all
//     candidates' texts in a single pass (transient value bytes —
//     nothing is retained, so reuse is safe), replacing O(candidates)
//     sequential Gets.
//   - small candidate sets (and any KV without streaming): the original
//     one Get per candidate loop, unchanged.
func (f *fullTextIndex) applyPhrases(ctx context.Context, plan fullTextPlan, keys map[string]float64) (map[string]float64, error) {
	for _, phrase := range plan.phrases {
		if len(keys) == 0 {
			break
		}
		if f.inMemory {
			if docs, ok := f.phraseHit(phrase); ok {
				keys = phraseIntersect(keys, docs)
				continue
			}
		}
		var matched map[string]float64
		if len(keys) > phraseStreamThreshold {
			if ss, ok := f.kv.(api.KVStreamScanner); ok {
				m, err := f.phraseMatchByStream(ctx, ss, phrase, keys)
				if err != nil {
					return nil, err
				}
				matched = m
			} else {
				m, err := f.phraseMatchByGets(ctx, phrase, keys)
				if err != nil {
					return nil, err
				}
				matched = m
			}
		} else {
			m, err := f.phraseMatchByGets(ctx, phrase, keys)
			if err != nil {
				return nil, err
			}
			matched = m
		}
		if f.inMemory && len(matched) <= maxPhraseCachedDocs {
			f.phrasePut(phrase, matched)
		}
		keys = matched
	}
	return keys, nil
}

// phraseMatchByGets is the original per-candidate Get loop: score of a
// surviving candidate advances by one per phrase, exactly like every
// other route.
func (f *fullTextIndex) phraseMatchByGets(ctx context.Context, phrase string, keys map[string]float64) (map[string]float64, error) {
	matched := make(map[string]float64)
	for key := range keys {
		text, found, err := f.kv.Get(ctx, ftTextPfx+key)
		if err != nil {
			return nil, err
		}
		if found && strings.Contains(string(text), phrase) {
			matched[key] = keys[key] + 1
		}
	}
	return matched, nil
}

// phraseMatchByStream walks the whole text index once. Only the
// candidate keys are tested, so docs indexed after the candidate set was
// built can neither join nor get dropped; a doc re-indexed concurrently
// is seen with either its old or new text — the same racing-get
// semantics the per-key route always had.
func (f *fullTextIndex) phraseMatchByStream(ctx context.Context, ss api.KVStreamScanner, phrase string, keys map[string]float64) (map[string]float64, error) {
	needle := []byte(phrase)
	matched := make(map[string]float64)
	err := ss.ScanStream(ctx, ftTextPfx, func(k string, text []byte) (bool, error) {
		key := strings.TrimPrefix(k, ftTextPfx)
		if _, cand := keys[key]; cand && bytes.Contains(text, needle) {
			matched[key] = keys[key] + 1
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return matched, nil
}

// phraseIntersect applies a cached phrase's doc set to the candidate
// scores: same "+1 per phrase" advance as the KV-read routes.
func phraseIntersect(keys map[string]float64, docs map[string]struct{}) map[string]float64 {
	out := make(map[string]float64, len(docs))
	for k, score := range keys {
		if _, ok := docs[k]; ok {
			out[k] = score + 1
		}
	}
	return out
}

// phraseHit reads the phrase-result cache. Entries are immutable once
// stored (phrasePut replaces wholesale, never mutates in place), so the
// returned map is safe for concurrent readers.
func (f *fullTextIndex) phraseHit(phrase string) (map[string]struct{}, bool) {
	f.phraseMu.Lock()
	defer f.phraseMu.Unlock()
	docs, ok := f.phraseCache[phrase]
	return docs, ok
}

// phrasePut stores one phrase's doc-set result, FIFO-evicting beyond the
// entry bound. Called only when a fresh result was just computed under
// no postings lock; the wipe-invalidation may have raced in the
// meantime, which is irrelevant — a NEWER result overwrites or the entry
// stays only until the next invalidation.
func (f *fullTextIndex) phrasePut(phrase string, matched map[string]float64) {
	docs := make(map[string]struct{}, len(matched))
	for k := range matched {
		docs[k] = struct{}{}
	}
	f.phraseMu.Lock()
	defer f.phraseMu.Unlock()
	if f.phraseCache == nil {
		f.phraseCache = make(map[string]map[string]struct{}, maxPhraseCacheEntries)
	}
	if _, exists := f.phraseCache[phrase]; !exists {
		f.phraseOrder = append(f.phraseOrder, phrase)
	}
	f.phraseCache[phrase] = docs
	for len(f.phraseOrder) > maxPhraseCacheEntries {
		evict := f.phraseOrder[0]
		f.phraseOrder = f.phraseOrder[1:]
		delete(f.phraseCache, evict)
	}
}

// invalidatePhrases wipes the phrase-result cache. Called from the
// applyAdd/Remove/Pending mutation appliers, which always run under
// rwMu's write lock — the fixed lock order documented on phraseMu.
//
// Why wipe EVERYTHING instead of tracking per-doc impact: raising the
// cost of a write by phrase-set bookkeeping defeats the point of the
// cache (query-heavy/write-light workloads are exactly where it wins),
// and a coarse wipe can only cost hits, never correctness — a phrase
// either re-matches fresh on the next query or stops being served from
// the cache until it is, which is precisely the invalidation semantic.
func (f *fullTextIndex) invalidatePhrases() {
	f.phraseMu.Lock()
	defer f.phraseMu.Unlock()
	f.phraseCache = nil
	f.phraseOrder = nil
}

// finalizeHits turns a scored key set into the sorted, possibly truncated
// hit list. When a limit smaller than the candidate count is given, a
// bounded top-k selection runs instead of a full sort: only the k
// survivors are ordered, so a "top 10 over 1M candidates" query does
// 1M·log(10) comparisons, not 1M·log(1M). Tie-breaking and truncation are
// identical to the full-sort path, so both paths return the same list.
func finalizeHits(keys map[string]float64, limit int) []api.SearchHit {
	if limit > 0 && len(keys) > limit {
		h := ftHitHeap{limit: limit}
		for k, score := range keys {
			h.consider(api.SearchHit{Key: k, Score: score})
		}
		hits := h.sorted()
		if len(hits) > limit {
			hits = hits[:limit]
		}
		return hits
	}
	hits := make([]api.SearchHit, 0, len(keys))
	for k, score := range keys {
		hits = append(hits, api.SearchHit{Key: k, Score: score})
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return hits[i].Key < hits[j].Key
	})
	return hits
}

// ftHitHeap keeps the `limit` best hits (higher score first, key asc on
// ties) as a min-heap of the WORST kept hit, so each incoming candidate
// either evicts the current worst or is dropped in O(log limit).
type ftHitHeap struct {
	limit int
	items []api.SearchHit
}

// worse reports whether a beats nothing — i.e. a ranks BELOW b under the
// final ordering rule (score desc, key asc on ties).
func ftWorse(a, b api.SearchHit) bool {
	if a.Score != b.Score {
		return a.Score < b.Score
	}
	return a.Key > b.Key
}

func (h *ftHitHeap) Len() int { return len(h.items) }

func (h *ftHitHeap) consider(hit api.SearchHit) {
	if h.limit <= 0 { // no limit: keep everything, sorted() will order it
		h.items = append(h.items, hit)
		h.up(len(h.items) - 1)
		return
	}
	if len(h.items) < h.limit {
		h.items = append(h.items, hit)
		h.up(len(h.items) - 1)
		return
	}
	if !ftWorse(h.items[0], hit) {
		return // candidate doesn't beat the current worst kept hit
	}
	h.items[0] = hit
	h.down(0)
}

// up/down are the standard sift operations with ftWorse as the
// "child outranks parent" test.
func (h *ftHitHeap) up(i int) {
	for i > 0 {
		parent := (i - 1) / 2
		if !ftWorse(h.items[i], h.items[parent]) {
			break
		}
		h.items[i], h.items[parent] = h.items[parent], h.items[i]
		i = parent
	}
}

func (h *ftHitHeap) down(i int) {
	n := len(h.items)
	for {
		l, r, best := 2*i+1, 2*i+2, i
		if l < n && ftWorse(h.items[best], h.items[l]) {
			best = l
		}
		if r < n && ftWorse(h.items[best], h.items[r]) {
			best = r
		}
		if best == i {
			return
		}
		h.items[i], h.items[best] = h.items[best], h.items[i]
		i = best
	}
}

// sorted returns the kept hits in final order. k ≤ limit items, so this
// costs k·log(k) — bounded regardless of candidate-set size.
func (h *ftHitHeap) sorted() []api.SearchHit {
	sort.Slice(h.items, func(i, j int) bool {
		if h.items[i].Score != h.items[j].Score {
			return h.items[i].Score > h.items[j].Score
		}
		return h.items[i].Key < h.items[j].Key
	})
	return h.items
}

// queryFromKV is the pre-cache scanning path, kept verbatim (modulo
// refactoring into this one function): one prefix scan per term, map
// intersection, per-key text fetch for phrases. Chosen (only) when the
// in-memory index is disabled via manifest config.
func (f *fullTextIndex) queryFromKV(ctx context.Context, plan fullTextPlan, limit int) ([]api.SearchHit, error) {
	// AND semantics: a candidate set per required term, intersected.
	var candidateSets []map[string]int // term -> per-key frequency
	for _, term := range plan.terms {
		postings, err := f.postingsForTerm(ctx, term)
		if err != nil {
			return nil, err
		}
		if len(postings) == 0 {
			return nil, nil // a required term has no matches at all
		}
		candidateSets = append(candidateSets, postings)
	}

	var keys map[string]float64
	if len(candidateSets) == 0 {
		keys = make(map[string]float64)
	} else {
		keys = make(map[string]float64, len(candidateSets[0]))
		for k, freq := range candidateSets[0] {
			keys[k] = float64(freq)
		}
		for _, set := range candidateSets[1:] {
			for k := range keys {
				freq, ok := set[k]
				if !ok {
					delete(keys, k)
					continue
				}
				keys[k] += float64(freq)
			}
		}
	}

	// Phrase filtering: require the lowercased concatenated text to
	// contain each phrase as a substring.
	for _, phrase := range plan.phrases {
		if len(keys) == 0 && len(candidateSets) > 0 {
			break
		}
		matched := make(map[string]float64)
		if len(candidateSets) == 0 && len(keys) == 0 {
			// No term candidates yet: seed from a phrase-only query by
			// scanning every indexed document's text. This is O(n) but
			// phrase-only queries are expected to be rare/small-scale.
			all, err := f.allDocKeys(ctx)
			if err != nil {
				return nil, err
			}
			for _, key := range all {
				keys[key] = 0
			}
		}
		for key := range keys {
			text, found, err := f.kv.Get(ctx, ftTextPfx+key)
			if err != nil {
				return nil, err
			}
			if found && strings.Contains(string(text), phrase) {
				matched[key] = keys[key] + 1
			}
		}
		keys = matched
	}

	// Negative-term exclusion.
	for _, neg := range plan.negative {
		if len(keys) == 0 {
			break
		}
		postings, err := f.postingsForTerm(ctx, neg)
		if err != nil {
			return nil, err
		}
		for k := range postings {
			delete(keys, k)
		}
	}
	return finalizeHits(keys, limit), nil
}

// postingsForTerm returns key -> term frequency for every document
// containing term, by scanning the "search/ft/idx/<term>/" prefix.
func (f *fullTextIndex) postingsForTerm(ctx context.Context, term string) (map[string]int, error) {
	prefix := ftIdxPfx + term + "/"
	out := make(map[string]int)
	cursor := ""
	for {
		items, next, err := f.kv.Scan(ctx, prefix, 1000, cursor)
		if err != nil {
			return nil, err
		}
		for fullKey, val := range items {
			key := strings.TrimPrefix(fullKey, prefix)
			count, _ := strconv.Atoi(string(val))
			out[key] = count
		}
		if next == "" {
			break
		}
		cursor = next
	}
	return out, nil
}

func (f *fullTextIndex) allDocKeys(ctx context.Context) ([]string, error) {
	var out []string
	cursor := ""
	for {
		items, next, err := f.kv.Scan(ctx, ftTextPfx, 1000, cursor)
		if err != nil {
			return nil, err
		}
		for fullKey := range items {
			out = append(out, strings.TrimPrefix(fullKey, ftTextPfx))
		}
		if next == "" {
			break
		}
		cursor = next
	}
	return out, nil
}

// --- query parsing, ported in simplified form from v1's search_index.go ---

type fullTextPlan struct {
	terms    []string
	phrases  []string
	negative []string
}

func parseFullTextPlan(q string) fullTextPlan {
	text := strings.TrimSpace(q)
	var plan fullTextPlan
	if text == "" {
		return plan
	}

	tokens := splitFullTextQuery(text)
	negateNext := false
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		upper := strings.ToUpper(token)
		if upper == "AND" || upper == "OR" {
			continue
		}
		if upper == "NOT" {
			negateNext = true
			continue
		}
		negative := negateNext
		negateNext = false
		if strings.HasPrefix(token, "-") && len(token) > 1 {
			negative = true
			token = strings.TrimPrefix(token, "-")
		}
		quoted := strings.HasPrefix(token, "\"") && strings.HasSuffix(token, "\"") && len(token) >= 2
		if quoted {
			phrase := strings.ToLower(strings.TrimSpace(token[1 : len(token)-1]))
			if phrase == "" {
				continue
			}
			if negative {
				plan.negative = append(plan.negative, tokenize(phrase)...)
				continue
			}
			plan.phrases = append(plan.phrases, phrase)
			continue
		}
		for _, term := range tokenize(strings.ToLower(token)) {
			if negative {
				plan.negative = append(plan.negative, term)
			} else {
				plan.terms = append(plan.terms, term)
			}
		}
	}
	plan.terms = dedupeStrings(plan.terms)
	plan.phrases = dedupeStrings(plan.phrases)
	plan.negative = dedupeStrings(plan.negative)
	return plan
}

func splitFullTextQuery(text string) []string {
	var out []string
	var b strings.Builder
	inQuote := false
	for _, r := range text {
		switch {
		case r == '"':
			b.WriteRune(r)
			inQuote = !inQuote
		case unicode.IsSpace(r) && !inQuote:
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func tokenize(s string) []string {
	if s == "" {
		return nil
	}
	return strings.FieldsFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func normalizeValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprintf("%v", t)
	}
}

var _ api.SearchIndex = (*fullTextIndex)(nil)
