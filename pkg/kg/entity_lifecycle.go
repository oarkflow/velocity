package kg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

func (s *KGGraphStore) ResolveEntity(ctx context.Context, entityID string) (string, []KGEntityAliasRecord, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	entityID = strings.TrimSpace(entityID)
	if entityID == "" {
		return "", nil, fmt.Errorf("entity_id is required")
	}
	current := entityID
	chain := []KGEntityAliasRecord{}
	seen := map[string]bool{}
	for i := 0; i < 16; i++ {
		if seen[current] {
			return "", chain, fmt.Errorf("alias cycle detected at %s", current)
		}
		seen[current] = true
		data, err := s.db.Get([]byte(kgAliasPrefix + current))
		if err != nil {
			return current, chain, nil
		}
		var record KGEntityAliasRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return "", chain, fmt.Errorf("decode alias %s: %w", current, err)
		}
		chain = append(chain, record)
		if record.CanonicalID == "" || record.CanonicalID == current {
			return current, chain, nil
		}
		current = record.CanonicalID
	}
	return "", chain, fmt.Errorf("alias chain too deep for %s", entityID)
}

func (s *KGGraphStore) ProposeMerge(ctx context.Context, req *KGEntityMergeRequest) (*KGMergeProposal, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, fmt.Errorf("merge request is required")
	}
	target := strings.TrimSpace(req.TargetID)
	sources := cleanEntityIDs(req.SourceIDs, target)
	if target == "" || len(sources) == 0 {
		return nil, fmt.Errorf("target_id and source_ids are required")
	}
	now := time.Now().UTC()
	proposal := &KGMergeProposal{
		ProposalID: stableMergeProposalID(sources, target, req.Reason),
		SourceIDs:  sources,
		TargetID:   target,
		Reason:     strings.TrimSpace(req.Reason),
		Status:     KGMergeStatusPending,
		CreatedBy:  strings.TrimSpace(req.CreatedBy),
		CreatedAt:  now,
		Attributes: cloneStringMap(req.Attributes),
	}
	if err := s.putMergeProposal(proposal); err != nil {
		return nil, err
	}
	return proposal, s.appendMutation("propose_merge", "entity", proposal.ProposalID, proposal.CreatedBy, 1)
}

func (s *KGGraphStore) ApproveMerge(ctx context.Context, proposalID, reviewedBy string) (*KGMergeProposal, error) {
	proposal, err := s.GetMergeProposal(ctx, proposalID)
	if err != nil {
		return nil, err
	}
	if proposal.Status != KGMergeStatusPending {
		return nil, fmt.Errorf("merge proposal is %s", proposal.Status)
	}
	if _, err := s.MergeEntities(ctx, &KGEntityMergeRequest{
		SourceIDs:  proposal.SourceIDs,
		TargetID:   proposal.TargetID,
		Reason:     proposal.Reason,
		CreatedBy:  reviewedBy,
		Attributes: proposal.Attributes,
	}); err != nil {
		return nil, err
	}
	proposal.Status = KGMergeStatusApproved
	proposal.ReviewedBy = strings.TrimSpace(reviewedBy)
	proposal.ReviewedAt = time.Now().UTC()
	if err := s.putMergeProposal(proposal); err != nil {
		return nil, err
	}
	return proposal, s.appendMutation("approve_merge", "entity", proposal.ProposalID, reviewedBy, 1)
}

func (s *KGGraphStore) RejectMerge(ctx context.Context, proposalID, reviewedBy string) (*KGMergeProposal, error) {
	proposal, err := s.GetMergeProposal(ctx, proposalID)
	if err != nil {
		return nil, err
	}
	if proposal.Status != KGMergeStatusPending {
		return nil, fmt.Errorf("merge proposal is %s", proposal.Status)
	}
	proposal.Status = KGMergeStatusRejected
	proposal.ReviewedBy = strings.TrimSpace(reviewedBy)
	proposal.ReviewedAt = time.Now().UTC()
	if err := s.putMergeProposal(proposal); err != nil {
		return nil, err
	}
	return proposal, s.appendMutation("reject_merge", "entity", proposal.ProposalID, reviewedBy, 1)
}

func (s *KGGraphStore) GetMergeProposal(ctx context.Context, proposalID string) (*KGMergeProposal, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	proposalID = strings.TrimSpace(proposalID)
	if proposalID == "" {
		return nil, fmt.Errorf("proposal_id is required")
	}
	data, err := s.db.Get([]byte(kgMergePrefix + proposalID))
	if err != nil {
		return nil, fmt.Errorf("merge proposal not found: %s", proposalID)
	}
	var proposal KGMergeProposal
	if err := json.Unmarshal(data, &proposal); err != nil {
		return nil, fmt.Errorf("decode merge proposal %s: %w", proposalID, err)
	}
	return &proposal, nil
}

func (s *KGGraphStore) ListMergeProposals(ctx context.Context, status KGMergeStatus) ([]KGMergeProposal, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keys, err := s.db.Keys(kgMergePrefix + "*")
	if err != nil {
		return nil, err
	}
	out := make([]KGMergeProposal, 0, len(keys))
	for _, key := range keys {
		data, err := s.db.Get([]byte(key))
		if err != nil {
			continue
		}
		var proposal KGMergeProposal
		if json.Unmarshal(data, &proposal) != nil {
			continue
		}
		if status == "" || proposal.Status == status {
			out = append(out, proposal)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *KGGraphStore) MergeEntities(ctx context.Context, req *KGEntityMergeRequest) ([]KGEntityAliasRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, fmt.Errorf("merge request is required")
	}
	target := strings.TrimSpace(req.TargetID)
	sources := cleanEntityIDs(req.SourceIDs, target)
	if target == "" || len(sources) == 0 {
		return nil, fmt.Errorf("target_id and source_ids are required")
	}
	now := time.Now().UTC()
	records := make([]KGEntityAliasRecord, 0, len(sources))
	for _, source := range sources {
		record := KGEntityAliasRecord{
			Alias:       source,
			CanonicalID: target,
			Reason:      strings.TrimSpace(req.Reason),
			CreatedBy:   strings.TrimSpace(req.CreatedBy),
			CreatedAt:   now,
			Attributes:  cloneStringMap(req.Attributes),
		}
		data, err := json.Marshal(record)
		if err != nil {
			return records, err
		}
		if err := s.db.Put([]byte(kgAliasPrefix+source), data); err != nil {
			return records, err
		}
		records = append(records, record)
	}
	return records, s.appendMutation("merge", "entity", target, req.CreatedBy, 1)
}

func (s *KGGraphStore) SplitEntity(ctx context.Context, aliases []string, actor string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cleaned := cleanEntityIDs(aliases, "")
	if len(cleaned) == 0 {
		return fmt.Errorf("aliases are required")
	}
	for _, alias := range cleaned {
		if err := s.db.Delete([]byte(kgAliasPrefix + alias)); err != nil {
			return err
		}
	}
	return s.appendMutation("split", "entity", strings.Join(cleaned, ","), actor, 1)
}

func (s *KGGraphStore) putMergeProposal(proposal *KGMergeProposal) error {
	data, err := json.Marshal(proposal)
	if err != nil {
		return err
	}
	return s.db.Put([]byte(kgMergePrefix+proposal.ProposalID), data)
}

func cleanEntityIDs(ids []string, exclude string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || id == exclude || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func stableMergeProposalID(sourceIDs []string, targetID, reason string) string {
	sources := append([]string(nil), sourceIDs...)
	sort.Strings(sources)
	h := sha256.Sum256([]byte(strings.Join(append(sources, targetID, reason), "\x00")))
	return "merge-" + hex.EncodeToString(h[:12])
}
