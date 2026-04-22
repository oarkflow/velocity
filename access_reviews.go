package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// AccessReview represents periodic access attestation.
type AccessReview struct {
	ReviewID   string    `json:"review_id"`
	Scope      string    `json:"scope"` // role, resource, user
	Target     string    `json:"target"`
	Reviewer   string    `json:"reviewer"`
	RequestedAt time.Time `json:"requested_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Status     string    `json:"status"` // pending, approved, revoked
	Notes      string    `json:"notes,omitempty"`
}

// AccessReviewManager manages access reviews.
type AccessReviewManager struct {
	db *DB
}

// NewAccessReviewManager creates a new access review manager.
func NewAccessReviewManager(db *DB) *AccessReviewManager {
	return &AccessReviewManager{db: db}
}

// CreateReview creates a new access review.
func (arm *AccessReviewManager) CreateReview(ctx context.Context, review *AccessReview) error {
	if review.ReviewID == "" {
		review.ReviewID = fmt.Sprintf("review:%d", time.Now().UnixNano())
	}
	if review.RequestedAt.IsZero() {
		review.RequestedAt = time.Now()
	}
	if review.Status == "" {
		review.Status = "pending"
	}

	data, err := json.Marshal(review)
	if err != nil {
		return fmt.Errorf("failed to marshal access review: %w", err)
	}
	return arm.db.Put([]byte("access:review:"+review.ReviewID), data)
}

// CompleteReview marks a review as completed.
func (arm *AccessReviewManager) CompleteReview(ctx context.Context, reviewID, status, notes string) error {
	data, err := arm.db.Get([]byte("access:review:" + reviewID))
	if err != nil {
		return fmt.Errorf("access review not found: %w", err)
	}
	var review AccessReview
	if err := json.Unmarshal(data, &review); err != nil {
		return fmt.Errorf("failed to unmarshal access review: %w", err)
	}

	now := time.Now()
	review.CompletedAt = &now
	review.Status = status
	review.Notes = notes

	updated, err := json.Marshal(review)
	if err != nil {
		return fmt.Errorf("failed to marshal access review: %w", err)
	}
	return arm.db.Put([]byte("access:review:"+review.ReviewID), updated)
}

// ListReviews returns all access reviews.
func (arm *AccessReviewManager) ListReviews(ctx context.Context) ([]AccessReview, error) {
	keys, err := arm.db.Keys("access:review:*")
	if err != nil {
		return nil, err
	}
	result := make([]AccessReview, 0)
	for _, key := range keys {
		data, err := arm.db.Get([]byte(key))
		if err != nil {
			continue
		}
		var review AccessReview
		if err := json.Unmarshal(data, &review); err != nil {
			continue
		}
		result = append(result, review)
	}
	return result, nil
}
