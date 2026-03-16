package doclib

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/oarkflow/velocity"
)

const docCommentPrefix = "doc:comment:"

// Comment represents a discussion entry on a document.
type Comment struct {
	ID        string    `json:"id"`
	DocID     string    `json:"doc_id"`
	Author    string    `json:"author"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CommentManager handles comment CRUD for documents.
type CommentManager struct {
	db  *velocity.DB
	doc *DocManager
}

// NewCommentManager returns a CommentManager.
func NewCommentManager(db *velocity.DB, doc *DocManager) *CommentManager {
	return &CommentManager{db: db, doc: doc}
}

// AddComment appends a comment to a document's comment list.
func (m *CommentManager) AddComment(docID, author, content string) (*Comment, error) {
	if content == "" {
		return nil, fmt.Errorf("%w: content required", ErrInvalidInput)
	}
	c := &Comment{
		ID:        uuid.NewString(),
		DocID:     docID,
		Author:    author,
		Content:   content,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	comments, _ := m.ListComments(docID)
	comments = append(comments, c)
	b, err := json.Marshal(comments)
	if err != nil {
		return nil, err
	}
	if err := m.db.Put([]byte(docCommentPrefix+docID), b); err != nil {
		return nil, err
	}
	return c, nil
}

// ListComments returns all comments for a document.
func (m *CommentManager) ListComments(docID string) ([]*Comment, error) {
	b, err := m.db.Get([]byte(docCommentPrefix + docID))
	if err != nil {
		return []*Comment{}, nil
	}
	var comments []*Comment
	if err := json.Unmarshal(b, &comments); err != nil {
		return nil, err
	}
	return comments, nil
}
