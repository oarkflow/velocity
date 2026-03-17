package compliance

import (
	"context"
	"errors"

	"github.com/oarkflow/velocity/internal/secretr/core/audit"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

// Assessment represents a manual compliance assessment (questionnaire)
type Assessment struct {
	ID          types.ID         `json:"id"`
	Framework   Framework        `json:"framework"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Status      ControlStatus    `json:"status"`
	Questions   []Question       `json:"questions"`
	AssignedTo  types.ID         `json:"assigned_to"`
	CreatedBy   types.ID         `json:"created_by"`
	CreatedAt   types.Timestamp  `json:"created_at"`
	UpdatedAt   types.Timestamp  `json:"updated_at"`
	CompletedAt *types.Timestamp `json:"completed_at,omitempty"`
}

// Question represents a single question in an assessment
type Question struct {
	ID        string  `json:"id"`
	ControlID string  `json:"control_id"` // Links to a specific control
	Text      string  `json:"text"`
	Type      string  `json:"type"` // boolean, text, choice
	Answer    *Answer `json:"answer,omitempty"`
}

// Answer represents the answer to a question
type Answer struct {
	Value       string          `json:"value"`
	Notes       string          `json:"notes,omitempty"`
	EvidenceIDs []types.ID      `json:"evidence_ids,omitempty"`
	AnsweredBy  types.ID        `json:"answered_by"`
	AnsweredAt  types.Timestamp `json:"answered_at"`
}

// AssessmentOptions holds options for creating an assessment
type AssessmentOptions struct {
	Name        string
	Description string
	Framework   Framework
	Controls    []string // List of Control IDs to include
	Assignee    types.ID
	CreatorID   types.ID
}

// CreateAssessment creates a new assessment
func (e *Engine) CreateAssessment(ctx context.Context, opts AssessmentOptions) (*Assessment, error) {
	id, err := e.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	def, err := e.GetFrameworkDefinition(opts.Framework)
	if err != nil {
		return nil, err
	}

	var questions []Question

	// Auto-generate questions based on controls
	for _, cat := range def.Categories {
		for _, ctrl := range cat.Controls {
			// If specific controls requested, filter
			if len(opts.Controls) > 0 {
				found := false
				for _, c := range opts.Controls {
					if c == ctrl.ID {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			// Only manual controls usually get questions, or all if verifying
			if !ctrl.Automated {
				questions = append(questions, Question{
					ID:        "Q-" + ctrl.ID,
					ControlID: ctrl.ID,
					Text:      "Is control " + ctrl.Name + " implemented? (" + ctrl.Description + ")",
					Type:      "boolean",
				})
			}
		}
	}

	now := types.Now()
	assessment := &Assessment{
		ID:          id,
		Framework:   opts.Framework,
		Name:        opts.Name,
		Description: opts.Description,
		Status:      ControlStatusPending,
		Questions:   questions,
		AssignedTo:  opts.Assignee,
		CreatedBy:   opts.CreatorID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := e.assessmentStore.Set(ctx, string(id), assessment); err != nil {
		return nil, err
	}

	return assessment, nil
}

// UpdateAssessmentAnswers updates answers in an assessment
func (e *Engine) UpdateAssessmentAnswers(ctx context.Context, assessmentID types.ID, answers map[string]Answer) (*Assessment, error) {
	assessment, err := e.assessmentStore.Get(ctx, string(assessmentID))
	if err != nil {
		return nil, err
	}

	updated := false
	now := types.Now()

	for i, q := range assessment.Questions {
		if ans, ok := answers[q.ID]; ok {
			ans.AnsweredAt = now // Ensure timestamp is set
			assessment.Questions[i].Answer = &ans
			updated = true
		}
	}

	if updated {
		assessment.UpdatedAt = now
		if err := e.assessmentStore.Set(ctx, string(assessmentID), assessment); err != nil {
			return nil, err
		}
	}

	return assessment, nil
}

// SubmitAssessment finalizes an assessment
func (e *Engine) SubmitAssessment(ctx context.Context, assessmentID types.ID, submitterID types.ID) (*Assessment, error) {
	assessment, err := e.assessmentStore.Get(ctx, string(assessmentID))
	if err != nil {
		return nil, err
	}

	// Calculate overall status
	allAnswered := true
	allCompliant := true

	for _, q := range assessment.Questions {
		if q.Answer == nil {
			allAnswered = false
			break
		}
		// Simple logic: "yes" or "true" = compliant
		if q.Answer.Value != "yes" && q.Answer.Value != "true" {
			allCompliant = false
		}
	}

	if !allAnswered {
		return nil, errors.New("compliance: all questions must be answered before submission")
	}

	if allCompliant {
		assessment.Status = ControlStatusCompliant
	} else {
		assessment.Status = ControlStatusNonCompliant
	}

	now := types.Now()
	assessment.CompletedAt = &now
	assessment.UpdatedAt = now

	if err := e.assessmentStore.Set(ctx, string(assessmentID), assessment); err != nil {
		return nil, err
	}

	// Audit submission
	if e.auditEngine != nil {
		e.auditEngine.Log(ctx, audit.AuditEventInput{
			Type:         "compliance",
			Action:       "assessment_submit",
			ActorID:      submitterID,
			ActorType:    "user",
			ResourceID:   &assessmentID,
			ResourceType: "assessment",
			Success:      true,
			Details: types.Metadata{
				"status": string(assessment.Status),
			},
		})
	}

	return assessment, nil
}
