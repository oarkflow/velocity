package doclib

import "errors"

var (
	ErrNotFound         = errors.New("not found")
	ErrAlreadyExists    = errors.New("already exists")
	ErrAccessDenied     = errors.New("access denied")
	ErrInvalidInput     = errors.New("invalid input")
	ErrInvalidStatus    = errors.New("invalid status transition")
	ErrApprovalRequired = errors.New("approval required")
	ErrAlreadyApproved  = errors.New("already approved")
	ErrRevoked          = errors.New("share revoked")
	ErrNotPending       = errors.New("share request is not pending")
)
