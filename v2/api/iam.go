package api

import "context"

// IAMStatement is one Allow/Deny rule inside an IAMPolicy. Actions and
// Resources support a trailing "*" wildcard (e.g. "kv:*" matches
// "kv:Put"/"kv:Get"; "*" alone matches anything) — no other wildcard
// position or glob syntax is supported, keeping the matching logic simple
// enough to audit for correctness, which matters here: an overly clever
// pattern language is exactly how access-control systems grow silent
// over-permission bugs.
type IAMStatement struct {
	Effect    string // "Allow" or "Deny"
	Actions   []string
	Resources []string
}

// IAMPolicy is a named, versioned set of IAMStatements.
type IAMPolicy struct {
	Name       string
	Version    int
	Statements []IAMStatement
}

// IAMService is the surface plugins/iam exposes: persisted policy
// storage, principal-to-policy attachment, and evaluation. Service name:
// "iam" -> api.IAMService.
//
// Evaluate follows standard IAM semantics: an explicit Deny in ANY
// attached policy always wins over an Allow in another; a request that
// matches no statement at all is an implicit Deny, never an implicit
// Allow. This is the security-critical property callers depend on — see
// plugins/iam's own tests for the correctness proof.
type IAMService interface {
	PutPolicy(ctx context.Context, name string, p IAMPolicy) error
	GetPolicy(ctx context.Context, name string) (IAMPolicy, error)
	DeletePolicy(ctx context.Context, name string) error
	ListPolicies(ctx context.Context) ([]string, error)

	AttachPolicy(ctx context.Context, principalSubject, policyName string) error
	DetachPolicy(ctx context.Context, principalSubject, policyName string) error

	// Evaluate checks whether principalSubject is allowed to perform
	// action on resource, based on every policy currently attached to
	// them. reason explains the decision (which statement/policy matched,
	// or "no matching statement" for an implicit deny) for audit/debug
	// purposes.
	Evaluate(ctx context.Context, principalSubject, action, resource string) (allowed bool, reason string, err error)
}
