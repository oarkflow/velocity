// Package iam implements Velocity v2's IAM plugin: persisted policy
// storage, principal-to-policy attachment, and Allow/Deny evaluation —
// replacing the in-memory, unpersisted policy map that previously backed
// plugins/web's /api/iam/policies/{name} routes directly.
//
// Evaluation follows standard IAM semantics: an explicit Deny in ANY
// attached policy always wins over an Allow in another, and a request
// matching no statement at all is an implicit Deny. See match.go for the
// (deliberately small) action/resource pattern language.
package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/oarkflow/velocity/v2/api"
)

// Plugin is the api.Plugin implementation registering "iam" as an
// api.IAMService.
type Plugin struct {
	storageDep string
	storage    api.StorageBackend
	log        api.Logger
}

// NewPlugin constructs the iam plugin. storageDep is the Plugin Name() of
// the storage plugin this one depends on for boot ordering; an empty
// string defaults to "storage-lsm". It does not affect the fixed
// "storage" service-name lookup used at Init time — see
// docs/ARCHITECTURE.md on why those are two different namespaces.
func NewPlugin(storageDep string) *Plugin {
	if storageDep == "" {
		storageDep = "storage-lsm"
	}
	return &Plugin{storageDep: storageDep}
}

func (p *Plugin) Name() string           { return "iam" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return []string{p.storageDep} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.log = k.Logger()

	storeAny := k.Registry().MustLookup("storage")
	store, ok := storeAny.(api.StorageBackend)
	if !ok {
		return fmt.Errorf("iam: service %q does not implement api.StorageBackend", "storage")
	}
	p.storage = store

	return k.Registry().Provide("iam", api.IAMService(p))
}

func (p *Plugin) Start(ctx context.Context) error { return nil }
func (p *Plugin) Stop(ctx context.Context) error  { return nil }

func (p *Plugin) Health() api.Health {
	if p.storage == nil {
		return api.Health{Status: "down", Detail: "storage backend not initialized"}
	}
	return api.Health{Status: "ok"}
}

var (
	_ api.Plugin     = (*Plugin)(nil)
	_ api.IAMService = (*Plugin)(nil)
)

func (p *Plugin) PutPolicy(ctx context.Context, name string, pol api.IAMPolicy) error {
	if name == "" {
		return fmt.Errorf("iam: policy name must not be empty")
	}
	if strings.Contains(name, "/") {
		return fmt.Errorf("iam: policy name %q must not contain %q", name, "/")
	}
	pol.Name = name
	data, err := json.Marshal(pol)
	if err != nil {
		return fmt.Errorf("iam: encoding policy %q: %w", name, err)
	}
	return p.storage.Put(ctx, api.Entry{Key: policyKey(name), Value: data})
}

func (p *Plugin) GetPolicy(ctx context.Context, name string) (api.IAMPolicy, error) {
	data, ok, err := p.storage.Get(ctx, policyKey(name))
	if err != nil {
		return api.IAMPolicy{}, err
	}
	if !ok {
		return api.IAMPolicy{}, fmt.Errorf("iam: policy %q not found", name)
	}
	var pol api.IAMPolicy
	if err := json.Unmarshal(data, &pol); err != nil {
		return api.IAMPolicy{}, fmt.Errorf("iam: decoding policy %q: %w", name, err)
	}
	return pol, nil
}

func (p *Plugin) DeletePolicy(ctx context.Context, name string) error {
	return p.storage.Delete(ctx, policyKey(name))
}

func (p *Plugin) ListPolicies(ctx context.Context) ([]string, error) {
	it, err := p.storage.Scan(ctx, []byte(policyPrefix))
	if err != nil {
		return nil, err
	}
	defer it.Close()

	var names []string
	for it.Next() {
		names = append(names, strings.TrimPrefix(string(it.Key()), policyPrefix))
	}
	return names, it.Err()
}

func (p *Plugin) AttachPolicy(ctx context.Context, principalSubject, policyName string) error {
	if _, err := p.GetPolicy(ctx, policyName); err != nil {
		return fmt.Errorf("iam: attach: %w", err)
	}
	return p.storage.Put(ctx, api.Entry{Key: attachKey(principalSubject, policyName)})
}

func (p *Plugin) DetachPolicy(ctx context.Context, principalSubject, policyName string) error {
	return p.storage.Delete(ctx, attachKey(principalSubject, policyName))
}

func (p *Plugin) attachedPolicyNames(ctx context.Context, subject string) ([]string, error) {
	prefix := attachPrefix(subject)
	it, err := p.storage.Scan(ctx, []byte(prefix))
	if err != nil {
		return nil, err
	}
	defer it.Close()

	var names []string
	for it.Next() {
		names = append(names, strings.TrimPrefix(string(it.Key()), prefix))
	}
	return names, it.Err()
}

// Evaluate implements the security-critical decision described on
// api.IAMService: collect every policy attached to principalSubject,
// scan every statement in every policy, and apply explicit-Deny-wins /
// implicit-deny-by-default. A single pass tracks whether any Allow
// matched; a Deny match short-circuits immediately since nothing can
// override it.
func (p *Plugin) Evaluate(ctx context.Context, principalSubject, action, resource string) (bool, string, error) {
	names, err := p.attachedPolicyNames(ctx, principalSubject)
	if err != nil {
		return false, "", fmt.Errorf("iam: listing attached policies: %w", err)
	}

	allowed := false
	allowReason := ""
	for _, name := range names {
		pol, err := p.GetPolicy(ctx, name)
		if err != nil {
			// A policy attachment pointing at a since-deleted policy is a
			// data-consistency issue worth surfacing, not silently
			// skipping — but it must not itself grant or deny anything.
			if p.log != nil {
				p.log.Warn("iam: attached policy no longer exists", "subject", principalSubject, "policy", name, "err", err)
			}
			continue
		}
		for _, stmt := range pol.Statements {
			if !anyPatternMatches(stmt.Actions, action) || !anyPatternMatches(stmt.Resources, resource) {
				continue
			}
			switch stmt.Effect {
			case "Deny":
				return false, fmt.Sprintf("explicit Deny in policy %q", name), nil
			case "Allow":
				if !allowed {
					allowed = true
					allowReason = fmt.Sprintf("Allow in policy %q", name)
				}
			}
		}
	}

	if allowed {
		return true, allowReason, nil
	}
	return false, "no attached policy statement matched (implicit deny)", nil
}
