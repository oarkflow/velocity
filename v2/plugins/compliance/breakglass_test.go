package compliance

import (
	"context"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

func TestBreakGlass_ValidGrantIsAuditedAndRevocable(t *testing.T) {
	ctx := context.Background()
	k, _ := bootTestKernel(t)

	p := NewPlugin("storage-mem")
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	grant, err := p.BreakGlassGrant(ctx,
		api.BreakGlassRequest{Requestor: "alice", Reason: "prod incident", Resource: "bucket/critical"},
		api.Principal{Subject: "bob"},
	)
	if err != nil {
		t.Fatalf("BreakGlassGrant: %v", err)
	}
	if grant.ID == "" {
		t.Fatal("expected a non-empty grant ID")
	}
	if !grant.ExpiresAt.After(time.Now()) {
		t.Fatal("expected grant to expire in the future")
	}

	if err := p.VerifyChain(ctx); err != nil {
		t.Fatalf("VerifyChain after grant: %v", err)
	}

	if err := p.BreakGlassRevoke(ctx, grant.ID); err != nil {
		t.Fatalf("BreakGlassRevoke: %v", err)
	}
	if err := p.VerifyChain(ctx); err != nil {
		t.Fatalf("VerifyChain after revoke: %v", err)
	}

	// Revoking the same grant again must fail.
	if err := p.BreakGlassRevoke(ctx, grant.ID); err == nil {
		t.Fatal("expected an error revoking an already-revoked grant")
	}
}

func TestBreakGlass_RejectsSelfApproval(t *testing.T) {
	ctx := context.Background()
	k, _ := bootTestKernel(t)

	p := NewPlugin("storage-mem")
	if err := p.Init(ctx, k); err != nil {
		t.Fatalf("Init: %v", err)
	}

	_, err := p.BreakGlassGrant(ctx,
		api.BreakGlassRequest{Requestor: "alice", Reason: "self-serve", Resource: "bucket/critical"},
		api.Principal{Subject: "alice"},
	)
	if err == nil {
		t.Fatal("expected an error when approver == requestor (segregation of duties)")
	}
}

func TestBreakGlass_UninitializedRejectsRatherThanNoop(t *testing.T) {
	ctx := context.Background()
	p := NewPlugin("storage-mem") // never Init'd — p.storage is nil

	_, err := p.BreakGlassGrant(ctx,
		api.BreakGlassRequest{Requestor: "alice", Reason: "x", Resource: "y"},
		api.Principal{Subject: "bob"},
	)
	if err == nil {
		t.Fatal("expected an error granting break-glass access on an uninitialized plugin, not a silent no-op")
	}
	if err := p.BreakGlassRevoke(ctx, "anything"); err == nil {
		t.Fatal("expected an error revoking on an uninitialized plugin, not a silent no-op")
	}
}
