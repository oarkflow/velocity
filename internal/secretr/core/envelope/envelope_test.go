package envelope_test

import (
	"context"
	"testing"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/envelope"
	"github.com/oarkflow/velocity/internal/secretr/core/policy"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

func TestEnvelopeWorkflow(t *testing.T) {
	// Setup
	policyEngine := policy.NewEngine(policy.EngineConfig{})
	engine := envelope.NewEngine(policyEngine)
	defer engine.Close()

	// 1. Setup Identities
	senderID := types.ID("sender-1")
	senderPub, senderPriv, _ := engine.Crypto().GenerateKeyPair()
	// defer senderPriv.Free()
	_ = senderPub

	recipID := types.ID("recipient-1")
	recipPub, recipPriv, _ := engine.Crypto().GenerateX25519KeyPair()
	// defer recipPriv.Free()

	// 2. Create Envelope
	secretPayload := types.SecretPayload{Name: "top-secret", Value: []byte("launch-codes"), Type: "generic"}

	ctx := context.Background()
	env, err := engine.Create(ctx, envelope.CreateOptions{
		SenderID:      senderID,
		SenderPrivKey: senderPriv.Bytes(),
		RecipientID:   recipID,
		RecipientPubKey: recipPub,
		Secrets:       []types.SecretPayload{secretPayload},
		Message:       "For your eyes only",
		ExpiresIn:     1 * time.Hour,
	})

	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// 3. Verify Structure
	if env.Header.SenderID != senderID {
		t.Error("Sender ID mismatch")
	}
	if len(env.Custody) != 1 {
		t.Error("Custody chain should have 1 entry")
	}
	if env.Custody[0].Action != types.ActionEnvelopeCreate {
		t.Error("Initial action should be Create")
	}

	// 4. Open Envelope (Success Case)
	openCtx := envelope.Context{
		Time: time.Now(),
		TrustScore: 1.0,
	}

	payload, err := engine.Open(ctx, envelope.OpenOptions{
		Envelope:        env,
		RecipientID:     recipID,
		RecipientPrivKey: recipPriv.Bytes(),
		Context:         openCtx,
	})

	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if payload.Message != "For your eyes only" {
		t.Errorf("Message mismatch: %s", payload.Message)
	}
	if string(payload.Secrets[0].Value) != "launch-codes" {
		t.Errorf("Secret value mismatch")
	}
}

func TestEnvelopeExpired(t *testing.T) {
	policyEngine := policy.NewEngine(policy.EngineConfig{})
	engine := envelope.NewEngine(policyEngine)
	defer engine.Close()

	recipPub, recipPriv, _ := engine.Crypto().GenerateX25519KeyPair()
	_, senderPriv, _ := engine.Crypto().GenerateKeyPair()

	// Create already expired envelope (small negative duration)
	env, _ := engine.Create(context.Background(), envelope.CreateOptions{
		SenderID:      "sender",
		SenderPrivKey: senderPriv.Bytes(),
		RecipientID:   "recipient",
		RecipientPubKey: recipPub,
		ExpiresIn:     -1 * time.Second,
	})

	_, err := engine.Open(context.Background(), envelope.OpenOptions{
		Envelope:        env,
		RecipientID:     "recipient",
		RecipientPrivKey: recipPriv.Bytes(),
	})

	if err != envelope.ErrEnvelopeExpired {
		t.Errorf("Expected ErrEnvelopeExpired, got %v", err)
	}
}

func TestBusinessRules(t *testing.T) {
	policyEngine := policy.NewEngine(policy.EngineConfig{})
	engine := envelope.NewEngine(policyEngine)
	defer engine.Close()

	recipPub, recipPriv, _ := engine.Crypto().GenerateX25519KeyPair()
	_, senderPriv, _ := engine.Crypto().GenerateKeyPair()

	// Require MFA
	rules := types.BusinessRules{RequireMFA: true}

	env, _ := engine.Create(context.Background(), envelope.CreateOptions{
		SenderID:      "sender",
		SenderPrivKey: senderPriv.Bytes(),
		RecipientID:   "recipient",
		RecipientPubKey: recipPub,
		Rules:         rules,
	})

	// Try without MFA
	ctxNoMFA := envelope.Context{MFAVerified: false}
	_, err := engine.Open(context.Background(), envelope.OpenOptions{
		Envelope:        env,
		RecipientID:     "recipient",
		RecipientPrivKey: recipPriv.Bytes(),
		Context:         ctxNoMFA,
	})

	if err == nil {
		t.Error("Should fail without MFA")
	}

	// Try with MFA
	ctxWithMFA := envelope.Context{MFAVerified: true}
	_, err = engine.Open(context.Background(), envelope.OpenOptions{
		Envelope:        env,
		RecipientID:     "recipient",
		RecipientPrivKey: recipPriv.Bytes(),
		Context:         ctxWithMFA,
	})

	if err != nil {
		t.Errorf("Should pass with MFA, got %v", err)
	}
}
