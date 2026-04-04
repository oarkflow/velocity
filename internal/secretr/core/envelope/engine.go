// Package envelope provides functionality for secure, auditable envelopes.
package envelope

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/core/policy"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrInvalidSignature      = errors.New("envelope: invalid signature")
	ErrChainBroken           = errors.New("envelope: custody chain broken")
	ErrAccessDenied          = errors.New("envelope: access denied by business rules")
	ErrRecipientMismatch     = errors.New("envelope: recipient mismatch")
	ErrEnvelopeExpired       = errors.New("envelope: envelope expired")
	ErrActorSignatureInvalid = errors.New("envelope: custody actor signature invalid")
)

// Engine manages secure envelopes
type Engine struct {
	crypto       *crypto.Engine
	policyEngine *policy.Engine
}

// NewEngine creates a new envelope engine
func NewEngine(policyEngine *policy.Engine) *Engine {
	return &Engine{
		crypto:       crypto.NewEngine(""),
		policyEngine: policyEngine,
	}
}

// Crypto returns the underlying crypto engine
func (e *Engine) Crypto() *crypto.Engine {
	return e.crypto
}

// CreateOptions holds options for creating an envelope
type CreateOptions struct {
	SenderID        types.ID
	SenderPrivKey   []byte
	RecipientID     types.ID
	RecipientPubKey []byte
	Secrets         []types.SecretPayload
	Files           []types.FilePayload
	Message         string
	PolicyID        types.ID
	Rules           types.BusinessRules
	ExpiresIn       time.Duration
}

// Create creates a new secure envelope
func (e *Engine) Create(ctx context.Context, opts CreateOptions) (*types.Envelope, error) {
	// 1. Prepare payload
	payload := types.EnvelopePayload{
		Secrets: opts.Secrets,
		Files:   opts.Files,
		Message: opts.Message,
	}
	payloadData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	// 2. Generate ephemeral DEK
	dek, err := e.crypto.GenerateKey(crypto.KeySize256)
	if err != nil {
		return nil, err
	}
	defer dek.Free()

	// 3. Encrypt payload with DEK
	encryptedPayload, err := e.crypto.Encrypt(dek.Bytes(), payloadData, nil)
	if err != nil {
		return nil, err
	}

	// 4. Encrypt DEK for recipient
	// Generate an ephemeral key pair for the sender to ensure forward secrecy
	ephemPub, ephemPriv, err := e.crypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, err
	}
	defer ephemPriv.Free()

	sharedSecret, err := e.crypto.ComputeSharedSecret(ephemPriv.Bytes(), opts.RecipientPubKey)
	if err != nil {
		return nil, err
	}
	defer sharedSecret.Free()

	// Encrypt the DEK with the shared secret
	encryptedDEK, err := e.crypto.Encrypt(sharedSecret.Bytes(), dek.Bytes(), nil)
	if err != nil {
		return nil, err
	}

	// Pack the ephemeral public key with the encrypted DEK
	// Format: [EphemPubKey(32)][EncryptedDEK]
	finalEncryptedKey := append(ephemPub, encryptedDEK...)

	now := types.Now()
	var exp types.Timestamp
	if opts.ExpiresIn != 0 {
		exp = types.Timestamp(time.Now().Add(opts.ExpiresIn).UnixNano())
	}

	// 5. Create Header
	header := types.EnvelopeHeader{
		SenderID:      opts.SenderID,
		RecipientID:   opts.RecipientID,
		PolicyID:      opts.PolicyID,
		BusinessRules: opts.Rules,
		CreatedAt:     now,
		ExpiresAt:     exp,
	}

	// 6. Assemble Envelope (minus signature)
	env := &types.Envelope{
		Version:      1,
		Header:       header,
		EncryptedKey: finalEncryptedKey,
		Payload:      encryptedPayload,
		Custody:      make([]types.CustodyEntry, 0),
	}

	id, _ := e.crypto.GenerateRandomID()
	env.ID = id

	// 7. Initial Custody Entry
	if err := e.appendCustody(env, types.CustodyEntry{
		Action:    types.ActionEnvelopeCreate,
		ActorID:   opts.SenderID,
		Timestamp: now,
		Location:  "local",
	}, opts.SenderPrivKey); err != nil {
		return nil, err
	}

	// 8. Sign the whole package
	sigData := e.signatureData(env)
	sig, err := e.crypto.Sign(opts.SenderPrivKey, sigData)
	if err != nil {
		return nil, err
	}
	env.Signature = sig

	return env, nil
}

// OpenOptions holds options for opening an envelope
type OpenOptions struct {
	Envelope              *types.Envelope
	RecipientID           types.ID
	RecipientPrivKey      []byte
	SenderPublicKey       []byte
	ResolveActorPublicKey func(actorID types.ID) ([]byte, error)
	Context               Context
}

type Context struct {
	IP          string
	Time        time.Time
	DeviceID    string
	MFAVerified bool
	TrustScore  float64
}

// Open validates and opens an envelope
func (e *Engine) Open(ctx context.Context, opts OpenOptions) (*types.EnvelopePayload, error) {
	env := opts.Envelope

	// 1. Basic Validations
	if env.Header.RecipientID != opts.RecipientID {
		return nil, ErrRecipientMismatch
	}
	if env.Header.ExpiresAt > 0 && types.Now() > env.Header.ExpiresAt {
		return nil, ErrEnvelopeExpired
	}

	// 2. Business Rules Validation
	if err := e.validateRules(env.Header.BusinessRules, opts.Context); err != nil {
		return nil, err
	}

	// 3. Verify Envelope Signature
	if len(opts.SenderPublicKey) > 0 {
		if err := e.verifyEnvelopeSignature(env, opts.SenderPublicKey); err != nil {
			return nil, err
		}
	}

	// 4. Verify Chain of Custody
	if err := e.VerifyChain(env); err != nil {
		return nil, err
	}
	if opts.ResolveActorPublicKey != nil {
		if err := e.VerifyChainSignatures(env, opts.ResolveActorPublicKey); err != nil {
			return nil, err
		}
	}

	// 5. Decrypt DEK
	if len(env.EncryptedKey) < 32 {
		return nil, errors.New("invalid key data")
	}
	ephemPub := env.EncryptedKey[:32]
	cipherDEK := env.EncryptedKey[32:]

	sharedSecret, err := e.crypto.ComputeSharedSecret(opts.RecipientPrivKey, ephemPub)
	if err != nil {
		return nil, err
	}
	defer sharedSecret.Free()

	dekBytes, err := e.crypto.Decrypt(sharedSecret.Bytes(), cipherDEK, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// 6. Decrypt Payload
	payloadData, err := e.crypto.Decrypt(dekBytes, env.Payload, nil)
	// Zeroize dekBytes
	for i := range dekBytes {
		dekBytes[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %w", err)
	}

	var payload types.EnvelopePayload
	if err := json.Unmarshal(payloadData, &payload); err != nil {
		return nil, err
	}

	return &payload, nil
}

// RecordAction adds a custody entry
func (e *Engine) RecordAction(env *types.Envelope, action string, actorID types.ID, privKey []byte, location string) error {
	return e.appendCustody(env, types.CustodyEntry{
		Action:    action,
		ActorID:   actorID,
		Timestamp: types.Now(),
		Location:  location,
	}, privKey)
}

func (e *Engine) appendCustody(env *types.Envelope, entry types.CustodyEntry, privKey []byte) error {
	// Calculate hash of previous entry + current data to form blockchain-like structure
	var prevHash []byte
	if len(env.Custody) > 0 {
		// Use hash of the last entry's signature
		prevHash = e.crypto.Hash(env.Custody[len(env.Custody)-1].Signature)
	} else {
		prevHash = make([]byte, 32) // Genesis hash
	}
	entry.PrevHash = append([]byte(nil), prevHash...)

	dataToHash := fmt.Sprintf("%x%s%s%d%s", prevHash, entry.Action, entry.ActorID, entry.Timestamp, entry.Location)
	entry.Hash = e.crypto.Hash([]byte(dataToHash))

	// Sign the entry
	signData, _ := json.Marshal(entry)
	sig, err := e.crypto.Sign(privKey, signData)
	if err != nil {
		return err
	}
	entry.Signature = sig

	env.Custody = append(env.Custody, entry)
	return nil
}

func (e *Engine) VerifyChain(env *types.Envelope) error {
	if len(env.Custody) == 0 {
		return errors.New("empty custody chain")
	}

	var prevHash []byte = make([]byte, 32)

	for i, entry := range env.Custody {
		if len(entry.PrevHash) > 0 && !equal(entry.PrevHash, prevHash) {
			return fmt.Errorf("chain broken at index %d (prev hash mismatch)", i)
		}
		// Verify Hash linkage
		dataToHash := fmt.Sprintf("%x%s%s%d%s", prevHash, entry.Action, entry.ActorID, entry.Timestamp, entry.Location)
		computedHash := e.crypto.Hash([]byte(dataToHash))

		if !equal(computedHash, entry.Hash) {
			return fmt.Errorf("chain broken at index %d", i)
		}

		// Prepare for next iteration
		prevHash = e.crypto.Hash(entry.Signature)
	}
	return nil
}

func (e *Engine) verifyEnvelopeSignature(env *types.Envelope, senderPubKey []byte) error {
	if env == nil {
		return ErrInvalidSignature
	}
	if len(env.Signature) == 0 {
		return ErrInvalidSignature
	}
	return e.crypto.Verify(senderPubKey, e.signatureData(env), env.Signature)
}

func (e *Engine) VerifyEnvelopeSignature(env *types.Envelope, senderPubKey []byte) error {
	return e.verifyEnvelopeSignature(env, senderPubKey)
}

func (e *Engine) VerifyChainSignatures(env *types.Envelope, resolveActorPublicKey func(actorID types.ID) ([]byte, error)) error {
	if env == nil {
		return ErrChainBroken
	}
	for i := range env.Custody {
		entry := env.Custody[i]
		if len(entry.Signature) == 0 {
			return fmt.Errorf("%w: index %d missing signature", ErrActorSignatureInvalid, i)
		}
		pub, err := resolveActorPublicKey(entry.ActorID)
		if err != nil {
			return fmt.Errorf("%w: index %d actor %s key resolve failed: %v", ErrActorSignatureInvalid, i, entry.ActorID, err)
		}
		signData, _ := json.Marshal(types.CustodyEntry{
			Hash:      entry.Hash,
			PrevHash:  entry.PrevHash,
			Action:    entry.Action,
			Category:  entry.Category,
			Outcome:   entry.Outcome,
			ActorID:   entry.ActorID,
			Timestamp: entry.Timestamp,
			Location:  entry.Location,
			Related:   entry.Related,
			Details:   entry.Details,
		})
		if err := e.crypto.Verify(pub, signData, entry.Signature); err != nil {
			return fmt.Errorf("%w: index %d actor %s: %v", ErrActorSignatureInvalid, i, entry.ActorID, err)
		}
	}
	return nil
}

func BuildDependencyRefs(env *types.Envelope, payload *types.EnvelopePayload) []string {
	refs := make([]string, 0, 6)
	if env == nil {
		return refs
	}
	if env.Header.PolicyID != "" {
		refs = append(refs, "policy:"+string(env.Header.PolicyID))
	}
	if payload != nil {
		for _, s := range payload.Secrets {
			if s.Name == "" {
				continue
			}
			refs = append(refs, "secret:"+s.Name)
		}
		for _, f := range payload.Files {
			if f.Name == "" {
				continue
			}
			refs = append(refs, "file:"+f.Name)
		}
	}
	sort.Strings(refs)
	return refs
}

func PayloadDigestBase64(payload *types.EnvelopePayload) string {
	if payload == nil {
		return ""
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	h := ehash(b)
	return base64.StdEncoding.EncodeToString(h)
}

func ehash(data []byte) []byte {
	e := crypto.NewEngine("")
	defer e.Close()
	return e.Hash(data)
}

func (e *Engine) validateRules(rules types.BusinessRules, ctx Context) error {
	// Trust Score
	if rules.RequiredTrustLevel > 0 && ctx.TrustScore < rules.RequiredTrustLevel {
		return fmt.Errorf("%w: trust score too low", ErrAccessDenied)
	}

	// MFA
	if rules.RequireMFA && !ctx.MFAVerified {
		return fmt.Errorf("%w: MFA required", ErrAccessDenied)
	}

	// Time Windows
	if len(rules.AllowedTimeWindows) > 0 {
		allowed := false
		currentHHMM := ctx.Time.Format("15:04")
		currentDay := int(ctx.Time.Weekday())

		for _, window := range rules.AllowedTimeWindows {
			dayMatch := false
			for _, d := range window.Days {
				if d == currentDay {
					dayMatch = true
					break
				}
			}
			if !dayMatch {
				continue
			}

			if currentHHMM >= window.StartTime && currentHHMM <= window.EndTime {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: outside allowed time window", ErrAccessDenied)
		}
	}

	return nil
}

func (e *Engine) signatureData(env *types.Envelope) []byte {
	hData, _ := json.Marshal(env.Header)
	combined := append(hData, env.EncryptedKey...)
	combined = append(combined, env.Payload...)
	return combined
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Close cleans up resources
func (e *Engine) Close() error {
	return e.crypto.Close()
}
