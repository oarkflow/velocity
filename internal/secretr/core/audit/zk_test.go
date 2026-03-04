package audit

import (
	"encoding/json"
	"testing"
)

func TestZKProofSystem(t *testing.T) {
	zk := NewZKProofSystem()

	// 1. Generate Key Pair
	priv, pub, err := zk.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// 2. Generate Proof
	proof, err := zk.GenerateProof(priv)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// 3. Verify Proof (Valid)
	if !zk.VerifyProof(pub, proof) {
		t.Error("Failed to verify valid proof")
	}

	// 4. Verify Proof (Invalid Public Key)
	otherPriv, otherPub, _ := zk.GenerateKeyPair()
	// Ensure keys are different
	if priv.Cmp(otherPriv) == 0 {
		t.Fatal("Generated identical keys randomly, very unlikely")
	}

	if zk.VerifyProof(otherPub, proof) {
		t.Error("Verified proof with wrong public key")
	}

	// 5. Verify Proof (Tampered Proof S)
	tamperedProof := &SchnorrProof{
		T: proof.T,
		S: append([]byte{}, proof.S...),
	}
	// Modify S slightly
	tamperedProof.S[len(tamperedProof.S)-1] ^= 0xFF

	if zk.VerifyProof(pub, tamperedProof) {
		t.Error("Verified tampered proof (S modified)")
	}

	// 6. Verify Proof (Tampered Proof T)
	tamperedProofT := &SchnorrProof{
		T: append([]byte{}, proof.T...),
		S: proof.S,
	}
	// Modify T slightly (last byte)
	tamperedProofT.T[len(tamperedProofT.T)-1] ^= 0xFF

	if zk.VerifyProof(pub, tamperedProofT) {
		t.Error("Verified tampered proof (T modified)")
	}
}

func TestVerifyZKProofIntegration(t *testing.T) {
	l := &Ledger{zkSystem: NewZKProofSystem()}

	// Generate valid proof data
	zk := NewZKProofSystem()
	priv, pub, _ := zk.GenerateKeyPair()
	schnorrProof, _ := zk.GenerateProof(priv)

	proofBytes, _ := json.Marshal(schnorrProof)

	zkProof := &ZKProof{
		ProofType: "Schnorr-P256",
		Public:    pub,
		ProofData: proofBytes,
	}

	// Verify valid proof through Ledger
	if !l.VerifyZKProof(zkProof) {
		t.Error("Ledger failed to verify valid ZK proof")
	}

	// Verify invalid proof
	zkProof.ProofData = []byte("invalid json")
	if l.VerifyZKProof(zkProof) {
		t.Error("Ledger verified invalid proof data")
	}
}
