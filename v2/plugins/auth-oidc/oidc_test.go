package authoidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
)

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestVerifyRSA_RoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("signed-content")
	hashed := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}

	eBytes := big.NewInt(int64(priv.PublicKey.E)).Bytes()
	key := &JWK{Kty: "RSA", N: b64url(priv.PublicKey.N.Bytes()), E: b64url(eBytes)}

	if err := verifyRSA(key, crypto.SHA256, hashed[:], sig); err != nil {
		t.Fatalf("verifyRSA: %v", err)
	}

	// Tampered signature must fail.
	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0xFF
	if err := verifyRSA(key, crypto.SHA256, hashed[:], badSig); err == nil {
		t.Fatal("expected tampered RSA signature to fail verification")
	}
}

func TestVerifyECDSA_RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("signed-content")
	hashed := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hashed[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	keySize := 32
	sig := make([]byte, keySize*2)
	r.FillBytes(sig[:keySize])
	s.FillBytes(sig[keySize:])

	key := &JWK{Kty: "EC", Crv: "P-256", X: b64url(priv.X.Bytes()), Y: b64url(priv.Y.Bytes())}

	if err := verifyECDSA(key, hashed[:], sig); err != nil {
		t.Fatalf("verifyECDSA: %v", err)
	}

	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0xFF
	if err := verifyECDSA(key, hashed[:], badSig); err == nil {
		t.Fatal("expected tampered ECDSA signature to fail verification")
	}
}

func TestValidateAudience(t *testing.T) {
	p := &Plugin{clientID: "client-123"}
	if !p.validateAudience("client-123") {
		t.Fatal("expected string audience match to pass")
	}
	if p.validateAudience("someone-else") {
		t.Fatal("expected mismatched string audience to fail")
	}
	if !p.validateAudience([]any{"other", "client-123"}) {
		t.Fatal("expected audience array containing client id to pass")
	}
	if p.validateAudience([]any{"other"}) {
		t.Fatal("expected audience array without client id to fail")
	}
}
