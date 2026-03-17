package audit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// ZKProofSystem handles Zero-Knowledge Proof operations
type ZKProofSystem struct {
	curve elliptic.Curve
}

// NewZKProofSystem creates a new ZK proof system using P-256
func NewZKProofSystem() *ZKProofSystem {
	return &ZKProofSystem{
		curve: elliptic.P256(),
	}
}

// SchnorrProof represents a Schnorr non-interactive zero-knowledge proof
type SchnorrProof struct {
	T []byte // Commitment point (marshaled)
	S []byte // Response scalar (marshaled)
}

// GenerateProof generates a ZK proof for knowledge of discrete log x (where Y = g^x)
// x is the secret key, Y is the public key point (marshaled)
func (zk *ZKProofSystem) GenerateProof(x *big.Int) (*SchnorrProof, error) {
	// 1. Generate random ephemeral scalar r
	r, err := rand.Int(rand.Reader, zk.curve.Params().N)
	if err != nil {
		return nil, err
	}

	// 2. Compute commitment T = g^r
	Tx, Ty := zk.curve.ScalarBaseMult(r.Bytes())
	T := marshalPoint(zk.curve, Tx, Ty)

	// PublicKey Y = g^x
	Yx, Yy := zk.curve.ScalarBaseMult(x.Bytes())
	Y := marshalPoint(zk.curve, Yx, Yy)

	// 3. Compute challenge c = H(g || Y || T)
	c := zk.computeChallenge(T, Y)

	// 4. Compute response s = r + c*x mod N
	cx := new(big.Int).Mul(c, x)
	s := new(big.Int).Add(r, cx)
	s.Mod(s, zk.curve.Params().N)

	return &SchnorrProof{
		T: T,
		S: s.Bytes(),
	}, nil
}

// VerifyProof verifies a Schnorr ZK proof
// Y is the public key point (marshaled)
func (zk *ZKProofSystem) VerifyProof(Y []byte, proof *SchnorrProof) bool {
	if len(Y) == 0 || proof == nil || len(proof.T) == 0 || len(proof.S) == 0 {
		return false
	}

	// Unmarshal public key Y
	Yx, Yy := unmarshalPoint(zk.curve, Y)
	if Yx == nil {
		return false
	}

	// Unmarshal commitment T
	Tx, Ty := unmarshalPoint(zk.curve, proof.T)
	if Tx == nil {
		return false
	}

	// 1. Compute challenge c = H(g || Y || T)
	c := zk.computeChallenge(proof.T, Y)

	// 2. Compute LHS = g^s
	LHSx, LHSy := zk.curve.ScalarBaseMult(proof.S)

	// 3. Compute RHS = T * Y^c
	// Y^c
	Ycx, Ycy := zk.curve.ScalarMult(Yx, Yy, c.Bytes())
	// T * Y^c
	RHSx, RHSy := zk.curve.Add(Tx, Ty, Ycx, Ycy)

	// 4. Check LHS == RHS
	return LHSx.Cmp(RHSx) == 0 && LHSy.Cmp(RHSy) == 0
}

// computeChallenge computes H(Y || T) -> scalar
func (zk *ZKProofSystem) computeChallenge(T, Y []byte) *big.Int {
	h := sha256.New()
	h.Write(Y)
	h.Write(T)
	hash := h.Sum(nil)

	c := new(big.Int).SetBytes(hash)
	c.Mod(c, zk.curve.Params().N)
	return c
}

// Helper to generate a key pair for testing/usage
func (zk *ZKProofSystem) GenerateKeyPair() (*big.Int, []byte, error) {
	// Use ecdsa.GenerateKey instead of deprecated elliptic.GenerateKey
	priv, err := ecdsa.GenerateKey(zk.curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pub := marshalPoint(zk.curve, priv.PublicKey.X, priv.PublicKey.Y)
	return priv.D, pub, nil
}

// ECDSAPublicToBytes makes it easy to use existing ecdsa keys
func (zk *ZKProofSystem) ECDSAPublicToBytes(pub *ecdsa.PublicKey) []byte {
	return marshalPoint(zk.curve, pub.X, pub.Y)
}

// ECDSAPrivateToBigInt makes it easy to use existing ecdsa keys
func (zk *ZKProofSystem) ECDSAPrivateToBigInt(priv *ecdsa.PrivateKey) *big.Int {
	return priv.D
}

// marshalPoint marshals a point to uncompressed form (replacement for deprecated elliptic.Marshal)
func marshalPoint(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) / 8
	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point

	xBytes := x.Bytes()
	copy(ret[1+byteLen-len(xBytes):], xBytes)

	yBytes := y.Bytes()
	copy(ret[1+2*byteLen-len(yBytes):], yBytes)
	return ret
}

// unmarshalPoint unmarshals a point from uncompressed form (replacement for deprecated elliptic.Unmarshal)
func unmarshalPoint(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(data) != 1+2*byteLen {
		return nil, nil
	}
	if data[0] != 4 { // only support uncompressed
		return nil, nil
	}

	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])

	// Validate point is on curve
	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}
	return x, y
}
