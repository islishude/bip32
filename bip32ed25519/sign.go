package bip32ed25519

import (
	"crypto/ed25519"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// Sign signs message with expanded Ed25519 signing.
//
// It uses kR as the deterministic nonce prefix and kL as the already-expanded
// private scalar. It never calls ed25519.NewKeyFromSeed.
func (k *XPrv) Sign(message []byte) ([]byte, error) {
	if k == nil {
		return nil, ErrNilKey
	}

	A, err := k.PublicKey()
	if err != nil {
		return nil, err
	}

	a, err := scalarFromLE32ModL(k.kL)
	if err != nil {
		return nil, err
	}

	rh := sha512.New()
	_, _ = rh.Write(k.kR[:]) // r = H(kR || message) mod L.
	_, _ = rh.Write(message)

	var rDigest [64]byte
	copy(rDigest[:], rh.Sum(nil))

	r, err := new(edwards25519.Scalar).SetUniformBytes(rDigest[:])
	if err != nil {
		return nil, err
	}

	R := new(edwards25519.Point).ScalarBaseMult(r)
	RBytes := R.Bytes()

	hh := sha512.New()
	_, _ = hh.Write(RBytes) // h = H(R || A || message) mod L.
	_, _ = hh.Write(A[:])
	_, _ = hh.Write(message)

	var hDigest [64]byte
	copy(hDigest[:], hh.Sum(nil))

	h, err := new(edwards25519.Scalar).SetUniformBytes(hDigest[:])
	if err != nil {
		return nil, err
	}

	// S = r + h * kL mod L, matching standard Ed25519 verification.
	S := new(edwards25519.Scalar).MultiplyAdd(h, a, r)

	sig := make([]byte, ed25519.SignatureSize)
	copy(sig[0:32], RBytes)
	copy(sig[32:64], S.Bytes())

	return sig, nil
}

// Verify verifies a standard Ed25519 signature with a 32-byte public key.
func Verify(pub [32]byte, message, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pub[:]), message, sig)
}

// Verify verifies a standard Ed25519 signature with this XPub public key.
func (p *XPub) Verify(message, sig []byte) bool {
	if p == nil {
		return false
	}
	return Verify(p.pub, message, sig)
}
