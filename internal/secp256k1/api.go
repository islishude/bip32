// Copyright 2026 The bip32 Authors.

// Package secp256k1 exposes only the curve operations required by BIP-32. It
// intentionally does not provide signing or general-purpose point APIs.
package secp256k1

import (
	"github.com/islishude/bip32/v2/internal/secp256k1/field"
	"github.com/islishude/bip32/v2/internal/secp256k1/scalar"
)

const (
	PrivateKeySize = 32
	PublicKeySize  = 33
)

// ValidPrivateScalar reports whether key is in [1,n-1].
func ValidPrivateScalar(key *[PrivateKeySize]byte) bool {
	var k scalar.Element
	return k.SetBytes(key) && !k.IsZero()
}

// AddScalars returns parent+tweak mod n. Parent must be a valid private key;
// tweak may be zero but must be canonical. A zero result is rejected.
func AddScalars(parent, tweak *[PrivateKeySize]byte) ([PrivateKeySize]byte, bool) {
	var p, t, child scalar.Element
	if !p.SetBytes(parent) || p.IsZero() || !t.SetBytes(tweak) {
		return [PrivateKeySize]byte{}, false
	}
	child.Add(&p, &t)
	if child.IsZero() {
		return [PrivateKeySize]byte{}, false
	}
	return child.Bytes(), true
}

// PublicKeyFromScalar derives a compressed SEC 1 public key using the
// constant-time fixed-base multiplication path.
func PublicKeyFromScalar(key *[PrivateKeySize]byte) ([PublicKeySize]byte, bool) {
	var k scalar.Element
	if !k.SetBytes(key) || k.IsZero() {
		return [PublicKeySize]byte{}, false
	}
	p := scalarBaseMultProjective(&k)
	x, y, ok := p.affine()
	if !ok {
		return [PublicKeySize]byte{}, false
	}
	return encodeAffine(&x, &y), true
}

// ValidPublicKey reports whether key is a canonical compressed SEC 1 point.
func ValidPublicKey(key *[PublicKeySize]byte) bool {
	_, ok := parseCompressed(key)
	return ok
}

// AddScalarBase returns parent + tweak*G. This operation is used only by
// public-child derivation, where both the parent extended public key and the
// derived tweak are public inputs.
func AddScalarBase(parent *[PublicKeySize]byte, tweak *[PrivateKeySize]byte) ([PublicKeySize]byte, bool) {
	parentPoint, ok := parseCompressed(parent)
	if !ok {
		return [PublicKeySize]byte{}, false
	}

	var t scalar.Element
	if !t.SetBytes(tweak) {
		return [PublicKeySize]byte{}, false
	}
	if t.IsZero() {
		return *parent, true
	}

	tweakProjective := scalarBaseMultProjective(&t)
	tx, ty, ok := tweakProjective.affine()
	if !ok {
		return [PublicKeySize]byte{}, false
	}
	var tweakPoint point
	tweakPoint.setAffine(&tx, &ty)

	var child point
	child.add(&parentPoint, &tweakPoint)
	x, y, ok := child.affine()
	if !ok {
		return [PublicKeySize]byte{}, false
	}
	return encodeAffine(&x, &y), true
}

func parseCompressed(key *[PublicKeySize]byte) (point, bool) {
	if key[0] != 0x02 && key[0] != 0x03 {
		return point{}, false
	}
	var xBytes [32]byte
	copy(xBytes[:], key[1:])
	x, y, ok := affineFromXBytes(&xBytes, key[0] == 0x03)
	if !ok {
		return point{}, false
	}
	var p point
	p.setAffine(&x, &y)
	return p, true
}

func encodeAffine(x, y *field.Element) (out [PublicKeySize]byte) {
	out[0] = 0x02
	if y.IsOdd() {
		out[0] = 0x03
	}
	x.PutBytes((*[field.Size]byte)(out[1:]))
	return out
}
