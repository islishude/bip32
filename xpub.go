package bip32

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

// XPub is an extended public key for BIP32-Ed25519.
// The encoded layout is publicKey || chainCode, each 32 bytes.
type XPub struct {
	xpub []byte
}

// NewXPub creates XPub from raw extended public key bytes.
func NewXPub(raw []byte) XPub {
	if len(raw) != XPubSize {
		panic("bip32-ed25519: NewXPub: size should be 64 bytes")
	}
	return XPub{xpub: append([]byte(nil), raw...)}
}

// String implements Stringer interface and returns plain hex string
func (x XPub) String() string {
	return hex.EncodeToString(x.xpub)
}

// Bytes returns intenal bytes
func (x XPub) Bytes() []byte {
	return append([]byte(nil), x.xpub...)
}

// PublicKey returns the current public key
func (x XPub) PublicKey() []byte {
	return append([]byte(nil), x.xpub[:32]...)
}

// ChainCode returns chain code bytes
func (x XPub) ChainCode() []byte {
	return append([]byte(nil), x.xpub[32:]...)
}

// Derive derives a new XPub by a soft index.
// It panics for hardened indexes because those require the parent private key.
func (x XPub) Derive(index uint32) XPub {
	result, err := x.derive(index, false)
	if err != nil {
		panic(err.Error())
	}
	return result
}

// DeriveStrict derives new XPub by a soft index and rejects discarded children.
func (x XPub) DeriveStrict(index uint32) (XPub, error) {
	return x.derive(index, true)
}

// derive performs public child-key derivation shared by legacy and strict APIs.
// strict only controls whether the rare identity-point child is rejected.
func (x XPub) derive(index uint32, strict bool) (XPub, error) {
	if index >= HardIndex {
		return XPub{}, errors.New("bip32-ed25519: xpub.Derive: expected a soft derivation")
	}

	// Public derivation only has AP and cP, so it can derive soft children only.
	var pubkey [32]byte
	copy(pubkey[:], x.xpub[:32])
	chaincode := append([]byte(nil), x.xpub[32:]...)

	zmac := hmac.New(sha512.New, chaincode)
	imac := hmac.New(sha512.New, chaincode)

	seri := make([]byte, 4)
	binary.LittleEndian.PutUint32(seri, index)

	// Z controls the public-key point offset [8 * ZL]B.
	_, _ = zmac.Write([]byte{2})
	_, _ = zmac.Write(pubkey[:])
	_, _ = zmac.Write(seri)

	// I contributes the next chain code; only the right 32 bytes are used.
	_, _ = imac.Write([]byte{3})
	_, _ = imac.Write(pubkey[:])
	_, _ = imac.Write(seri)

	// Ai = AP + [8 * ZL]B, where ZL is truncated to 28 bytes by the helper.
	left, ok := pointPlus(&pubkey, pointOfTrunc28Mul8(zmac.Sum(nil)[:32]))
	if !ok {
		return XPub{}, errors.New("bip32-ed25519: can't convert bytes to edwards25519 Point")
	}

	var out [64]byte
	copy(out[:32], left[:32])
	copy(out[32:], imac.Sum(nil)[32:])

	if strict && isIdentityPointEncoding(out[:32]) {
		return XPub{}, errors.New("bip32-ed25519: XPub.DeriveStrict: child public key is the identity point")
	}

	return XPub{xpub: out[:]}, nil
}

// Verify verifies signature by message
func (x XPub) Verify(msg, sig []byte) bool {
	pk := x.xpub[:32]
	return ed25519.Verify(pk, msg, sig)
}
