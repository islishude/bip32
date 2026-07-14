// Copyright 2026 The bip32 Authors.

// Package scalar implements the small subset of secp256k1 scalar arithmetic
// required by BIP-32 child-key derivation.
package scalar

import (
	"encoding/binary"
	"math/bits"

	fiat "github.com/islishude/bip32/v2/internal/secp256k1/fiat/scalarfield"
)

// Size is the byte length of a secp256k1 scalar.
const Size = 32

const (
	order0 uint64 = 0xbfd25e8cd0364141
	order1 uint64 = 0xbaaedce6af48a03b
	order2 uint64 = 0xfffffffffffffffe
	order3 uint64 = 0xffffffffffffffff
)

// Order is the secp256k1 group order n in canonical big-endian form.
var Order = [Size]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
	0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
}

// Element is an integer modulo the secp256k1 group order. Values are stored in
// Montgomery form so addition is delegated to Fiat-Crypto generated code.
type Element struct {
	x fiat.MontgomeryDomainFieldElement
}

// SetBytes parses a canonical 32-byte big-endian scalar. Zero is canonical and
// accepted because BIP-32 permits a zero tweak even though private keys may not
// themselves be zero.
func (z *Element) SetBytes(b *[Size]byte) bool {
	words := bytesToWords(b)
	if !LessThanOrderWords(words) {
		return false
	}
	in := fiat.NonMontgomeryDomainFieldElement(words)
	fiat.ToMontgomery(&z.x, &in)
	return true
}

// LessThanOrder reports whether b is a canonical scalar encoding.
func LessThanOrder(b *[Size]byte) bool {
	return LessThanOrderWords(bytesToWords(b))
}

// LessThanOrderWords reports whether little-endian words are less than n. All
// limbs are processed regardless of the input value.
func LessThanOrderWords(words [4]uint64) bool {
	_, borrow := bits.Sub64(words[0], order0, 0)
	_, borrow = bits.Sub64(words[1], order1, borrow)
	_, borrow = bits.Sub64(words[2], order2, borrow)
	_, borrow = bits.Sub64(words[3], order3, borrow)
	return borrow == 1
}

// Add assigns z = x + y mod n.
func (z *Element) Add(x, y *Element) *Element {
	fiat.Add(&z.x, &x.x, &y.x)
	return z
}

// IsZero reports whether z is zero.
func (z *Element) IsZero() bool {
	return z.x == fiat.MontgomeryDomainFieldElement{}
}

// Equal reports whether z and x represent the same scalar.
func (z *Element) Equal(x *Element) bool {
	return z.x == x.x
}

// Bytes returns the canonical big-endian encoding of z.
func (z *Element) Bytes() [Size]byte {
	return wordsToBytes(z.Words())
}

// Words returns canonical little-endian non-Montgomery limbs.
func (z *Element) Words() [4]uint64 {
	var out fiat.NonMontgomeryDomainFieldElement
	fiat.FromMontgomery(&out, &z.x)
	return [4]uint64(out)
}

func bytesToWords(b *[Size]byte) [4]uint64 {
	return [4]uint64{
		binary.BigEndian.Uint64(b[24:32]),
		binary.BigEndian.Uint64(b[16:24]),
		binary.BigEndian.Uint64(b[8:16]),
		binary.BigEndian.Uint64(b[0:8]),
	}
}

func wordsToBytes(words [4]uint64) (out [Size]byte) {
	binary.BigEndian.PutUint64(out[0:8], words[3])
	binary.BigEndian.PutUint64(out[8:16], words[2])
	binary.BigEndian.PutUint64(out[16:24], words[1])
	binary.BigEndian.PutUint64(out[24:32], words[0])
	return out
}
