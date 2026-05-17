package bip32

import (
	"bytes"
	"math/big"

	"filippo.io/edwards25519"
)

// ed25519BaseOrder is the prime-order subgroup size:
// 2^252 + 27742317777372353535851937790883648493.
var ed25519BaseOrder = func() *big.Int {
	order := new(big.Int).Lsh(big.NewInt(1), 252)
	addend, ok := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	if !ok {
		panic("bip32-ed25519: invalid ed25519 base order")
	}
	return order.Add(order, addend)
}()

// add28Mul8 computes kl + 8 * trunc28(zl) as a 32-byte little-endian value.
// Only the first 28 bytes of zl are used, which is the BIP32-Ed25519 rule
// that keeps child private scalars within the safe clamping bit range.
func add28Mul8(kl, zl []byte) *[32]byte {
	var carry uint16 = 0
	var out [32]byte

	for i := range 28 {
		// zl[i] << 3 is multiplication by 8 in little-endian limb order.
		r := uint16(kl[i]) + uint16(zl[i])<<3 + carry
		out[i] = byte(r & 0xff)
		carry = r >> 8
	}

	// Propagate carry through the untouched high 4 bytes of kL.
	for i := 28; i < 32; i++ {
		r := uint16(kl[i]) + carry
		out[i] = byte(r & 0xff)
		carry = r >> 8
	}

	return &out
}

// add256Bits computes kr + zr mod 2^256 as a 32-byte little-endian value.
func add256Bits(kr, zr []byte) *[32]byte {
	var carry uint16 = 0
	var out [32]byte

	for i := range 32 {
		r := uint16(kr[i]) + uint16(zr[i]) + carry
		out[i] = byte(r) // Dropping carry after byte 31 gives modulo 2^256.
		carry = r >> 8
	}

	return &out
}

// pointOfTrunc28Mul8 returns [8 * trunc28(zl)]B encoded as an Edwards25519 point.
func pointOfTrunc28Mul8(zl []byte) *[32]byte {
	scalarBytes := add28Mul8(make([]byte, 32), zl)
	var wideBytes [64]byte
	// SetUniformBytes accepts a 64-byte wide scalar and reduces it internally.
	copy(wideBytes[:32], scalarBytes[:])
	scalar, _ := edwards25519.NewScalar().SetUniformBytes(wideBytes[:])
	Ap := edwards25519.NewIdentityPoint().ScalarBaseMult(scalar)

	var zl8b [32]byte
	copy(zl8b[:], Ap.Bytes())
	return &zl8b
}

// pointPlus adds two compressed Edwards25519 points and returns the compressed sum.
func pointPlus(pk, zl8 *[32]byte) (*[32]byte, bool) {
	a, err := edwards25519.NewIdentityPoint().SetBytes(pk[:])
	if err != nil {
		return nil, false
	}

	b, err := edwards25519.NewIdentityPoint().SetBytes(zl8[:])
	if err != nil {
		return nil, false
	}

	r := edwards25519.NewIdentityPoint().Add(a, b)

	var res [32]byte
	copy(res[:], r.Bytes())

	return &res, true
}

// isDivisibleByEd25519BaseOrder reports the private-child discard condition.
// kl is interpreted as a little-endian integer, matching the paper.
func isDivisibleByEd25519BaseOrder(kl []byte) bool {
	value := littleEndianBytesToBigInt(kl)
	return new(big.Int).Mod(value, ed25519BaseOrder).Sign() == 0
}

// littleEndianBytesToBigInt converts protocol byte order into math/big order.
func littleEndianBytesToBigInt(in []byte) *big.Int {
	be := make([]byte, len(in))
	for i := range in {
		be[len(in)-1-i] = in[i]
	}
	return new(big.Int).SetBytes(be)
}

// isIdentityPointEncoding reports the public-child discard condition.
// Edwards25519 encodes the identity point (0, 1) as little-endian y=1 with sign bit 0.
func isIdentityPointEncoding(pk []byte) bool {
	var identity [32]byte
	identity[0] = 1
	return bytes.Equal(pk, identity[:])
}
