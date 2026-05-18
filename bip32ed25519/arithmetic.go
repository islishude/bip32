package bip32ed25519

import "filippo.io/edwards25519"

// add28Mul8LE adds 8 * ZL to dst, where ZL is the left 28 bytes of Z.
//
// The private derivation rule is integer addition over 32 little-endian bytes,
// not addition modulo the Ed25519 group order.
func add28Mul8LE(dst *[32]byte, zl []byte) (overflow bool) {
	if len(zl) != 28 {
		panic("bip32ed25519: ZL must be 28 bytes")
	}

	var shiftCarry uint16
	var addCarry uint16

	for i := range 32 {
		var addend uint16

		switch {
		case i < 28:
			v := (uint16(zl[i]) << 3) | shiftCarry // Multiplication by 8 in LE limb order.
			addend = v & 0xff
			shiftCarry = v >> 8
		case i == 28:
			addend = shiftCarry // Carry from byte 27 is the only contribution at byte 28.
			shiftCarry = 0
		default:
			addend = 0
		}

		sum := uint16(dst[i]) + addend + addCarry
		dst[i] = byte(sum)
		addCarry = sum >> 8
	}

	return shiftCarry != 0 || addCarry != 0
}

// addMod256LE adds x to dst modulo 2^256.
func addMod256LE(dst *[32]byte, x []byte) {
	if len(x) != 32 {
		panic("bip32ed25519: addend must be 32 bytes")
	}

	var carry uint16
	for i := range 32 {
		sum := uint16(dst[i]) + uint16(x[i]) + carry
		dst[i] = byte(sum)
		carry = sum >> 8
	}
	// The final carry is intentionally discarded to get modulo 2^256 behavior.
}

// scalarFromLE32ModL reduces a little-endian 32-byte integer modulo L.
func scalarFromLE32ModL(x [32]byte) (*edwards25519.Scalar, error) {
	var wide [64]byte
	copy(wide[0:32], x[:]) // SetUniformBytes expects a 64-byte wide input.
	return new(edwards25519.Scalar).SetUniformBytes(wide[:])
}

// scalarFromZL28Times8 converts 8 * Z[0:28] into a canonical scalar.
//
// Since 8 * ZL is smaller than the Ed25519 group order, SetCanonicalBytes is
// appropriate here. This is separate from scalarFromLE32ModL on purpose.
func scalarFromZL28Times8(zl []byte) (*edwards25519.Scalar, error) {
	if len(zl) != 28 {
		return nil, ErrInvalidTweak
	}

	var s [32]byte
	var carry uint16

	for i := range 28 {
		v := (uint16(zl[i]) << 3) | carry
		s[i] = byte(v)
		carry = v >> 8
	}
	s[28] = byte(carry) // Bytes 29..31 remain zero because ZL is only 28 bytes.

	return new(edwards25519.Scalar).SetCanonicalBytes(s[:])
}
