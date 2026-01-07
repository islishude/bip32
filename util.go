package bip32

import "filippo.io/edwards25519"

func add28Mul8(kl, zl []byte) *[32]byte {
	var carry uint16 = 0
	var out [32]byte

	for i := 0; i < 28; i++ {
		r := uint16(kl[i]) + uint16(zl[i])<<3 + carry
		out[i] = byte(r & 0xff)
		carry = r >> 8
	}

	for i := 28; i < 32; i++ {
		r := uint16(kl[i]) + carry
		out[i] = byte(r & 0xff)
		carry = r >> 8
	}

	return &out
}

func add256Bits(kr, zr []byte) *[32]byte {
	var carry uint16 = 0
	var out [32]byte

	for i := 0; i < 32; i++ {
		r := uint16(kr[i]) + uint16(zr[i]) + carry
		out[i] = byte(r)
		carry = r >> 8
	}

	return &out
}

func pointOfTrunc28Mul8(zl []byte) *[32]byte {
	scalarBytes := add28Mul8(make([]byte, 32), zl)
	var wideBytes [64]byte
	copy(wideBytes[:32], scalarBytes[:])
	scalar, _ := edwards25519.NewScalar().SetUniformBytes(wideBytes[:])
	Ap := edwards25519.NewIdentityPoint().ScalarBaseMult(scalar)

	var zl8b [32]byte
	copy(zl8b[:], Ap.Bytes())
	return &zl8b
}

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
