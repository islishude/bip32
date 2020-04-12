package bip32

import "github.com/islishude/bip32/internal/edwards25519"

func add28Mul8(kl, zl []byte) []byte {
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

	return out[:]
}

func add256Bits(kr, zr []byte) []byte {
	var carry uint16 = 0
	var out [32]byte

	for i := 0; i < 32; i++ {
		r := uint16(kr[i]) + uint16(zr[i]) + carry
		out[i] = byte(r & 0xff)
		carry = r >> 8
	}

	return out[:]
}

func pointLeft(pubkey, zl []byte) []byte {
	var hBytes [32]byte
	kl := make([]byte, 32)
	copy(hBytes[:], add28Mul8(kl, zl)[:32])

	var A edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&A, &hBytes)

	var zl8b [32]byte
	A.ToBytes(&zl8b)

	var key [32]byte
	key[0] = 1

	var ap [32]byte
	copy(ap[:], pubkey)
	A.FromBytes(&ap)

	var Ai edwards25519.ProjectiveGroupElement
	edwards25519.GeDoubleScalarMultVartime(&Ai, &key, &A, &zl8b)
	Ai.ToBytes(&key)

	return key[:]
}
