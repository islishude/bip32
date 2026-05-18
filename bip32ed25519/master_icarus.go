package bip32ed25519

import (
	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
)

// NewMasterKeyIcarus creates a root XPrv using the CIP-0003 Icarus algorithm.
//
// The seed is the upper-layer entropy input, and password is the optional
// Icarus passphrase bytes. Do not pass a BIP39 64-byte PBKDF2 seed unless that
// is explicitly the system you are defining.
func NewMasterKeyIcarus(seed, password []byte) (*XPrv, error) {
	if len(seed) == 0 {
		return nil, ErrInvalidSeed
	}

	// CIP-0003 Icarus: PBKDF2-HMAC-SHA512(password, seed, 4096, 96).
	data := pbkdf2.Key(password, seed, 4096, XPrvSize, sha512.New)
	tweakRootBits(data[0:32])

	var out XPrv
	copy(out.kL[:], data[0:32])
	copy(out.kR[:], data[32:64])
	copy(out.cc[:], data[64:96])
	if out.isZeroScalar() {
		return nil, ErrInvalidXPrv
	}
	return &out, nil
}

func tweakRootBits(kL []byte) {
	if len(kL) != 32 {
		panic("bip32ed25519: kL must be 32 bytes")
	}

	// Root tweak keeps kL in the expanded Ed25519 scalar shape required by HDKD.
	kL[0] &= 0b11111000
	kL[31] &= 0b00011111
	kL[31] |= 0b01000000
}
