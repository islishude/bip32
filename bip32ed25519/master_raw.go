package bip32ed25519

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"io"
)

// NewMasterKeyRawKhovratovich creates a raw paper-style root key.
//
// This is not the Cardano Shelley/Icarus root derivation. It is provided for
// systems that explicitly need the Khovratovich-Law root algorithm.
func NewMasterKeyRawKhovratovich(secret32 []byte) (*XPrv, error) {
	if len(secret32) != 32 {
		return nil, ErrInvalidSeed
	}

	secret := sha512.Sum512(secret32)
	// The paper rejects master secrets when this pre-tweak bit is set.
	if secret[31]&0b00100000 != 0 {
		return nil, ErrRejectedMasterSecret
	}
	tweakRootBits(secret[0:32])

	chainInput := make([]byte, 0, 1+len(secret32))
	chainInput = append(chainInput, 0x01)
	chainInput = append(chainInput, secret32...)
	cc := sha256.Sum256(chainInput)

	var out XPrv
	copy(out.kL[:], secret[0:32])
	copy(out.kR[:], secret[32:64])
	copy(out.cc[:], cc[:])
	if out.isZeroScalar() {
		return nil, ErrInvalidXPrv
	}
	return &out, nil
}

// GenerateMasterKeyRawKhovratovich samples until the raw root secret is valid.
func GenerateMasterKeyRawKhovratovich(r io.Reader) (*XPrv, error) {
	if r == nil {
		r = rand.Reader
	}

	var secret [32]byte
	for {
		if _, err := io.ReadFull(r, secret[:]); err != nil {
			return nil, err
		}
		key, err := NewMasterKeyRawKhovratovich(secret[:])
		if err == nil {
			return key, nil
		}
		if err != ErrRejectedMasterSecret {
			return nil, err
		}
	}
}
