package bip32ed25519

import "filippo.io/edwards25519"

// PublicKey returns A = [kL]B as a compressed Ed25519 public key.
func (k *XPrv) PublicKey() ([32]byte, error) {
	if k == nil {
		return [32]byte{}, ErrNilKey
	}

	s, _ := scalarFromLE32ModL(k.kL)

	// kL is already an expanded scalar value, not a 32-byte Ed25519 seed.
	point := new(edwards25519.Point).ScalarBaseMult(s)
	var out [32]byte
	copy(out[:], point.Bytes())
	return out, nil
}

// XPub returns the matching extended public key with the same chain code.
func (k *XPrv) XPub() (*XPub, error) {
	if k == nil {
		return nil, ErrNilKey
	}

	pub, err := k.PublicKey()
	if err != nil {
		return nil, err
	}

	return &XPub{
		pub:         pub,
		cc:          k.cc,
		depth:       k.depth,
		childNumber: k.childNumber,
	}, nil
}
