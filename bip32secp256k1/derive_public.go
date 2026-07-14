package bip32secp256k1

import internalsecp "github.com/islishude/bip32/v2/internal/secp256k1"

// Derive derives the exact normal public child at index.
func (p *XPub) Derive(index uint32) (*XPub, error) {
	return p.derive(index, hmacSHA512)
}

func (p *XPub) derive(index uint32, mac hmac512Func) (*XPub, error) {
	if p == nil {
		return nil, ErrNilKey
	}
	if IsHardened(index) {
		return nil, ErrHardenedFromXPub
	}
	if p.depth == MaxDepth {
		return nil, ErrDepthOverflow
	}

	var data [PublicKeySize + 4]byte
	copy(data[:PublicKeySize], p.pub[:])
	indexBE := ser32BE(index)
	copy(data[PublicKeySize:], indexBE[:])

	i := mac(p.cc[:], data[:])
	defer clear(i[:])
	var tweak [PrivateKeySize]byte
	copy(tweak[:], i[:PrivateKeySize])
	defer clear(tweak[:])

	childPub, ok := internalsecp.AddScalarBase(&p.pub, &tweak)
	if !ok {
		return nil, ErrInvalidChild
	}
	child := &XPub{
		pub:               childPub,
		network:           p.network,
		depth:             p.depth + 1,
		parentFingerprint: keyFingerprint(p.pub),
		childNumber:       index,
	}
	copy(child.cc[:], i[PrivateKeySize:])
	return child, nil
}

// DeriveRelativePath derives a normal path relative to this extended public
// key. Any hardened segment returns ErrHardenedFromXPub.
func (p *XPub) DeriveRelativePath(path string) (*XPub, error) {
	if p == nil {
		return nil, ErrNilKey
	}
	indexes, err := ParseRelativePath(path)
	if err != nil {
		return nil, err
	}
	child := p.clone()
	for _, index := range indexes {
		child, err = child.Derive(index)
		if err != nil {
			return nil, err
		}
	}
	return child, nil
}
