package bip32ed25519

import "filippo.io/edwards25519"

// Derive derives a soft public child key.
//
// Hardened public derivation is impossible and returns ErrHardenedFromXPub.
func (p *XPub) Derive(index uint32) (*XPub, error) {
	if p == nil {
		return nil, ErrNilKey
	}
	if IsHardened(index) {
		return nil, ErrHardenedFromXPub
	}
	if p.depth >= MaxDepth {
		return nil, ErrDepthOverflow
	}

	indexLE := ser32LE(index)

	zInput := make([]byte, 0, 1+32+4)
	zInput = append(zInput, 0x02) // Same Z domain used by soft private derivation.
	zInput = append(zInput, p.pub[:]...)
	zInput = append(zInput, indexLE[:]...)

	z := hmacSHA512(p.cc[:], zInput)

	// Public derivation adds [8 * Z[0:28]]B to the parent public point.
	tweak, err := scalarFromZL28Times8(z[0:28])
	if err != nil {
		return nil, err
	}

	parentPoint, err := new(edwards25519.Point).SetBytes(p.pub[:])
	if err != nil {
		return nil, ErrInvalidXPub
	}

	tweakPoint := new(edwards25519.Point).ScalarBaseMult(tweak)
	childPoint := new(edwards25519.Point).Add(parentPoint, tweakPoint)
	if childPoint.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, ErrInvalidChild
	}

	ccInput := make([]byte, 0, 1+32+4)
	ccInput = append(ccInput, 0x03) // I domain: soft child chain code.
	ccInput = append(ccInput, p.pub[:]...)
	ccInput = append(ccInput, indexLE[:]...)

	i := hmacSHA512(p.cc[:], ccInput)

	child := &XPub{
		depth:       p.depth + 1,
		childNumber: index,
	}
	copy(child.pub[:], childPoint.Bytes())
	copy(child.cc[:], i[32:64]) // Chain code comes from the right half of I.

	return child, nil
}

// DeriveRelativePath derives a soft relative path such as 0/0 from an XPub.
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
