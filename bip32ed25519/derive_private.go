package bip32ed25519

// Derive derives a private child key for hardened and soft indexes.
func (k *XPrv) Derive(index uint32) (*XPrv, error) {
	if k == nil {
		return nil, ErrNilKey
	}
	if k.depth >= MaxDepth {
		return nil, ErrDepthOverflow
	}

	parentPub, err := k.PublicKey()
	if err != nil {
		return nil, err
	}

	indexLE := ser32LE(index)

	var zInput []byte
	var ccInput []byte

	if IsHardened(index) {
		zInput = make([]byte, 0, 1+64+4)
		zInput = append(zInput, 0x00) // Z domain: hardened private derivation.
		zInput = append(zInput, k.kL[:]...)
		zInput = append(zInput, k.kR[:]...)
		zInput = append(zInput, indexLE[:]...) // ED25519-BIP32 uses little-endian ser32.

		ccInput = make([]byte, 0, 1+64+4)
		ccInput = append(ccInput, 0x01) // I domain: hardened child chain code.
		ccInput = append(ccInput, k.kL[:]...)
		ccInput = append(ccInput, k.kR[:]...)
		ccInput = append(ccInput, indexLE[:]...)
	} else {
		zInput = make([]byte, 0, 1+32+4)
		zInput = append(zInput, 0x02) // Z domain: soft public-compatible derivation.
		zInput = append(zInput, parentPub[:]...)
		zInput = append(zInput, indexLE[:]...)

		ccInput = make([]byte, 0, 1+32+4)
		ccInput = append(ccInput, 0x03) // I domain: soft child chain code.
		ccInput = append(ccInput, parentPub[:]...)
		ccInput = append(ccInput, indexLE[:]...)
	}

	z := hmacSHA512(k.cc[:], zInput)
	i := hmacSHA512(k.cc[:], ccInput)

	child := &XPrv{
		depth:       k.depth + 1,
		childNumber: index,
		path:        append(append([]uint32(nil), k.path...), index),
	}

	copy(child.kL[:], k.kL[:])
	// Only Z[0:28] is used for kL, and the protocol multiplies it by 8.
	if overflow := add28Mul8LE(&child.kL, z[0:28]); overflow {
		return nil, ErrInvalidChild
	}

	copy(child.kR[:], k.kR[:])
	addMod256LE(&child.kR, z[32:64]) // kR addition is modulo 2^256.

	copy(child.cc[:], i[32:64]) // Chain code comes from the right half of I.

	if child.isZeroScalar() {
		return nil, ErrInvalidChild
	}

	return child, nil
}

// DerivePath derives an absolute path such as m/1852'/1815'/0'/0/0.
func (k *XPrv) DerivePath(path string) (*XPrv, error) {
	if k == nil {
		return nil, ErrNilKey
	}

	indexes, err := ParseAbsolutePath(path)
	if err != nil {
		return nil, err
	}

	child := k.clone()
	for _, index := range indexes {
		child, err = child.Derive(index)
		if err != nil {
			return nil, err
		}
	}
	return child, nil
}
