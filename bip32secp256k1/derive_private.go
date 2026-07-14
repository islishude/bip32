package bip32secp256k1

import internalsecp "github.com/islishude/bip32/v2/internal/secp256k1"

// Derive derives the exact private child at index. Invalid-child conditions
// return ErrInvalidChild; the method never silently advances to index+1.
func (k *XPrv) Derive(index uint32) (*XPrv, error) {
	return k.derive(index, hmacSHA512)
}

func (k *XPrv) derive(index uint32, mac hmac512Func) (*XPrv, error) {
	if k == nil {
		return nil, ErrNilKey
	}
	if k.depth == MaxDepth {
		return nil, ErrDepthOverflow
	}

	parentPub, err := k.PublicKey()
	if err != nil {
		return nil, err
	}

	var data [PublicKeySize + 4]byte
	defer clear(data[:])
	if IsHardened(index) {
		data[0] = 0
		copy(data[1:PublicKeySize], k.key[:])
	} else {
		copy(data[:PublicKeySize], parentPub[:])
	}
	indexBE := ser32BE(index)
	copy(data[PublicKeySize:], indexBE[:])

	i := mac(k.cc[:], data[:])
	defer clear(i[:])
	var tweak [PrivateKeySize]byte
	copy(tweak[:], i[:PrivateKeySize])
	defer clear(tweak[:])

	childKey, ok := internalsecp.AddScalars(&k.key, &tweak)
	if !ok {
		return nil, ErrInvalidChild
	}
	child := &XPrv{
		key:               childKey,
		network:           k.network,
		depth:             k.depth + 1,
		parentFingerprint: keyFingerprint(parentPub),
		childNumber:       index,
	}
	copy(child.cc[:], i[PrivateKeySize:])
	clear(childKey[:])
	return child, nil
}

// DerivePath derives an absolute path rooted at this master key.
func (k *XPrv) DerivePath(path string) (*XPrv, error) {
	if k == nil {
		return nil, ErrNilKey
	}
	if !k.isRoot() {
		return nil, ErrNotRoot
	}
	indexes, err := ParseAbsolutePath(path)
	if err != nil {
		return nil, err
	}
	return k.deriveIndexes(indexes)
}

// DeriveRelativePath derives a path relative to this extended private key.
func (k *XPrv) DeriveRelativePath(path string) (*XPrv, error) {
	if k == nil {
		return nil, ErrNilKey
	}
	indexes, err := ParseRelativePath(path)
	if err != nil {
		return nil, err
	}
	return k.deriveIndexes(indexes)
}

func (k *XPrv) deriveIndexes(indexes []uint32) (*XPrv, error) {
	child := k.clone()
	for _, index := range indexes {
		next, err := child.Derive(index)
		if err != nil {
			child.Wipe()
			return nil, err
		}
		child.Wipe()
		child = next
	}
	return child, nil
}
