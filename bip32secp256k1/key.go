package bip32secp256k1

import internalsecp "github.com/islishude/bip32/v2/internal/secp256k1"

// XPrv is a standard BIP-32 extended private key.
type XPrv struct {
	key [PrivateKeySize]byte
	cc  [ChainCodeSize]byte

	network           Network
	depth             uint8
	parentFingerprint [FingerprintSize]byte
	childNumber       uint32
}

// XPub is a standard BIP-32 extended public key.
type XPub struct {
	pub [PublicKeySize]byte
	cc  [ChainCodeSize]byte

	network           Network
	depth             uint8
	parentFingerprint [FingerprintSize]byte
	childNumber       uint32
}

// PrivateKey returns a copy of the canonical 32-byte private key.
func (k *XPrv) PrivateKey() []byte {
	if k == nil {
		return nil
	}
	out := make([]byte, PrivateKeySize)
	copy(out, k.key[:])
	return out
}

// PublicKey returns the matching compressed SEC 1 public key.
func (k *XPrv) PublicKey() ([PublicKeySize]byte, error) {
	if k == nil {
		return [PublicKeySize]byte{}, ErrNilKey
	}
	pub, ok := internalsecp.PublicKeyFromScalar(&k.key)
	if !ok {
		return [PublicKeySize]byte{}, ErrInvalidXPrv
	}
	return pub, nil
}

// XPub returns the matching extended public key and preserves all serialized
// metadata and network version selection.
func (k *XPrv) XPub() (*XPub, error) {
	if k == nil {
		return nil, ErrNilKey
	}
	pub, err := k.PublicKey()
	if err != nil {
		return nil, err
	}
	return &XPub{
		pub:               pub,
		cc:                k.cc,
		network:           k.network,
		depth:             k.depth,
		parentFingerprint: k.parentFingerprint,
		childNumber:       k.childNumber,
	}, nil
}

// PublicKey returns the compressed SEC 1 public key.
func (p *XPub) PublicKey() [PublicKeySize]byte {
	if p == nil {
		return [PublicKeySize]byte{}
	}
	return p.pub
}

// ChainCode returns a copy of the private extended key's chain code.
func (k *XPrv) ChainCode() []byte {
	if k == nil {
		return nil
	}
	out := make([]byte, ChainCodeSize)
	copy(out, k.cc[:])
	return out
}

// ChainCode returns a copy of the public extended key's chain code.
func (p *XPub) ChainCode() []byte {
	if p == nil {
		return nil
	}
	out := make([]byte, ChainCodeSize)
	copy(out, p.cc[:])
	return out
}

// Network returns the version network encoded by this extended private key.
func (k *XPrv) Network() Network {
	if k == nil {
		return 0
	}
	return k.network
}

// Network returns the version network encoded by this extended public key.
func (p *XPub) Network() Network {
	if p == nil {
		return 0
	}
	return p.network
}

// Depth returns the key's derivation depth.
func (k *XPrv) Depth() uint8 {
	if k == nil {
		return 0
	}
	return k.depth
}

// Depth returns the key's derivation depth.
func (p *XPub) Depth() uint8 {
	if p == nil {
		return 0
	}
	return p.depth
}

// ParentFingerprint returns the first four bytes of HASH160(parent public key).
func (k *XPrv) ParentFingerprint() [FingerprintSize]byte {
	if k == nil {
		return [FingerprintSize]byte{}
	}
	return k.parentFingerprint
}

// ParentFingerprint returns the first four bytes of HASH160(parent public key).
func (p *XPub) ParentFingerprint() [FingerprintSize]byte {
	if p == nil {
		return [FingerprintSize]byte{}
	}
	return p.parentFingerprint
}

// ChildNumber returns the exact index used to derive this key.
func (k *XPrv) ChildNumber() uint32 {
	if k == nil {
		return 0
	}
	return k.childNumber
}

// ChildNumber returns the exact index used to derive this key.
func (p *XPub) ChildNumber() uint32 {
	if p == nil {
		return 0
	}
	return p.childNumber
}

// Wipe clears key material in this XPrv instance on a best-effort basis. Go
// can retain copies in stack frames, heap moves, returned slices, or encodings.
func (k *XPrv) Wipe() {
	if k == nil {
		return
	}
	clear(k.key[:])
	clear(k.cc[:])
	k.network = 0
	k.depth = 0
	clear(k.parentFingerprint[:])
	k.childNumber = 0
}

func (k *XPrv) clone() *XPrv {
	if k == nil {
		return nil
	}
	out := *k
	return &out
}

func (p *XPub) clone() *XPub {
	if p == nil {
		return nil
	}
	out := *p
	return &out
}

func (k *XPrv) isRoot() bool {
	return k != nil && k.depth == 0 && k.parentFingerprint == [FingerprintSize]byte{} && k.childNumber == 0
}
