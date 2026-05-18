package bip32ed25519

import "filippo.io/edwards25519"

// XPrv is a Cardano/Khovratovich-Law extended private key.
//
// Its binary form is kL || kR || chainCode. Metadata fields are kept only in
// memory and are intentionally excluded from Bytes.
type XPrv struct {
	kL [32]byte
	kR [32]byte
	cc [32]byte

	depth       uint32
	childNumber uint32
	path        []uint32
}

// XPub is a Cardano/Khovratovich-Law extended public key.
//
// Its binary form is publicKey || chainCode. The chain code is sensitive from a
// privacy perspective because it allows soft descendant public-key derivation.
type XPub struct {
	pub [32]byte
	cc  [32]byte

	depth       uint32
	childNumber uint32
}

// NewXPrvFromBytes imports a 96-byte kL || kR || chainCode value.
func NewXPrvFromBytes(b []byte) (*XPrv, error) {
	if len(b) != XPrvSize {
		return nil, ErrInvalidXPrv
	}

	var k XPrv
	copy(k.kL[:], b[0:32])
	copy(k.kR[:], b[32:64])
	copy(k.cc[:], b[64:96])

	// Imported child keys must preserve Ed25519 expanded-scalar bit invariants.
	if !validExpandedScalarBits(k.kL) || k.isZeroScalar() {
		return nil, ErrInvalidXPrv
	}

	return &k, nil
}

// NewXPubFromBytes imports a 64-byte publicKey || chainCode value.
func NewXPubFromBytes(b []byte) (*XPub, error) {
	if len(b) != XPubSize {
		return nil, ErrInvalidXPub
	}
	// Validate the compressed public key before storing the chain code.
	if _, err := new(edwards25519.Point).SetBytes(b[0:32]); err != nil {
		return nil, ErrInvalidXPub
	}

	var p XPub
	copy(p.pub[:], b[0:32])
	copy(p.cc[:], b[32:64])
	return &p, nil
}

// Bytes returns a copy of the 96-byte CIP-16 binary XPrv serialization.
func (k *XPrv) Bytes() []byte {
	if k == nil {
		return nil
	}
	out := make([]byte, XPrvSize)
	copy(out[0:32], k.kL[:])
	copy(out[32:64], k.kR[:])
	copy(out[64:96], k.cc[:])
	return out
}

// ExtendedPrivateKey returns a copy of kL || kR without the chain code.
func (k *XPrv) ExtendedPrivateKey() []byte {
	if k == nil {
		return nil
	}
	out := make([]byte, ScalarSize+PrefixSize)
	copy(out[0:32], k.kL[:])
	copy(out[32:64], k.kR[:])
	return out
}

// ChainCode returns a copy of the XPrv chain code.
func (k *XPrv) ChainCode() []byte {
	if k == nil {
		return nil
	}
	out := make([]byte, ChainCodeSize)
	copy(out, k.cc[:])
	return out
}

// Path returns a copy of the in-memory derivation path metadata.
func (k *XPrv) Path() []uint32 {
	if k == nil {
		return nil
	}
	return append([]uint32(nil), k.path...)
}

// Depth returns the in-memory derivation depth metadata.
func (k *XPrv) Depth() uint32 {
	if k == nil {
		return 0
	}
	return k.depth
}

// ChildNumber returns the in-memory child-number metadata.
func (k *XPrv) ChildNumber() uint32 {
	if k == nil {
		return 0
	}
	return k.childNumber
}

// Wipe clears key material in this XPrv instance on a best-effort basis.
//
// Go can still leave copies in stack frames, heap moves, or caller-owned slices.
func (k *XPrv) Wipe() {
	if k == nil {
		return
	}
	clear(k.kL[:])
	clear(k.kR[:])
	clear(k.cc[:])
	clear(k.path)
	k.path = nil
	k.depth = 0
	k.childNumber = 0
}

// Bytes returns a copy of the 64-byte CIP-16 binary XPub serialization.
func (p *XPub) Bytes() []byte {
	if p == nil {
		return nil
	}
	out := make([]byte, XPubSize)
	copy(out[0:32], p.pub[:])
	copy(out[32:64], p.cc[:])
	return out
}

// PublicKey returns the compressed 32-byte Ed25519 public key.
func (p *XPub) PublicKey() [32]byte {
	if p == nil {
		return [32]byte{}
	}
	return p.pub
}

// ChainCode returns a copy of the XPub chain code.
func (p *XPub) ChainCode() []byte {
	if p == nil {
		return nil
	}
	out := make([]byte, ChainCodeSize)
	copy(out, p.cc[:])
	return out
}

// Depth returns the in-memory derivation depth metadata.
func (p *XPub) Depth() uint32 {
	if p == nil {
		return 0
	}
	return p.depth
}

// ChildNumber returns the in-memory child-number metadata.
func (p *XPub) ChildNumber() uint32 {
	if p == nil {
		return 0
	}
	return p.childNumber
}

func validExpandedScalarBits(kL [32]byte) bool {
	// Child kL may have bit 0x20 set, so do not enforce the stricter root rule.
	if kL[0]&0b00000111 != 0 {
		return false
	}
	if kL[31]&0b10000000 != 0 {
		return false
	}
	if kL[31]&0b01000000 == 0 {
		return false
	}
	return true
}

func (k *XPrv) isZeroScalar() bool {
	if k == nil {
		return true
	}
	s, err := scalarFromLE32ModL(k.kL)
	if err != nil {
		return true
	}
	// Compare after reduction modulo L to reject the zero scalar class.
	return s.Equal(new(edwards25519.Scalar)) == 1
}

func (k *XPrv) clone() *XPrv {
	if k == nil {
		return nil
	}
	out := *k
	out.path = append([]uint32(nil), k.path...)
	return &out
}

func (p *XPub) clone() *XPub {
	if p == nil {
		return nil
	}
	out := *p
	return &out
}
