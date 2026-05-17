package bip32

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"filippo.io/edwards25519"
)

const (
	XPrvSize  = 96
	XPubSize  = 64
	HardIndex = 0x80000000
)

// XPrv is an extended private key for BIP32-Ed25519.
// The encoded layout is kL || kR || chainCode, each 32 bytes.
type XPrv struct {
	xprv []byte
}

// NewXPrv creates XPrv from raw extended private key bytes.
// It validates the Ed25519 clamping bits that BIP32-Ed25519 relies on.
func NewXPrv(raw []byte) (XPrv, error) {
	if len(raw) != XPrvSize {
		return XPrv{}, errors.New("bip32-ed25519: NewXPrv: size should be 96 bytes")
	}

	// kL must stay divisible by 8 to preserve the Ed25519 subgroup invariant.
	if (raw[0] & 0b0000_0111) != 0b0000_0000 {
		return XPrv{}, errors.New("bip32-ed25519: NewXPrv: the lowest 3 bits of the first byte of seed should be cleared")
	}

	// Serialized derived keys only require the top two bits to be 01.
	// Root-key constructors enforce the stricter third-highest-bit rule.
	if (raw[31] & 0b1100_0000) != 0b0100_0000 {
		return XPrv{}, errors.New("bip32-ed25519: NewXPrv: the highest bit of the last byte of seed should be cleared, and the second highest bit should be set")
	}

	return XPrv{xprv: append([]byte(nil), raw...)}, nil
}

// NewRootXPrv creates XPrv by seed(bip39), the seed size should be 32 bytes at least.
// For strict BIP32-Ed25519 root key validation, use NewRootXPrvStrict.
func NewRootXPrv(seed []byte) XPrv {
	if len(seed) < 32 {
		panic("bip32-ed25519: NewRootXPrv: seed size should be at least 32 bytes")
	}

	// Keep legacy behavior: only the first 32 bytes are the master secret,
	// while the full seed is still fed into the historical chain-code hash.
	xprv, _ := newRootXPrv(seed[:32], seed, false)
	return xprv
}

// NewRootXPrvStrict creates XPrv from a 32-byte master secret according to BIP32-Ed25519.
func NewRootXPrvStrict(seed []byte) (XPrv, error) {
	if len(seed) != 32 {
		return XPrv{}, errors.New("bip32-ed25519: NewRootXPrvStrict: seed size should be 32 bytes")
	}

	return newRootXPrv(seed, seed, true)
}

// newRootXPrv expands a master secret and root chain-code seed into kL || kR || c.
// When strict is true it implements the paper's "discard master secret" rule.
func newRootXPrv(secret, chainSeed []byte, strict bool) (XPrv, error) {
	// Let k(seed) be a 256-bit master secret.
	// Then derive k = H512(k) and denote its left 32-byte by kL and right one by kR.
	secretKey := sha512.Sum512(secret)

	// BIP32-Ed25519 requires this bit to be zero before clamping so that all
	// descendants keep the Ed25519 clamping bits for paths up to depth 2^20.
	if strict && (secretKey[31]&0b0010_0000) != 0 {
		return XPrv{}, errors.New("bip32-ed25519: NewRootXPrvStrict: the third highest bit of the last byte of hashed seed should be cleared")
	}

	// Modify kL:
	// the lowest 3 bits of the first byte are cleared
	secretKey[0] &= 0b1111_1000
	// the highest bit of the last byte is cleared
	// and third highest bit also should clear according bip32-ed25519 spec
	secretKey[31] &= 0b0101_1111
	// and the second highest bit of the last byte is set
	secretKey[31] |= 0b0100_0000

	xprv := make([]byte, XPrvSize)
	copy(xprv[:64], secretKey[:])

	// Derive c = H256(0x01 || k), where H256 is SHA-256, and call it the root chain code.
	// chainSeed is separate from secret to preserve NewRootXPrv's legacy long-seed behavior.
	chaincode := sha256.Sum256(append([]byte{1}, chainSeed...))
	copy(xprv[64:], chaincode[:])
	return XPrv{xprv}, nil
}

// String implements Stringer interface and returns plain hex string
func (x XPrv) String() string {
	return hex.EncodeToString(x.xprv)
}

// Bytes returns intenal bytes
func (x XPrv) Bytes() []byte {
	return append([]byte(nil), x.xprv...)
}

// ChainCode returns chain code bytes
func (x XPrv) ChainCode() []byte {
	return append([]byte(nil), x.xprv[64:]...)
}

// Derive derives a new XPrv by an index.
// It preserves the historical API and does not report the paper's discard condition.
func (x XPrv) Derive(index uint32) XPrv {
	result, _ := x.derive(index, false)
	return result
}

// DeriveStrict derives new XPrv by an index and rejects discarded children.
func (x XPrv) DeriveStrict(index uint32) (XPrv, error) {
	return x.derive(index, true)
}

// derive performs the private child-key derivation shared by legacy and strict APIs.
// strict only controls whether the rare "kL divisible by base order" child is rejected.
func (x XPrv) derive(index uint32, strict bool) (XPrv, error) {
	/*
		cP is the chain code.
		kP is (klP,krP) extended private key
		aP is the public key.
		ser32(i) serializes a uint32 i as a 4-byte little endian bytes

		If hardened child:
			let Z = HMAC-SHA512(Key = cP, Data = 0x00 || kP || ser32(i)).
			let I = HMAC-SHA512(Key = cP, Data = 0x01 || kP || ser32(i)).

		If normal child:
			let Z = HMAC-SHA512(Key = cP, Data = 0x02 || aP || ser32(i)).
			let I = HMAC-SHA512(Key = cP, Data = 0x03 || aP || ser32(i)).

		chain code
		The I is truncated to right 32 bytes.
	*/

	ekey := append([]byte(nil), x.xprv[:64]...)
	chaincode := append([]byte(nil), x.xprv[64:96]...)

	kl := append([]byte(nil), x.xprv[:32]...)
	kr := append([]byte(nil), x.xprv[32:64]...)

	zmac := hmac.New(sha512.New, chaincode)
	imac := hmac.New(sha512.New, chaincode)

	seri := make([]byte, 4)
	binary.LittleEndian.PutUint32(seri, index)

	if index >= HardIndex {
		// Hardened children bind the HMAC input to the private extended key.
		_, _ = zmac.Write([]byte{0})
		_, _ = zmac.Write(ekey)
		_, _ = zmac.Write(seri)

		_, _ = imac.Write([]byte{1})
		_, _ = imac.Write(ekey)
		_, _ = imac.Write(seri)
	} else {
		// Soft children use the parent public key so xpub derivation can match.
		pubkey := x.PublicKey()
		_, _ = zmac.Write([]byte{2})
		_, _ = zmac.Write(pubkey[:])
		_, _ = zmac.Write(seri)

		_, _ = imac.Write([]byte{3})
		_, _ = imac.Write(pubkey[:])
		_, _ = imac.Write(seri)
	}

	zout, iout := zmac.Sum(nil), imac.Sum(nil)
	zl, zr := zout[0:32], zout[32:64]

	result := make([]byte, 96)
	// The paper uses only the left 28 bytes of ZL and multiplies them by 8.
	copy(result[0:32], add28Mul8(kl, zl)[:])   // kl
	copy(result[32:64], add256Bits(kr, zr)[:]) // kr
	copy(result[64:96], iout[32:])             // chain code

	if strict && isDivisibleByEd25519BaseOrder(result[:32]) {
		return XPrv{}, errors.New("bip32-ed25519: XPrv.DeriveStrict: child private key is divisible by the ed25519 base order")
	}

	return XPrv{result}, nil
}

// DeriveHard derives new XPrv by a hardend index
func (x XPrv) DeriveHard(index uint32) XPrv {
	if index >= HardIndex {
		panic("bip32-ed25519: xprv.DeriveHard: overflow")
	}
	// Derive expects the final serialized child index, so add the hardening bit here.
	return x.Derive(HardIndex + index)
}

// PublicKey returns the public key
func (x XPrv) PublicKey() []byte {
	var hBytes [64]byte
	copy(hBytes[:32], x.xprv[:32]) // SetUniformBytes requires a 64-byte input.

	scalar, _ := edwards25519.NewScalar().SetUniformBytes(hBytes[:])
	A := edwards25519.NewIdentityPoint().ScalarBaseMult(scalar)

	return A.Bytes()
}

// Sign signs message
func (x XPrv) Sign(message []byte) []byte {
	var hsout [64]byte

	// Ed25519 derives the deterministic nonce from kR and the message.
	hasher := sha512.New()
	_, _ = hasher.Write(x.xprv[32:64])
	_, _ = hasher.Write(message)
	hasher.Sum(hsout[:0])

	nonce, _ := edwards25519.NewScalar().SetUniformBytes(hsout[:])

	R := edwards25519.NewIdentityPoint().ScalarBaseMult(nonce)
	r := R.Bytes()

	var sig [64]byte
	copy(sig[:32], r[:])
	copy(sig[32:], x.PublicKey()[:])

	// Challenge hash H(R || A || M), where A is the encoded public key.
	hasher.Reset()
	_, _ = hasher.Write(sig[:])
	_, _ = hasher.Write(message)
	hasher.Sum(hsout[:0])

	a, _ := edwards25519.NewScalar().SetUniformBytes(hsout[:])

	var bBytes [64]byte
	copy(bBytes[:32], x.xprv[:32])
	b, _ := edwards25519.NewScalar().SetUniformBytes(bBytes[:])

	// S = nonce + challenge * privateScalar, reduced by edwards25519.Scalar.
	s := edwards25519.NewScalar().MultiplyAdd(a, b, nonce)
	copy(sig[32:], s.Bytes())

	return sig[:]
}

// Verify verifies signature by message
func (x XPrv) Verify(msg, sig []byte) bool {
	return ed25519.Verify(x.PublicKey(), msg, sig)
}

// XPub returns extends public key for current XPrv
func (x XPrv) XPub() XPub {
	var xpub [64]byte
	// XPub stores the encoded public key with the same chain code.
	copy(xpub[:32], x.PublicKey())
	copy(xpub[32:], x.xprv[64:96])
	return XPub{xpub: xpub[:]}
}
