package bip32

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"

	"github.com/islishude/bip32/internal/edwards25519"
)

const (
	XPrvSize  = 96
	XPubSize  = 64
	HardIndex = 0x80000000
)

type XPrv struct {
	xprv []byte
}

func NewXPrv(raw []byte) XPrv {
	if len(raw) != 96 {
		panic("xprv size should be 96 bytes")
	}

	if (raw[0] & 0b0000_0111) != 0b0000_0000 {
		panic("the lowest 3 bits of the first byte of seed should be cleared")
	}

	if (raw[31] & 0b1100_0000) != 0b0100_0000 {
		panic("the highest bit of the last byte of seed should be cleared")
	}

	return XPrv{xprv: append([]byte(nil), raw...)}
}

func NewRootXPrv(seed []byte) XPrv {
	// Let ˜k(seed) be 256-bit master secret
	// Then derive k = H512(˜k)and denote its left 32-byte by kL and right one by kR.
	secretKey := sha512.Sum512(seed[:32])

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

	// Derive c ← H256(0x01||˜k), where H256 is SHA-256, and call it the root chain code
	chaincode := sha256.Sum256(append([]byte{1}, seed...))
	copy(xprv[64:], chaincode[:])
	return XPrv{xprv}
}

func (x XPrv) String() string {
	return hex.EncodeToString(x.xprv)
}

func (x XPrv) Bytes() []byte {
	return append([]byte(nil), x.xprv...)
}

func (x XPrv) ChainCode() []byte {
	return append([]byte(nil), x.xprv[64:]...)
}

func (x XPrv) Derive(index uint32) XPrv {
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
		_, _ = zmac.Write([]byte{0})
		_, _ = zmac.Write(ekey)
		_, _ = zmac.Write(seri)

		_, _ = imac.Write([]byte{1})
		_, _ = imac.Write(ekey)
		_, _ = imac.Write(seri)
	} else {
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
	copy(result[0:32], add28Mul8(kl, zl)[:])   // kl
	copy(result[32:64], add256Bits(kr, zr)[:]) // kr
	copy(result[64:96], iout[32:])             // chain code

	return XPrv{result}
}

func (x XPrv) PublicKey() ed25519.PublicKey {
	var A edwards25519.ExtendedGroupElement

	var hBytes [32]byte
	copy(hBytes[:], x.xprv[:32]) // make sure prvkey is 32 bytes

	edwards25519.GeScalarMultBase(&A, &hBytes)
	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)

	return publicKeyBytes[:]
}

func (x XPrv) Sign(message []byte) []byte {
	var hashOut [64]byte

	h := sha512.New()
	_, _ = h.Write(x.xprv[32:]) // write kr
	_, _ = h.Write(message)     // write msg
	h.Sum(hashOut[:0])

	var nonce [32]byte
	edwards25519.ScReduce(&nonce, &hashOut)

	var signature [ed25519.SignatureSize]byte
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &nonce)

	var r [32]byte
	R.ToBytes(&r)

	copy(signature[:32], r[:])
	copy(signature[32:], x.PublicKey())

	h.Reset()

	var hramDigest [64]byte
	_, _ = h.Write(signature[:]) // write signature
	_, _ = h.Write(message)      // write msg
	h.Sum(hramDigest[:0])

	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	var private32 [32]byte
	copy(private32[:], x.xprv[0:32])

	var s [32]byte

	edwards25519.ScMulAdd(&s, &hramDigestReduced, &private32, &nonce)
	copy(signature[:], r[:])
	copy(signature[32:], s[:])

	return signature[:]
}

func (x XPrv) Verify(msg, sig []byte) bool {
	return ed25519.Verify(x.PublicKey(), msg, sig)
}

func (x XPrv) XPub() XPub {
	var xpub [64]byte
	copy(xpub[:32], x.PublicKey())
	copy(xpub[32:], x.xprv[64:96])
	return XPub{xpub: xpub[:]}
}
