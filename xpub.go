package bip32

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"strconv"

	"github.com/islishude/bip32/internal/edwards25519"
)

type XPub struct {
	xpub []byte
}

func (x XPub) PublicKey() ed25519.PublicKey {
	return append([]byte(nil), x.xpub[:32]...)
}

func (x XPub) Derive(index uint32) XPub {
	if index > HardIndex {
		panic("bip32: xpub: expected a soft derivation,but got " + strconv.FormatUint(uint64(index), 10))
	}

	pubkey := append([]byte(nil), x.xpub[:32]...)
	chaincode := append([]byte(nil), x.xpub[32:]...)

	zmac := hmac.New(sha512.New, chaincode)
	imac := hmac.New(sha512.New, chaincode)

	seri := make([]byte, 4)
	binary.LittleEndian.PutUint32(seri, index)

	zmac.Write([]byte{2})
	zmac.Write(pubkey)
	zmac.Write(seri)

	imac.Write([]byte{3})
	imac.Write(pubkey)
	imac.Write(seri)

	zl8 := pointTrunc28Mul8(zmac.Sum(nil)[:32])

	//Ai ← AP +[8ZL]B
	var Ai edwards25519.ProjectiveGroupElement
	var key [32]byte
	key[0] = 1
	var Ap edwards25519.ExtendedGroupElement
	var ap [32]byte
	copy(ap[:], pubkey)
	Ap.FromBytes(&ap)
	edwards25519.GeDoubleScalarMultVartime(&Ai, &key, &Ap, zl8)
	Ai.ToBytes(&key)

	var out [64]byte
	copy(out[:], key[:32])
	copy(out[32:], imac.Sum(nil)[32:])

	return XPub{xpub: out[:]}
}
