package bip32

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"strconv"
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

	_, _ = zmac.Write([]byte{2})
	_, _ = zmac.Write(pubkey)
	_, _ = zmac.Write(seri)

	_, _ = imac.Write([]byte{3})
	_, _ = imac.Write(pubkey)
	_, _ = imac.Write(seri)

	key := pointLeft(pubkey, zmac.Sum(nil)[:32])

	var out [64]byte
	copy(out[:], key[:32])
	copy(out[32:], imac.Sum(nil)[32:])
	return XPub{xpub: out[:]}
}
