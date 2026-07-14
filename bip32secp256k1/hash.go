package bip32secp256k1

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/ripemd160"
)

type hmac512Func func(key, data []byte) [64]byte

func hmacSHA512(key, data []byte) (out [sha512.Size]byte) {
	h := hmac.New(sha512.New, key)
	_, _ = h.Write(data)
	sum := h.Sum(nil)
	copy(out[:], sum)
	clear(sum)
	return out
}

func keyFingerprint(pub [PublicKeySize]byte) (out [FingerprintSize]byte) {
	sha := sha256.Sum256(pub[:])
	h := ripemd160.New()
	_, _ = h.Write(sha[:])
	id := h.Sum(nil)
	copy(out[:], id[:FingerprintSize])
	clear(id)
	return out
}
