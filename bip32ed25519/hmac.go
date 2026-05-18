package bip32ed25519

import (
	"crypto/hmac"
	"crypto/sha512"
)

func hmacSHA512(key, data []byte) (out [64]byte) {
	mac := hmac.New(sha512.New, key)
	_, _ = mac.Write(data)
	mac.Sum(out[:0])
	return
}
