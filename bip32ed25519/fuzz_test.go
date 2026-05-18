package bip32ed25519

import (
	"encoding/hex"
	"testing"
)

func FuzzParsePath(f *testing.F) {
	for _, seed := range []string{"m", "m/1852'/1815'/0'/0/0", "0/0", "m//0", "m/-1"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, path string) {
		_, _ = ParseAbsolutePath(path)
		_, _ = ParseRelativePath(path)
	})
}

func FuzzNewXPrvFromBytes(f *testing.F) {
	f.Add([]byte{})
	f.Add(mustDecodeHexForFuzz("c065afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d245d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		key, err := NewXPrvFromBytes(raw)
		if err != nil {
			return
		}
		_, _ = key.PublicKey()
	})
}

func FuzzNewXPubFromBytes(f *testing.F) {
	f.Add([]byte{})
	f.Add(mustDecodeHexForFuzz("ff"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = NewXPubFromBytes(raw)
	})
}

func mustDecodeHexForFuzz(raw string) []byte {
	out, err := hex.DecodeString(raw)
	if err != nil {
		panic(err)
	}
	return out
}
