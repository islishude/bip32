package bip32secp256k1

import "testing"

func FuzzParseExtendedKeyText(f *testing.F) {
	f.Add("")
	f.Add("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
	f.Add("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
	f.Fuzz(func(t *testing.T, encoded string) {
		_, _ = ParseXPrv(encoded)
		_, _ = ParseXPub(encoded)
	})
}

func FuzzParseExtendedKeyBinary(f *testing.F) {
	f.Add([]byte{})
	root, err := NewMasterKey(testSeed, Mainnet)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(root.Bytes())
	public, err := root.XPub()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(public.Bytes())
	f.Fuzz(func(t *testing.T, serialized []byte) {
		_, _ = NewXPrvFromBytes(serialized)
		_, _ = NewXPubFromBytes(serialized)
	})
}

func FuzzParsePath(f *testing.F) {
	for _, path := range []string{"m", "m/44'/0'/0'/0/0", "0/0", "m//0", "m/-1"} {
		f.Add(path)
	}
	f.Fuzz(func(t *testing.T, path string) {
		_, _ = ParseAbsolutePath(path)
		_, _ = ParseRelativePath(path)
	})
}
