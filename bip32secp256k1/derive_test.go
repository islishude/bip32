package bip32secp256k1

import (
	"bytes"
	"errors"
	"math/big"
	"testing"
)

var secp256k1Order = mustBigFromHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")

func TestInvalidMasterKeyHandling(t *testing.T) {
	if _, err := newMasterKey(testSeed, Mainnet, fixedHMAC([32]byte{}, 0)); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("zero master IL error = %v", err)
	}
	orderBytes := bigTo32(secp256k1Order)
	if _, err := newMasterKey(testSeed, Mainnet, fixedHMAC(orderBytes, 0)); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("master IL >= n error = %v", err)
	}
}

func TestPublicPrivateDerivationEquivalence(t *testing.T) {
	root := mustMaster(t, Mainnet)
	account, err := root.DeriveRelativePath("0'/1")
	if err != nil {
		t.Fatalf("derive account: %v", err)
	}
	accountPublic, err := account.XPub()
	if err != nil {
		t.Fatalf("account XPub: %v", err)
	}

	for _, index := range []uint32{0, 1, 2, 1000000000, HardenedOffset - 1} {
		privateChild, err := account.Derive(index)
		if err != nil {
			t.Fatalf("private Derive(%d): %v", index, err)
		}
		privateChildPublic, err := privateChild.XPub()
		if err != nil {
			t.Fatalf("private child XPub(%d): %v", index, err)
		}
		publicChild, err := accountPublic.Derive(index)
		if err != nil {
			t.Fatalf("public Derive(%d): %v", index, err)
		}
		if !bytes.Equal(privateChildPublic.Bytes(), publicChild.Bytes()) {
			t.Fatalf("public/private derivation mismatch at %d", index)
		}
	}

	if _, err := accountPublic.Derive(HardenedOffset); !errors.Is(err, ErrHardenedFromXPub) {
		t.Fatalf("hardened public error = %v", err)
	}
	if _, err := accountPublic.DeriveRelativePath("0/1'"); !errors.Is(err, ErrHardenedFromXPub) {
		t.Fatalf("hardened relative public error = %v", err)
	}
}

func TestAbsoluteAndRelativePathRules(t *testing.T) {
	root := mustMaster(t, Mainnet)
	child, err := root.Derive(0)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if _, err := child.DerivePath("m/1"); !errors.Is(err, ErrNotRoot) {
		t.Fatalf("non-root absolute error = %v", err)
	}
	relative, err := child.DeriveRelativePath("1/2")
	if err != nil || relative.Depth() != 3 {
		t.Fatalf("relative derive = depth %d, %v", relative.Depth(), err)
	}

	maxPrivate := *root
	maxPrivate.depth = MaxDepth
	if _, err := maxPrivate.Derive(0); !errors.Is(err, ErrDepthOverflow) {
		t.Fatalf("private depth overflow error = %v", err)
	}
	maxPublic, err := maxPrivate.XPub()
	if err != nil {
		t.Fatalf("max XPub: %v", err)
	}
	if _, err := maxPublic.Derive(0); !errors.Is(err, ErrDepthOverflow) {
		t.Fatalf("public depth overflow error = %v", err)
	}
}

func TestExactIndexInvalidChildHandling(t *testing.T) {
	root := mustMaster(t, Mainnet)
	xpub, err := root.XPub()
	if err != nil {
		t.Fatalf("XPub: %v", err)
	}

	orderBytes := bigTo32(secp256k1Order)
	invalidIL := fixedHMAC(orderBytes, 0xaa)
	if _, err := root.derive(7, invalidIL); !errors.Is(err, ErrInvalidChild) {
		t.Fatalf("private IL >= n error = %v", err)
	}
	if _, err := xpub.derive(7, invalidIL); !errors.Is(err, ErrInvalidChild) {
		t.Fatalf("public IL >= n error = %v", err)
	}

	parent := new(big.Int).SetBytes(root.PrivateKey())
	negParent := new(big.Int).Sub(secp256k1Order, parent)
	zeroChildIL := fixedHMAC(bigTo32(negParent), 0xbb)
	if _, err := root.derive(11, zeroChildIL); !errors.Is(err, ErrInvalidChild) {
		t.Fatalf("zero private child error = %v", err)
	}
	if _, err := xpub.derive(11, zeroChildIL); !errors.Is(err, ErrInvalidChild) {
		t.Fatalf("infinity public child error = %v", err)
	}

	zeroTweak := fixedHMAC([32]byte{}, 0xcc)
	privateChild, err := root.derive(19, zeroTweak)
	if err != nil {
		t.Fatalf("zero tweak private derive: %v", err)
	}
	if privateChild.ChildNumber() != 19 || !bytes.Equal(privateChild.PrivateKey(), root.PrivateKey()) {
		t.Fatal("zero tweak changed private key or requested child number")
	}
	publicChild, err := xpub.derive(19, zeroTweak)
	if err != nil {
		t.Fatalf("zero tweak public derive: %v", err)
	}
	if publicChild.ChildNumber() != 19 || publicChild.PublicKey() != xpub.PublicKey() {
		t.Fatal("zero tweak changed public key or requested child number")
	}
}

func fixedHMAC(left [32]byte, right byte) hmac512Func {
	return func(_, _ []byte) (out [64]byte) {
		copy(out[:32], left[:])
		for i := 32; i < len(out); i++ {
			out[i] = right
		}
		return out
	}
}

func bigTo32(value *big.Int) (out [32]byte) {
	value.FillBytes(out[:])
	return out
}

func mustBigFromHex(value string) *big.Int {
	out, ok := new(big.Int).SetString(value, 16)
	if !ok {
		panic("invalid big integer")
	}
	return out
}
