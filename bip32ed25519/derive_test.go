package bip32ed25519

import (
	"bytes"
	"errors"
	"testing"
)

func TestSoftPublicDerivationMatchesPrivateDerivation(t *testing.T) {
	root := testIcarusRoot(t)
	rootPub, err := root.XPub()
	if err != nil {
		t.Fatalf("XPub: %v", err)
	}

	indexes := []uint32{0, 1, 2, 42, 0x7fffffff}
	for _, index := range indexes {
		childPrv, err := root.Derive(index)
		if err != nil {
			t.Fatalf("XPrv.Derive(%d): %v", index, err)
		}
		childPubFromPrv, err := childPrv.XPub()
		if err != nil {
			t.Fatalf("child XPub(%d): %v", index, err)
		}
		childPubFromPub, err := rootPub.Derive(index)
		if err != nil {
			t.Fatalf("XPub.Derive(%d): %v", index, err)
		}
		if !bytes.Equal(childPubFromPrv.Bytes(), childPubFromPub.Bytes()) {
			t.Fatalf("soft child xpub mismatch at %d", index)
		}
	}
}

func TestCIP1852PathAndAccountXPub(t *testing.T) {
	root := testIcarusRoot(t)

	account, err := root.DerivePath("m/1852'/1815'/0'")
	if err != nil {
		t.Fatalf("account path: %v", err)
	}
	accountXPub, err := account.XPub()
	if err != nil {
		t.Fatalf("account XPub: %v", err)
	}

	fromXPub, err := accountXPub.DeriveRelativePath("0/0")
	if err != nil {
		t.Fatalf("account xpub relative path: %v", err)
	}

	fromXPrv, err := root.DerivePath("m/1852'/1815'/0'/0/0")
	if err != nil {
		t.Fatalf("payment path: %v", err)
	}
	fromXPrvPub, err := fromXPrv.XPub()
	if err != nil {
		t.Fatalf("payment XPub: %v", err)
	}

	if !bytes.Equal(fromXPub.Bytes(), fromXPrvPub.Bytes()) {
		t.Fatal("account xpub soft derivation does not match private path")
	}
}

func TestHardenedFromXPubFails(t *testing.T) {
	xpub, err := testIcarusRoot(t).XPub()
	if err != nil {
		t.Fatalf("XPub: %v", err)
	}
	if _, err := xpub.Derive(HardenedOffset); !errors.Is(err, ErrHardenedFromXPub) {
		t.Fatalf("XPub.Derive(hardened) error = %v, want %v", err, ErrHardenedFromXPub)
	}
}

func TestDeriveDepthOverflow(t *testing.T) {
	root := testIcarusRoot(t)
	root.depth = MaxDepth
	if _, err := root.Derive(0); !errors.Is(err, ErrDepthOverflow) {
		t.Fatalf("XPrv depth overflow error = %v, want %v", err, ErrDepthOverflow)
	}

	xpub, err := testIcarusRoot(t).XPub()
	if err != nil {
		t.Fatalf("XPub: %v", err)
	}
	xpub.depth = MaxDepth
	if _, err := xpub.Derive(0); !errors.Is(err, ErrDepthOverflow) {
		t.Fatalf("XPub depth overflow error = %v, want %v", err, ErrDepthOverflow)
	}
}

func TestPrivateDerivationChainCodeUsesSecondHMACRightHalf(t *testing.T) {
	root := testIcarusRoot(t)
	index := uint32(7)

	child, err := root.Derive(index)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	pub, err := root.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	indexLE := ser32LE(index)
	ccInput := make([]byte, 0, 1+32+4)
	ccInput = append(ccInput, 0x03)
	ccInput = append(ccInput, pub[:]...)
	ccInput = append(ccInput, indexLE[:]...)
	i := hmacSHA512(root.cc[:], ccInput)

	if !bytes.Equal(child.cc[:], i[32:64]) {
		t.Fatal("child chain code did not use right half of second HMAC")
	}
}
