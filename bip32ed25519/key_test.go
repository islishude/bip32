package bip32ed25519

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestXPrvSerializationRoundTripAndCopies(t *testing.T) {
	root := testIcarusRoot(t)

	raw := root.Bytes()
	roundTrip, err := NewXPrvFromBytes(raw)
	if err != nil {
		t.Fatalf("NewXPrvFromBytes: %v", err)
	}
	if !bytes.Equal(roundTrip.Bytes(), raw) {
		t.Fatal("XPrv round-trip bytes changed")
	}

	raw[0] ^= 0xff
	if bytes.Equal(roundTrip.Bytes(), raw) {
		t.Fatal("NewXPrvFromBytes retained caller buffer")
	}

	cc := roundTrip.ChainCode()
	cc[0] ^= 0xff
	if bytes.Equal(cc, roundTrip.ChainCode()) {
		t.Fatal("XPrv.ChainCode did not return a copy")
	}

	xsk := roundTrip.ExtendedPrivateKey()
	xsk[0] ^= 0xff
	if bytes.Equal(xsk, roundTrip.ExtendedPrivateKey()) {
		t.Fatal("XPrv.ExtendedPrivateKey did not return a copy")
	}
}

func TestXPubSerializationRoundTripAndCopies(t *testing.T) {
	root := testIcarusRoot(t)
	xpub, err := root.XPub()
	if err != nil {
		t.Fatalf("XPub: %v", err)
	}

	raw := xpub.Bytes()
	roundTrip, err := NewXPubFromBytes(raw)
	if err != nil {
		t.Fatalf("NewXPubFromBytes: %v", err)
	}
	if !bytes.Equal(roundTrip.Bytes(), raw) {
		t.Fatal("XPub round-trip bytes changed")
	}

	raw[0] ^= 0xff
	if bytes.Equal(roundTrip.Bytes(), raw) {
		t.Fatal("NewXPubFromBytes retained caller buffer")
	}

	cc := roundTrip.ChainCode()
	cc[0] ^= 0xff
	if bytes.Equal(cc, roundTrip.ChainCode()) {
		t.Fatal("XPub.ChainCode did not return a copy")
	}
}

func TestNewXPrvFromBytesInvalid(t *testing.T) {
	if _, err := NewXPrvFromBytes(nil); !errors.Is(err, ErrInvalidXPrv) {
		t.Fatalf("invalid length error = %v, want %v", err, ErrInvalidXPrv)
	}

	valid := testIcarusRoot(t).Bytes()

	invalidLowBits := append([]byte(nil), valid...)
	invalidLowBits[0] |= 0x01
	if _, err := NewXPrvFromBytes(invalidLowBits); !errors.Is(err, ErrInvalidXPrv) {
		t.Fatalf("invalid low bits error = %v, want %v", err, ErrInvalidXPrv)
	}

	missingSecondHighBit := append([]byte(nil), valid...)
	missingSecondHighBit[31] &^= 0x40
	if _, err := NewXPrvFromBytes(missingSecondHighBit); !errors.Is(err, ErrInvalidXPrv) {
		t.Fatalf("missing second-high bit error = %v, want %v", err, ErrInvalidXPrv)
	}

	invalidHighBit := append([]byte(nil), valid...)
	invalidHighBit[31] |= 0x80
	if _, err := NewXPrvFromBytes(invalidHighBit); !errors.Is(err, ErrInvalidXPrv) {
		t.Fatalf("invalid high bit error = %v, want %v", err, ErrInvalidXPrv)
	}
}

func TestNewXPubFromBytesInvalid(t *testing.T) {
	if _, err := NewXPubFromBytes(nil); !errors.Is(err, ErrInvalidXPub) {
		t.Fatalf("invalid length error = %v, want %v", err, ErrInvalidXPub)
	}

	invalid := make([]byte, XPubSize)
	copy(invalid, mustDecodeHex(t, "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))
	if _, err := NewXPubFromBytes(invalid); !errors.Is(err, ErrInvalidXPub) {
		t.Fatalf("invalid point error = %v, want %v", err, ErrInvalidXPub)
	}
}

func TestWipe(t *testing.T) {
	root := testIcarusRoot(t)
	root.Wipe()
	if !bytes.Equal(root.Bytes(), make([]byte, XPrvSize)) {
		t.Fatal("Wipe did not clear serialized key material")
	}
	if root.Path() != nil {
		t.Fatal("Wipe did not clear path metadata")
	}
}

func TestXPrvMetadataAndPublicKey(t *testing.T) {
	root := testIcarusRoot(t)

	if got := root.Path(); len(got) != 0 {
		t.Fatalf("root Path = %v, want empty", got)
	}
	if got := root.Depth(); got != 0 {
		t.Fatalf("root Depth = %d, want 0", got)
	}
	if got := root.ChildNumber(); got != 0 {
		t.Fatalf("root ChildNumber = %d, want 0", got)
	}

	pub, err := root.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	xpub, err := root.XPub()
	if err != nil {
		t.Fatalf("XPub: %v", err)
	}
	if pub != xpub.PublicKey() {
		t.Fatal("XPrv.PublicKey does not match XPub.PublicKey")
	}

	hardened7, err := Harden(7)
	if err != nil {
		t.Fatalf("Harden: %v", err)
	}
	child, err := root.Derive(42)
	if err != nil {
		t.Fatalf("Derive(42): %v", err)
	}
	grandchild, err := child.Derive(hardened7)
	if err != nil {
		t.Fatalf("Derive(hardened7): %v", err)
	}

	wantPath := []uint32{42, hardened7}
	if got := grandchild.Path(); !reflect.DeepEqual(got, wantPath) {
		t.Fatalf("grandchild Path = %v, want %v", got, wantPath)
	}
	if got := grandchild.Depth(); got != 2 {
		t.Fatalf("grandchild Depth = %d, want 2", got)
	}
	if got := grandchild.ChildNumber(); got != hardened7 {
		t.Fatalf("grandchild ChildNumber = %d, want %d", got, hardened7)
	}

	grandchildXPub, err := grandchild.XPub()
	if err != nil {
		t.Fatalf("grandchild XPub: %v", err)
	}
	if got := grandchildXPub.Depth(); got != 2 {
		t.Fatalf("grandchild XPub Depth = %d, want 2", got)
	}
	if got := grandchildXPub.ChildNumber(); got != hardened7 {
		t.Fatalf("grandchild XPub ChildNumber = %d, want %d", got, hardened7)
	}

	gotPath := grandchild.Path()
	gotPath[0] = 0
	if reflect.DeepEqual(grandchild.Path(), gotPath) {
		t.Fatal("XPrv.Path did not return a copy")
	}
}

func TestNilXPrvMetadataAndPublicKey(t *testing.T) {
	var key *XPrv

	if got := key.Path(); got != nil {
		t.Fatalf("nil Path = %v, want nil", got)
	}
	if got := key.Depth(); got != 0 {
		t.Fatalf("nil Depth = %d, want 0", got)
	}
	if got := key.ChildNumber(); got != 0 {
		t.Fatalf("nil ChildNumber = %d, want 0", got)
	}
	if _, err := key.PublicKey(); !errors.Is(err, ErrNilKey) {
		t.Fatalf("nil PublicKey error = %v, want %v", err, ErrNilKey)
	}

	var pub *XPub
	if got := pub.Depth(); got != 0 {
		t.Fatalf("nil XPub Depth = %d, want 0", got)
	}
	if got := pub.ChildNumber(); got != 0 {
		t.Fatalf("nil XPub ChildNumber = %d, want 0", got)
	}
}
