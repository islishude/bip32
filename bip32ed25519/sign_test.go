package bip32ed25519

import (
	"crypto/ed25519"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	key, err := testIcarusRoot(t).DerivePath("m/1852'/1815'/0'/0/0")
	if err != nil {
		t.Fatalf("DerivePath: %v", err)
	}

	message := []byte("hello ed25519-bip32")
	sig, err := key.Sign(message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature size = %d, want %d", len(sig), ed25519.SignatureSize)
	}

	pub, err := key.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !Verify(pub, message, sig) {
		t.Fatal("Verify returned false for valid signature")
	}

	xpub, err := key.XPub()
	if err != nil {
		t.Fatalf("XPub: %v", err)
	}
	if !xpub.Verify(message, sig) {
		t.Fatal("XPub.Verify returned false for valid signature")
	}

	if Verify(pub, []byte("changed"), sig) {
		t.Fatal("Verify returned true for changed message")
	}
	sig[0] ^= 0x01
	if Verify(pub, message, sig) {
		t.Fatal("Verify returned true for changed signature")
	}
}
