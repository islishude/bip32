package bip32

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestXPub_Derive(t *testing.T) {
	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Error(err)
		return
	}
	xprv := NewRootXPrv(root)
	for i := uint32(0); i < 100; i++ {
		a := xprv.Derive(i).XPub().PublicKey()
		b := xprv.XPub().Derive(i).PublicKey()
		if !bytes.Equal(a, b) {
			t.Errorf("XPub.Derive failed: %d", i)
		}
	}
}
