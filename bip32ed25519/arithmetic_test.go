package bip32ed25519

import (
	"bytes"
	"testing"
)

func TestAdd28Mul8LE(t *testing.T) {
	var dst [32]byte
	copy(dst[:], mustDecodeHex(t, "b9d2ad48d44954b409f674a306c08da5b7e1c52005a512f5854c2593173db4a6"))
	z := mustDecodeHex(t, "1d9b4170ef340b683ddf03f847b1c1aeb8d276e271446c52c9fbd324a3fa8206")

	if overflow := add28Mul8LE(&dst, z[:28]); overflow {
		t.Fatal("add28Mul8LE overflowed unexpectedly")
	}

	want := mustDecodeHex(t, "a1abbaca4ff1adf4f4ef9363464a9b1b7d777c3494c87488d02ac5b9183db4a6")
	if !bytes.Equal(dst[:], want) {
		t.Fatalf("add28Mul8LE = %x, want %x", dst, want)
	}
}

func TestAdd28Mul8LEOverflow(t *testing.T) {
	var dst [32]byte
	for i := range dst {
		dst[i] = 0xff
	}
	z := make([]byte, 28)
	z[0] = 1

	if overflow := add28Mul8LE(&dst, z); !overflow {
		t.Fatal("add28Mul8LE did not report overflow")
	}
}

func TestAddMod256LE(t *testing.T) {
	var dst [32]byte
	for i := range dst {
		dst[i] = 0xff
	}
	addend := make([]byte, 32)
	addend[0] = 1

	addMod256LE(&dst, addend)
	if !bytes.Equal(dst[:], make([]byte, 32)) {
		t.Fatalf("addMod256LE wrap = %x, want zero", dst)
	}
}

func TestScalarFromZL28Times8RejectsWrongLength(t *testing.T) {
	if _, err := scalarFromZL28Times8(make([]byte, 27)); !errorsIs(err, ErrInvalidTweak) {
		t.Fatalf("scalarFromZL28Times8 error = %v, want %v", err, ErrInvalidTweak)
	}
}

func errorsIs(err, target error) bool {
	return err == target
}
