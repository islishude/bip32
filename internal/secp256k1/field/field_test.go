package field

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"
)

func TestFieldArithmeticAgainstBigInt(t *testing.T) {
	modulus := new(big.Int).SetBytes(Modulus[:])
	for i := range uint64(256) {
		leftBig := fieldInput(i*2+1, modulus)
		rightBig := fieldInput(i*2+2, modulus)
		left := mustFieldElement(t, leftBig)
		right := mustFieldElement(t, rightBig)

		var got Element
		got.Add(&left, &right)
		assertFieldEqual(t, &got, new(big.Int).Mod(new(big.Int).Add(leftBig, rightBig), modulus))
		got.Sub(&left, &right)
		assertFieldEqual(t, &got, new(big.Int).Mod(new(big.Int).Sub(leftBig, rightBig), modulus))
		got.Mul(&left, &right)
		assertFieldEqual(t, &got, new(big.Int).Mod(new(big.Int).Mul(leftBig, rightBig), modulus))
		got.Square(&left)
		assertFieldEqual(t, &got, new(big.Int).Mod(new(big.Int).Mul(leftBig, leftBig), modulus))

		if leftBig.Sign() != 0 {
			got.Inv(&left)
			want := new(big.Int).ModInverse(leftBig, modulus)
			assertFieldEqual(t, &got, want)
		}

		var square, root, checked Element
		square.Square(&left)
		if !root.Sqrt(&square) {
			t.Fatal("square rejected by Sqrt")
		}
		checked.Square(&root)
		if !checked.Equal(&square) {
			t.Fatal("Sqrt result does not square to input")
		}
	}
}

func TestFieldCanonicalBoundsAndZeroInverse(t *testing.T) {
	modulus := Modulus
	var value Element
	if value.SetBytes(&modulus) {
		t.Fatal("field modulus accepted as canonical value")
	}
	var zero, inverse Element
	inverse.Inv(&zero)
	if !inverse.IsZero() {
		t.Fatal("inverse of zero should be zero")
	}
}

func fieldInput(counter uint64, modulus *big.Int) *big.Int {
	var input [8]byte
	binary.BigEndian.PutUint64(input[:], counter)
	digest := sha256.Sum256(input[:])
	value := new(big.Int).SetBytes(digest[:])
	return value.Mod(value, modulus)
}

func mustFieldElement(t *testing.T, value *big.Int) Element {
	t.Helper()
	var encoded [32]byte
	value.FillBytes(encoded[:])
	var out Element
	if !out.SetBytes(&encoded) {
		t.Fatal("canonical field value rejected")
	}
	return out
}

func assertFieldEqual(t *testing.T, got *Element, want *big.Int) {
	t.Helper()
	encoded := got.Bytes()
	if gotBig := new(big.Int).SetBytes(encoded[:]); gotBig.Cmp(want) != 0 {
		t.Fatalf("field result = %x, want %x", gotBig, want)
	}
}
