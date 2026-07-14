package scalar

import (
	"math/big"
	"testing"
)

func TestScalarAddAgainstBigInt(t *testing.T) {
	modulus := new(big.Int).SetBytes(Order[:])
	cases := [][2]*big.Int{
		{big.NewInt(0), big.NewInt(0)},
		{big.NewInt(1), big.NewInt(1)},
		{new(big.Int).Sub(modulus, big.NewInt(1)), big.NewInt(1)},
		{new(big.Int).Sub(modulus, big.NewInt(1)), new(big.Int).Sub(modulus, big.NewInt(1))},
	}

	state := uint64(0x243f6a8885a308d3)
	for range 512 {
		var leftBytes, rightBytes [32]byte
		for i := range 4 {
			state = state*6364136223846793005 + 1442695040888963407
			putUint64BE(leftBytes[i*8:], state)
			state = state*6364136223846793005 + 1442695040888963407
			putUint64BE(rightBytes[i*8:], state)
		}
		left := new(big.Int).SetBytes(leftBytes[:])
		right := new(big.Int).SetBytes(rightBytes[:])
		left.Mod(left, modulus)
		right.Mod(right, modulus)
		cases = append(cases, [2]*big.Int{left, right})
	}

	for _, test := range cases {
		leftBytes := bigToScalar(test[0])
		rightBytes := bigToScalar(test[1])
		var left, right, sum Element
		if !left.SetBytes(&leftBytes) || !right.SetBytes(&rightBytes) {
			t.Fatal("canonical scalar rejected")
		}
		sum.Add(&left, &right)
		want := new(big.Int).Add(test[0], test[1])
		want.Mod(want, modulus)
		sumBytes := sum.Bytes()
		if got := new(big.Int).SetBytes(sumBytes[:]); got.Cmp(want) != 0 {
			t.Fatalf("%x + %x = %x, want %x", test[0], test[1], got, want)
		}
	}
}

func TestScalarCanonicalBounds(t *testing.T) {
	var zero Element
	var zeroBytes [32]byte
	if !zero.SetBytes(&zeroBytes) || !zero.IsZero() {
		t.Fatal("zero scalar should be canonical")
	}
	order := Order
	if zero.SetBytes(&order) {
		t.Fatal("group order accepted as canonical scalar")
	}
	nMinusOne := new(big.Int).Sub(new(big.Int).SetBytes(Order[:]), big.NewInt(1))
	canonical := bigToScalar(nMinusOne)
	if !zero.SetBytes(&canonical) || zero.IsZero() {
		t.Fatal("n-1 rejected")
	}
}

func bigToScalar(value *big.Int) (out [32]byte) {
	value.FillBytes(out[:])
	return out
}

func putUint64BE(out []byte, value uint64) {
	for i := 7; i >= 0; i-- {
		out[i] = byte(value)
		value >>= 8
	}
}
