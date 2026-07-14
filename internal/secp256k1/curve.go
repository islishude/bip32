// Copyright 2026 The bip32 Authors.

package secp256k1

import "github.com/islishude/bip32/v2/internal/secp256k1/field"

const secp256k1B uint64 = 7

var (
	secp256k1BElement = fieldElementUint64(secp256k1B)
)

func fieldElementUint64(v uint64) field.Element {
	var out field.Element
	out.SetUint64(v)
	return out
}

func affineFromXBytes(xBytes *[32]byte, wantOdd bool) (field.Element, field.Element, bool) {
	var x field.Element
	if !x.SetBytes(xBytes) {
		return field.Element{}, field.Element{}, false
	}
	var x2, rhs, y field.Element
	x2.Square(&x)
	rhs.Mul(&x2, &x)
	rhs.Add(&rhs, &secp256k1BElement)
	if !y.Sqrt(&rhs) {
		return field.Element{}, field.Element{}, false
	}
	if y.IsOdd() != wantOdd {
		y.Neg(&y)
	}
	return x, y, true
}
