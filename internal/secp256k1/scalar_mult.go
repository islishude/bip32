// Copyright 2026 The bip32 Authors.

package secp256k1

import "github.com/islishude/bip32/v2/internal/secp256k1/scalar"

// scalarBaseMultProjective multiplies the generator by a secret scalar using a
// signed fixed window. Every window scans the complete table and uses mask
// selection; the complete mixed-add formula handles exceptional points.
func scalarBaseMultProjective(k *scalar.Element) projectivePoint {
	words := k.Words()
	defer clear(words[:])

	var r projectivePoint
	r.setInfinity()
	var carry uint64
	for i := range generatorAffineTableW5 {
		value := uint64(fixedWindowDigit(&words, uint(i), baseWindow)) + carry
		negative := (value + (1 << (baseWindow - 1))) >> baseWindow
		negativeMask := uint64(0) - negative
		digitBits := value - negative*(1<<baseWindow)
		magnitude := (digitBits ^ negativeMask) + negative

		selected := generatorAffineTableW5[i][0]
		for j := 2; j <= len(generatorAffineTableW5[i]); j++ {
			selected.selectPoint(&selected, &generatorAffineTableW5[i][j-1], equalByte(byte(magnitude), byte(j)))
		}
		var negY = selected.y
		negY.Neg(&selected.y)
		selected.y.Select(&selected.y, &negY, negative)

		var sum projectivePoint
		sum.addCompleteMixed(&r, &selected)
		r.selectPoint(&r, &sum, equalByte(byte(magnitude), 0)^1)
		carry = negative
	}
	return r
}

func fixedWindowDigit(words *[4]uint64, windowIndex, window uint) byte {
	bit := windowIndex * window
	wordIndex := bit / 64
	shift := bit % 64
	digit := words[wordIndex] >> shift
	if shift+window > 64 && wordIndex+1 < uint(len(words)) {
		digit |= words[wordIndex+1] << (64 - shift)
	}
	return byte(digit & ((1 << window) - 1))
}

func equalByte(x, y byte) uint64 {
	v := uint64(x ^ y)
	v |= v >> 4
	v |= v >> 2
	v |= v >> 1
	return (v ^ 1) & 1
}
