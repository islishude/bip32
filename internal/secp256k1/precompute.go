// Copyright 2026 The bip32 Authors.

package secp256k1

//go:generate go run ./cmd/genprecomp

const (
	baseWindow    = 5
	baseWindows   = (256 + baseWindow - 1) / baseWindow
	baseTableSize = 1 << (baseWindow - 1)
)

var generatorAffineTableW5 = loadGeneratorAffineTableW5(&generatorAffineTableW5Words)

func loadGeneratorAffineTableW5(words *[baseWindows][baseTableSize][8]uint64) [baseWindows][baseTableSize]affinePoint {
	var table [baseWindows][baseTableSize]affinePoint
	for i := range table {
		for j := range table[i] {
			table[i][j].x.SetMontgomeryWords([4]uint64{
				words[i][j][0], words[i][j][1], words[i][j][2], words[i][j][3],
			})
			table[i][j].y.SetMontgomeryWords([4]uint64{
				words[i][j][4], words[i][j][5], words[i][j][6], words[i][j][7],
			})
		}
	}
	return table
}
