package field

import fiat "github.com/islishude/bip32/v2/internal/secp256k1/fiat/basefield"

var b3Montgomery = fiat.MontgomeryDomainFieldElement{0x1500005025, 0, 0, 0}

func addMontgomery(out, x, y *fiat.MontgomeryDomainFieldElement) {
	fiat.Add(out, x, y)
}

func subMontgomery(out, x, y *fiat.MontgomeryDomainFieldElement) {
	fiat.Sub(out, x, y)
}

func mulMontgomery(out, x, y *fiat.MontgomeryDomainFieldElement) {
	fiat.Mul(out, x, y)
}

func mulByB3Montgomery(out, x *fiat.MontgomeryDomainFieldElement) {
	fiat.Mul(out, x, &b3Montgomery)
}

func squareMontgomery(out, x *fiat.MontgomeryDomainFieldElement) {
	fiat.Square(out, x)
}

func squareMontgomeryN(out, x *fiat.MontgomeryDomainFieldElement, n uint64) {
	*out = *x
	for range n {
		fiat.Square(out, out)
	}
}
