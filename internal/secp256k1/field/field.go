package field

import (
	"encoding/binary"

	fiat "github.com/islishude/bip32/v2/internal/secp256k1/fiat/basefield"
)

// Size is the byte length of a secp256k1 field element.
const Size = 32

// Modulus is the secp256k1 base-field prime p = 2^256 - 2^32 - 977.
var Modulus = [Size]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
}

const (
	ModuleLimb0 uint64 = 0xffffffffffffffff
	ModuleLimb1 uint64 = 0xffffffffffffffff
	ModuleLimb2 uint64 = 0xffffffffffffffff
	ModuleLimb3 uint64 = 0xfffffffefffffc2f
)

// Element is an element of the secp256k1 base field modulo p.
//
// Values are stored in Montgomery form so multiplication and squaring can use
// fiat-crypto's generated routines directly.
type Element struct {
	x fiat.MontgomeryDomainFieldElement
}

// LessThanModulus reports whether b is a canonical field encoding.
func LessThanModulus(b *[Size]byte) bool {
	return LessThanModulusWords(bytesToWords(b))
}

// LessThanModulusWords reports whether little-endian non-Montgomery words are
// a canonical field encoding.
func LessThanModulusWords(words [4]uint64) bool {
	if words[3] != ModuleLimb0 {
		return words[3] < ModuleLimb0
	}

	if words[2] != ModuleLimb1 {
		return words[2] < ModuleLimb1
	}

	if words[1] != ModuleLimb2 {
		return words[1] < ModuleLimb2
	}

	return words[0] < ModuleLimb3
}

func bytesToWords(b *[Size]byte) [4]uint64 {
	return [4]uint64{
		binary.BigEndian.Uint64(b[24:32]),
		binary.BigEndian.Uint64(b[16:24]),
		binary.BigEndian.Uint64(b[8:16]),
		binary.BigEndian.Uint64(b[0:8]),
	}
}

func putWordsBytes(out *[Size]byte, words [4]uint64) {
	binary.BigEndian.PutUint64(out[0:8], words[3])
	binary.BigEndian.PutUint64(out[8:16], words[2])
	binary.BigEndian.PutUint64(out[16:24], words[1])
	binary.BigEndian.PutUint64(out[24:32], words[0])
}

// Set assigns z = x.
func (z *Element) Set(x *Element) *Element {
	z.x = x.x
	return z
}

// SetZero assigns z = 0.
func (z *Element) SetZero() *Element {
	clear(z.x[:])
	return z
}

// SetOne assigns z = 1.
func (z *Element) SetOne() *Element {
	fiat.SetOne(&z.x)
	return z
}

// SetUint64 assigns z = v.
func (z *Element) SetUint64(v uint64) *Element {
	return z.SetNonMontgomeryWords([4]uint64{v, 0, 0, 0})
}

// SetBytes parses a canonical 32-byte big-endian field element.
func (z *Element) SetBytes(b *[Size]byte) bool {
	words := bytesToWords(b)
	if !LessThanModulusWords(words) {
		return false
	}
	z.SetNonMontgomeryWords(words)
	return true
}

// NonMontgomeryWords returns the canonical non-Montgomery little-endian limbs of z.
func (z *Element) NonMontgomeryWords() [4]uint64 {
	var out fiat.NonMontgomeryDomainFieldElement
	fiat.FromMontgomery(&out, &z.x)
	return [4]uint64{out[0], out[1], out[2], out[3]}
}

// Bytes returns the canonical 32-byte big-endian encoding of z.
func (z *Element) Bytes() [Size]byte {
	var be [Size]byte
	z.PutBytes(&be)
	return be
}

// PutBytes writes the canonical 32-byte big-endian encoding of z to out.
func (z *Element) PutBytes(out *[Size]byte) {
	putWordsBytes(out, z.NonMontgomeryWords())
}

// IsZero reports whether z is 0.
func (z *Element) IsZero() bool {
	return z.x == fiat.MontgomeryDomainFieldElement{}
}

// IsOdd reports whether z's canonical integer encoding is odd.
func (z *Element) IsOdd() bool {
	words := z.NonMontgomeryWords()
	return words[0]&1 == 1
}

// Equal reports whether z and x are the same field element.
func (z *Element) Equal(x *Element) bool {
	return z.x == x.x
}

// Select assigns z = x when choice == 0 and z = y when choice == 1.
func (z *Element) Select(x, y *Element, choice uint64) *Element {
	mask := uint64(0) - (choice & 1)
	for i := range z.x {
		z.x[i] = (x.x[i] &^ mask) | (y.x[i] & mask)
	}
	return z
}

// Add assigns z = x + y mod p.
func (z *Element) Add(x, y *Element) *Element {
	addMontgomery(&z.x, &x.x, &y.x)
	return z
}

// Sub assigns z = x - y mod p.
func (z *Element) Sub(x, y *Element) *Element {
	subMontgomery(&z.x, &x.x, &y.x)
	return z
}

// Neg assigns z = -x mod p.
func (z *Element) Neg(x *Element) *Element {
	fiat.Opp(&z.x, &x.x)
	return z
}

// Double assigns z = 2*x mod p.
func (z *Element) Double(x *Element) *Element {
	return z.Add(x, x)
}

// Mul assigns z = x*y mod p.
func (z *Element) Mul(x, y *Element) *Element {
	mulMontgomery(&z.x, &x.x, &y.x)
	return z
}

// MulByB3 assigns z = 21*x mod p. The constant is 3*b for secp256k1's b = 7
// and is used by the complete mixed-add formula.
func (z *Element) MulByB3(x *Element) *Element {
	mulByB3Montgomery(&z.x, &x.x)
	return z
}

// Square assigns z = x^2 mod p.
func (z *Element) Square(x *Element) *Element {
	squareMontgomery(&z.x, &x.x)
	return z
}

// SquareN assigns z = x^(2^n) mod p.
func (z *Element) SquareN(x *Element, n int) *Element {
	if n < 1 {
		return z.Set(x)
	}
	squareMontgomeryN(&z.x, &x.x, uint64(n))
	return z
}

// Sqrt attempts to assign z to a square root of x.
func (z *Element) Sqrt(x *Element) bool {
	z.sqrtCandidate(x)
	var check Element
	// Re-square the candidate because non-residues also produce a field value.
	check.Square(z)
	return check.Equal(x)
}

// SetNonMontgomeryWords assigns z = canonical little-endian non-Montgomery words.
func (z *Element) SetNonMontgomeryWords(words [4]uint64) *Element {
	in := fiat.NonMontgomeryDomainFieldElement{
		words[0], words[1], words[2], words[3],
	}
	fiat.ToMontgomery(&z.x, &in)
	return z
}

// SetMontgomeryWords assigns z from trusted Montgomery-domain limbs.
// It is intended for repository-generated precomputation tables only.
func (z *Element) SetMontgomeryWords(words [4]uint64) *Element {
	z.x = fiat.MontgomeryDomainFieldElement(words)
	return z
}
