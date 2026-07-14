package secp256k1

import (
	"encoding/hex"
	"testing"
)

func TestPublicKeyAndPointOperations(t *testing.T) {
	one := scalarBytes(1)
	two := scalarBytes(2)
	orderMinusOne := mustDecode32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
	generatorCompressed := mustDecode33("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	twoGCompressed := mustDecode33("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
	negativeGenerator := mustDecode33("0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	fieldModulusX := mustDecode33("02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
	var zero [32]byte

	if _, ok := PublicKeyFromScalar(&zero); ok {
		t.Fatal("zero private scalar accepted")
	}
	if got, ok := PublicKeyFromScalar(&one); !ok || got != generatorCompressed {
		t.Fatalf("1*G = %x, %v", got, ok)
	}
	if got, ok := PublicKeyFromScalar(&two); !ok || got != twoGCompressed {
		t.Fatalf("2*G = %x, %v", got, ok)
	}
	if got, ok := PublicKeyFromScalar(&orderMinusOne); !ok || got != negativeGenerator {
		t.Fatalf("(n-1)*G = %x, %v", got, ok)
	}
	if got, ok := AddScalarBase(&generatorCompressed, &one); !ok || got != twoGCompressed {
		t.Fatalf("G + 1*G = %x, %v", got, ok)
	}
	if got, ok := AddScalarBase(&generatorCompressed, &zero); !ok || got != generatorCompressed {
		t.Fatalf("G + 0*G = %x, %v", got, ok)
	}
	if _, ok := AddScalars(&orderMinusOne, &one); ok {
		t.Fatal("zero private child accepted")
	}

	invalidPoint := mustDecode33("020000000000000000000000000000000000000000000000000000000000000007")
	if ValidPublicKey(&invalidPoint) {
		t.Fatal("off-curve compressed point accepted")
	}
	if ValidPublicKey(&fieldModulusX) {
		t.Fatal("non-canonical compressed x-coordinate accepted")
	}

	g, ok := parseCompressed(&generatorCompressed)
	if !ok {
		t.Fatal("generator parse failed")
	}
	negG, ok := parseCompressed(&negativeGenerator)
	if !ok {
		t.Fatal("negative generator parse failed")
	}
	var infinity point
	infinity.add(&g, &negG)
	if !infinity.isInfinity() {
		t.Fatal("G + (-G) is not infinity")
	}
	var identity point
	identity.add(&point{}, &g)
	x, y, ok := identity.affine()
	if !ok || encodeAffine(&x, &y) != generatorCompressed {
		t.Fatal("infinity + G mismatch")
	}
	var doubled point
	doubled.add(&g, &g)
	x, y, ok = doubled.affine()
	if !ok || encodeAffine(&x, &y) != twoGCompressed {
		t.Fatal("G + G mismatch")
	}
}

func FuzzValidPublicKey(f *testing.F) {
	f.Add([]byte{})
	generator := mustDecode33("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	f.Add(generator[:])
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) != PublicKeySize {
			return
		}
		var key [PublicKeySize]byte
		copy(key[:], input)
		_ = ValidPublicKey(&key)
	})
}

func scalarBytes(value byte) (out [32]byte) {
	out[31] = value
	return out
}

func mustDecode32(value string) (out [32]byte) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(out) {
		panic("invalid 32-byte test value")
	}
	copy(out[:], decoded)
	return out
}

func mustDecode33(value string) (out [33]byte) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(out) {
		panic("invalid 33-byte test value")
	}
	copy(out[:], decoded)
	return out
}
