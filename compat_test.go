package bip32_test

import (
	"errors"
	"reflect"
	"testing"

	bip32 "github.com/islishude/bip32/v2"
	"github.com/islishude/bip32/v2/bip32ed25519"
	"github.com/islishude/bip32/v2/bip32secp256k1"
)

func TestCurvePackageCompatibilityWrappers(t *testing.T) {
	if bip32ed25519.ChainCodeSize != bip32.ChainCodeSize ||
		bip32secp256k1.ChainCodeSize != bip32.ChainCodeSize {
		t.Fatal("curve package chain-code sizes differ from the root constant")
	}
	if bip32ed25519.HardenedOffset != bip32.HardenedOffset ||
		bip32secp256k1.HardenedOffset != bip32.HardenedOffset {
		t.Fatal("curve package hardened offsets differ from the root constant")
	}

	want, err := bip32.ParseAbsolutePath("m/44'/0'/0'/0/1")
	if err != nil {
		t.Fatalf("root ParseAbsolutePath: %v", err)
	}
	for name, parse := range map[string]func(string) ([]uint32, error){
		"ed25519":   bip32ed25519.ParseAbsolutePath,
		"secp256k1": bip32secp256k1.ParseAbsolutePath,
	} {
		got, err := parse("m/44'/0'/0'/0/1")
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s ParseAbsolutePath = %v, %v", name, got, err)
		}
	}

	if _, err := bip32ed25519.ParseAbsolutePath("m/"); !errors.Is(err, bip32ed25519.ErrInvalidPath) || err.Error() != "bip32ed25519: invalid derivation path: \"m/\"" {
		t.Fatalf("ed25519 compatibility error = %v", err)
	}
	if _, err := bip32secp256k1.ParseAbsolutePath("m/"); !errors.Is(err, bip32secp256k1.ErrInvalidPath) || err.Error() != "bip32secp256k1: invalid derivation path: \"m/\"" {
		t.Fatalf("secp256k1 compatibility error = %v", err)
	}
}
