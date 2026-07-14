package bip32secp256k1

import (
	"errors"
	"reflect"
	"testing"
)

func TestPathParsing(t *testing.T) {
	h0, _ := Harden(0)
	h44, _ := Harden(44)
	hMax, _ := Harden(HardenedOffset - 1)

	absolute := []struct {
		path string
		want []uint32
	}{
		{"m", []uint32{}},
		{"m/44'/0h/0H/0/1", []uint32{h44, h0, h0, 0, 1}},
	}
	for _, test := range absolute {
		got, err := ParseAbsolutePath(test.path)
		if err != nil || !reflect.DeepEqual(got, test.want) {
			t.Fatalf("ParseAbsolutePath(%q) = %v, %v", test.path, got, err)
		}
	}

	got, err := ParseRelativePath("0/2147483647'")
	if err != nil || !reflect.DeepEqual(got, []uint32{0, hMax}) {
		t.Fatalf("ParseRelativePath = %v, %v", got, err)
	}

	for _, path := range []string{"", "m/", "m//0", "m/-1", "m/2147483648", "m/0x1", "M/0"} {
		if _, err := ParseAbsolutePath(path); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("ParseAbsolutePath(%q) error = %v", path, err)
		}
	}
	for _, path := range []string{"", "m", "m/0", "0//1", "-1", "2147483648"} {
		if _, err := ParseRelativePath(path); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("ParseRelativePath(%q) error = %v", path, err)
		}
	}
	if _, err := Harden(HardenedOffset); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("Harden overflow error = %v", err)
	}
}
