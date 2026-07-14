package bip32

import (
	"errors"
	"reflect"
	"testing"
)

func TestPathHelpers(t *testing.T) {
	h0, err := Harden(0)
	if err != nil || h0 != HardenedOffset {
		t.Fatalf("Harden(0) = %d, %v", h0, err)
	}
	h44, err := Harden(44)
	if err != nil || !IsHardened(h44) {
		t.Fatalf("Harden(44) = %d, %v", h44, err)
	}
	if IsHardened(HardenedOffset - 1) {
		t.Fatal("normal index reported as hardened")
	}
	if _, err := Harden(HardenedOffset); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("Harden overflow error = %v", err)
	}

	wantAbsolute := []uint32{h44, h0, h0, 0, 1}
	absolute, err := ParseAbsolutePath("m/44'/0h/0H/0/1")
	if err != nil || !reflect.DeepEqual(absolute, wantAbsolute) {
		t.Fatalf("ParseAbsolutePath = %v, %v", absolute, err)
	}
	root, err := ParseAbsolutePath("m")
	if err != nil || len(root) != 0 {
		t.Fatalf("ParseAbsolutePath(m) = %v, %v", root, err)
	}
	relative, err := ParseRelativePath("0/1'")
	if err != nil || !reflect.DeepEqual(relative, []uint32{0, HardenedOffset + 1}) {
		t.Fatalf("ParseRelativePath = %v, %v", relative, err)
	}

	for _, path := range []string{"", "m/", "m//0", "m/-1", "m/2147483648", "M/0"} {
		if _, err := ParseAbsolutePath(path); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("ParseAbsolutePath(%q) error = %v", path, err)
		}
	}
	for _, path := range []string{"", "m", "m/0", "0//1", "-1", "2147483648"} {
		if _, err := ParseRelativePath(path); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("ParseRelativePath(%q) error = %v", path, err)
		}
	}
}
