package bip32ed25519

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseAbsolutePath(t *testing.T) {
	h1852, _ := Harden(1852)
	h1815, _ := Harden(1815)
	h0, _ := Harden(0)

	tests := []struct {
		path string
		want []uint32
	}{
		{path: "m", want: []uint32{}},
		{path: "m/1852'/1815'/0'/0/0", want: []uint32{h1852, h1815, h0, 0, 0}},
		{path: "m/1852h/1815h/0h/0/0", want: []uint32{h1852, h1815, h0, 0, 0}},
		{path: "m/1852H/1815H/0H/0/0", want: []uint32{h1852, h1815, h0, 0, 0}},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := ParseAbsolutePath(tt.path)
			if err != nil {
				t.Fatalf("ParseAbsolutePath: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseAbsolutePath = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRelativePath(t *testing.T) {
	hMax, _ := Harden(2147483647)

	tests := []struct {
		path string
		want []uint32
	}{
		{path: "0/0", want: []uint32{0, 0}},
		{path: "0/2147483647", want: []uint32{0, 2147483647}},
		{path: "2147483647'", want: []uint32{hMax}},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := ParseRelativePath(tt.path)
			if err != nil {
				t.Fatalf("ParseRelativePath: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseRelativePath = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePathInvalid(t *testing.T) {
	absoluteInvalid := []string{
		"",
		"m/",
		"m//0",
		"m/-1",
		"m/2147483648",
		"m/2147483648'",
		"m/abc'",
		"m/0x01",
	}
	for _, path := range absoluteInvalid {
		t.Run("absolute "+path, func(t *testing.T) {
			if _, err := ParseAbsolutePath(path); !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("ParseAbsolutePath(%q) error = %v, want %v", path, err, ErrInvalidPath)
			}
		})
	}

	relativeInvalid := []string{"", "m", "m/0", "0x01", "0//1", "-1"}
	for _, path := range relativeInvalid {
		t.Run("relative "+path, func(t *testing.T) {
			if _, err := ParseRelativePath(path); !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("ParseRelativePath(%q) error = %v, want %v", path, err, ErrInvalidPath)
			}
		})
	}

	if _, err := Harden(HardenedOffset); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("Harden(HardenedOffset) error = %v, want %v", err, ErrInvalidPath)
	}
}
