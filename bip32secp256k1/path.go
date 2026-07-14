package bip32secp256k1

import (
	"encoding/binary"

	bip32 "github.com/islishude/bip32/v2"
	"github.com/islishude/bip32/v2/internal/bip32path"
)

func ser32BE(i uint32) [4]byte {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], i)
	return out
}

// IsHardened reports whether i has the hardened offset bit set.
func IsHardened(i uint32) bool {
	return bip32.IsHardened(i)
}

// Harden applies the hardened offset to a normal child index.
func Harden(i uint32) (uint32, error) {
	return bip32path.Harden(i, HardenedOffset, ErrInvalidPath)
}

// ParseAbsolutePath parses a private path rooted at m.
func ParseAbsolutePath(path string) ([]uint32, error) {
	return bip32path.ParseAbsolutePath(path, HardenedOffset, ErrInvalidPath)
}

// ParseRelativePath parses a path relative to an existing extended key.
func ParseRelativePath(path string) ([]uint32, error) {
	return bip32path.ParseRelativePath(path, HardenedOffset, ErrInvalidPath)
}
