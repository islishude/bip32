package bip32

import "github.com/islishude/bip32/v2/internal/bip32path"

// IsHardened reports whether i has the hardened offset bit set.
func IsHardened(i uint32) bool {
	return i >= HardenedOffset
}

// Harden returns i with the hardened offset applied.
func Harden(i uint32) (uint32, error) {
	return bip32path.Harden(i, HardenedOffset, ErrInvalidPath)
}

// ParseAbsolutePath parses a path rooted at m. Hardened suffixes may be ', h,
// or H.
func ParseAbsolutePath(path string) ([]uint32, error) {
	return bip32path.ParseAbsolutePath(path, HardenedOffset, ErrInvalidPath)
}

// ParseRelativePath parses a path relative to an existing extended key.
func ParseRelativePath(path string) ([]uint32, error) {
	return bip32path.ParseRelativePath(path, HardenedOffset, ErrInvalidPath)
}
