package bip32ed25519

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// ser32LE serializes a child index using ED25519-BIP32 little-endian order.
func ser32LE(i uint32) [4]byte {
	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], i)
	return out
}

// IsHardened reports whether i has the hardened offset bit set.
func IsHardened(i uint32) bool {
	return i >= HardenedOffset
}

// Harden returns i with the hardened offset applied.
func Harden(i uint32) (uint32, error) {
	if i >= HardenedOffset {
		return 0, ErrInvalidPath
	}
	return i + HardenedOffset, nil
}

// ParseAbsolutePath parses paths rooted at m.
//
// It accepts suffixes ', h, and H for hardened indexes.
func ParseAbsolutePath(path string) ([]uint32, error) {
	if path == "m" {
		return []uint32{}, nil
	}
	if !strings.HasPrefix(path, "m/") {
		return nil, fmt.Errorf("%w: %q", ErrInvalidPath, path)
	}

	rest := strings.TrimPrefix(path, "m/")
	if rest == "" {
		return nil, fmt.Errorf("%w: %q", ErrInvalidPath, path)
	}
	return parseSegments(rest)
}

// ParseRelativePath parses relative paths such as 0/0.
func ParseRelativePath(path string) ([]uint32, error) {
	if path == "" || path == "m" || strings.HasPrefix(path, "m/") {
		return nil, fmt.Errorf("%w: %q", ErrInvalidPath, path)
	}
	return parseSegments(path)
}

func parseSegments(path string) ([]uint32, error) {
	segments := strings.Split(path, "/")
	out := make([]uint32, 0, len(segments))
	for _, segment := range segments {
		index, err := parseSegment(segment)
		if err != nil {
			return nil, err
		}
		out = append(out, index)
	}
	return out, nil
}

func parseSegment(segment string) (uint32, error) {
	if segment == "" {
		return 0, fmt.Errorf("%w: empty segment", ErrInvalidPath)
	}

	hardened := false
	switch segment[len(segment)-1] {
	case '\'', 'h', 'H':
		hardened = true
		segment = segment[:len(segment)-1] // Strip the marker before decimal parsing.
	}
	if segment == "" {
		return 0, fmt.Errorf("%w: empty segment", ErrInvalidPath)
	}

	for _, r := range segment {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("%w: segment %q", ErrInvalidPath, segment)
		}
	}

	base, err := strconv.ParseUint(segment, 10, 32)
	if err != nil || base > uint64(HardenedOffset-1) {
		return 0, fmt.Errorf("%w: segment %q", ErrInvalidPath, segment)
	}

	index := uint32(base)
	if hardened {
		return index + HardenedOffset, nil // Safe because base is limited above.
	}
	return index, nil
}
