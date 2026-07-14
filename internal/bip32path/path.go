// Package bip32path contains the shared implementation behind the public root
// path helpers and the compatibility wrappers in curve-specific subpackages.
package bip32path

import (
	"fmt"
	"strconv"
	"strings"
)

// Harden applies hardenedOffset to a normal child index. invalidPath is
// supplied by the caller so compatibility wrappers retain their error values.
func Harden(i, hardenedOffset uint32, invalidPath error) (uint32, error) {
	if i >= hardenedOffset {
		return 0, invalidPath
	}
	return i + hardenedOffset, nil
}

// ParseAbsolutePath parses a path rooted at m.
func ParseAbsolutePath(path string, hardenedOffset uint32, invalidPath error) ([]uint32, error) {
	if path == "m" {
		return []uint32{}, nil
	}
	if !strings.HasPrefix(path, "m/") {
		return nil, fmt.Errorf("%w: %q", invalidPath, path)
	}
	rest := strings.TrimPrefix(path, "m/")
	if rest == "" {
		return nil, fmt.Errorf("%w: %q", invalidPath, path)
	}
	return parseSegments(rest, hardenedOffset, invalidPath)
}

// ParseRelativePath parses a path relative to an existing extended key.
func ParseRelativePath(path string, hardenedOffset uint32, invalidPath error) ([]uint32, error) {
	if path == "" || path == "m" || strings.HasPrefix(path, "m/") {
		return nil, fmt.Errorf("%w: %q", invalidPath, path)
	}
	return parseSegments(path, hardenedOffset, invalidPath)
}

func parseSegments(path string, hardenedOffset uint32, invalidPath error) ([]uint32, error) {
	segments := strings.Split(path, "/")
	out := make([]uint32, 0, len(segments))
	for _, segment := range segments {
		index, err := parseSegment(segment, hardenedOffset, invalidPath)
		if err != nil {
			return nil, err
		}
		out = append(out, index)
	}
	return out, nil
}

func parseSegment(segment string, hardenedOffset uint32, invalidPath error) (uint32, error) {
	if segment == "" {
		return 0, fmt.Errorf("%w: empty segment", invalidPath)
	}

	hardened := false
	switch segment[len(segment)-1] {
	case '\'', 'h', 'H':
		hardened = true
		segment = segment[:len(segment)-1]
	}
	if segment == "" {
		return 0, fmt.Errorf("%w: empty segment", invalidPath)
	}
	for _, r := range segment {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("%w: segment %q", invalidPath, segment)
		}
	}

	base, err := strconv.ParseUint(segment, 10, 32)
	if err != nil || base > uint64(hardenedOffset-1) {
		return 0, fmt.Errorf("%w: segment %q", invalidPath, segment)
	}
	index := uint32(base)
	if hardened {
		index += hardenedOffset
	}
	return index, nil
}
