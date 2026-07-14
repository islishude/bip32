package bip32

import "errors"

var (
	// ErrInvalidPath reports a malformed absolute or relative derivation path.
	ErrInvalidPath = errors.New("bip32: invalid derivation path")
)
