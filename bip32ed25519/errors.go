package bip32ed25519

import "errors"

var (
	// ErrInvalidSeed reports an empty or incorrectly sized master seed input.
	ErrInvalidSeed = errors.New("bip32ed25519: invalid seed")
	// ErrInvalidXPrv reports malformed 96-byte extended private key material.
	ErrInvalidXPrv = errors.New("bip32ed25519: invalid extended private key")
	// ErrInvalidXPub reports malformed 64-byte extended public key material.
	ErrInvalidXPub = errors.New("bip32ed25519: invalid extended public key")
	// ErrInvalidPath reports a malformed absolute or relative derivation path.
	ErrInvalidPath = errors.New("bip32ed25519: invalid derivation path")
	// ErrInvalidChild reports the rare invalid child-key discard condition.
	ErrInvalidChild = errors.New("bip32ed25519: invalid child key")
	// ErrInvalidTweak reports malformed derivation tweak input.
	ErrInvalidTweak = errors.New("bip32ed25519: invalid derivation tweak")
	// ErrNilKey reports method calls made on a nil key receiver.
	ErrNilKey = errors.New("bip32ed25519: nil key")
	// ErrDepthOverflow reports derivation past MaxDepth.
	ErrDepthOverflow = errors.New("bip32ed25519: derivation depth overflow")
	// ErrHardenedFromXPub reports hardened derivation attempted from XPub.
	ErrHardenedFromXPub = errors.New("bip32ed25519: cannot derive hardened child from xpub")
	// ErrRejectedMasterSecret reports raw Khovratovich root rejection.
	ErrRejectedMasterSecret = errors.New("bip32ed25519: rejected master secret")
)
