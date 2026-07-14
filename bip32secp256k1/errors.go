package bip32secp256k1

import "errors"

var (
	// ErrInvalidSeed reports a master seed outside the 16-to-64-byte range.
	ErrInvalidSeed = errors.New("bip32secp256k1: invalid seed")
	// ErrInvalidMasterKey reports a master HMAC result that is zero or >= n.
	ErrInvalidMasterKey = errors.New("bip32secp256k1: invalid master key")
	// ErrInvalidNetwork reports a network or version outside Mainnet/Testnet.
	ErrInvalidNetwork = errors.New("bip32secp256k1: invalid network")
	// ErrInvalidXPrv reports malformed extended-private-key material.
	ErrInvalidXPrv = errors.New("bip32secp256k1: invalid extended private key")
	// ErrInvalidXPub reports malformed extended-public-key material.
	ErrInvalidXPub = errors.New("bip32secp256k1: invalid extended public key")
	// ErrInvalidEncoding reports malformed or non-canonical Base58 text.
	ErrInvalidEncoding = errors.New("bip32secp256k1: invalid Base58Check encoding")
	// ErrInvalidChecksum reports a Base58Check checksum mismatch.
	ErrInvalidChecksum = errors.New("bip32secp256k1: invalid Base58Check checksum")
	// ErrInvalidPath reports a malformed absolute or relative derivation path.
	ErrInvalidPath = errors.New("bip32secp256k1: invalid derivation path")
	// ErrInvalidChild reports an exact-index IL >= n, zero key, or infinity.
	ErrInvalidChild = errors.New("bip32secp256k1: invalid child key")
	// ErrNilKey reports a method call on a nil key receiver.
	ErrNilKey = errors.New("bip32secp256k1: nil key")
	// ErrDepthOverflow reports derivation past the one-byte depth limit.
	ErrDepthOverflow = errors.New("bip32secp256k1: derivation depth overflow")
	// ErrNotRoot reports absolute-path derivation from a non-root key.
	ErrNotRoot = errors.New("bip32secp256k1: absolute derivation requires a root key")
	// ErrHardenedFromXPub reports hardened public-child derivation.
	ErrHardenedFromXPub = errors.New("bip32secp256k1: cannot derive hardened child from xpub")
)
