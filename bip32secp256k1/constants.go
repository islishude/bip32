package bip32secp256k1

import bip32 "github.com/islishude/bip32/v2"

const (
	// PrivateKeySize is the width of a canonical secp256k1 private scalar.
	PrivateKeySize = 32
	// PublicKeySize is the width of a compressed SEC 1 public key.
	PublicKeySize = 33
	// ChainCodeSize is the width of a BIP-32 chain code.
	ChainCodeSize = bip32.ChainCodeSize
	// FingerprintSize is the width of a serialized parent fingerprint.
	FingerprintSize = 4
	// SerializedKeySize is the BIP-32 binary extended-key payload size. It does
	// not include the four-byte Base58Check checksum.
	SerializedKeySize = 78
	// XPrvSize and XPubSize name the standard serialized payload size for each
	// extended-key kind.
	XPrvSize = SerializedKeySize
	XPubSize = SerializedKeySize
	// EncodedKeySize is the exact text length of xprv/xpub/tprv/tpub values.
	EncodedKeySize = 111
	// ChecksumSize is the Base58Check checksum width.
	ChecksumSize = 4

	// MinSeedSize and MaxSeedSize are the BIP-32 master-seed bounds.
	MinSeedSize = 16
	MaxSeedSize = 64

	// HardenedOffset separates normal and hardened child indexes.
	HardenedOffset uint32 = bip32.HardenedOffset
	// MaxDepth is the largest depth representable by the one-byte BIP-32 field.
	MaxDepth uint8 = 255
)
