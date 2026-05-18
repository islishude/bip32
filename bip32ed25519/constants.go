package bip32ed25519

const (
	// ScalarSize is the byte size of kL, the little-endian scalar half of XPrv.
	ScalarSize = 32
	// PrefixSize is the byte size of kR, the deterministic signing nonce prefix.
	PrefixSize = 32
	// ChainCodeSize is the byte size of the BIP32 chain code.
	ChainCodeSize = 32
	// PublicKeySize is the byte size of a compressed Ed25519 public key.
	PublicKeySize = 32

	// XPrvSize is the CIP-16 binary size of kL || kR || chainCode.
	XPrvSize = 96
	// XPubSize is the CIP-16 binary size of publicKey || chainCode.
	XPubSize = 64

	// HardenedOffset is ORed into child indexes for hardened derivation.
	HardenedOffset uint32 = 0x80000000
	// MaxDepth is the key-tree depth limit used by the ED25519-BIP32 paper.
	MaxDepth uint32 = 1 << 20
)
