package bip32

const (
	// ChainCodeSize is the byte size of a BIP-32 chain code.
	ChainCodeSize = 32
	// HardenedOffset separates normal and hardened child indexes.
	HardenedOffset uint32 = 0x80000000
)
