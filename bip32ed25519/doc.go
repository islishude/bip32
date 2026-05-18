// Package bip32ed25519 implements the Cardano/Khovratovich-Law
// ED25519-BIP32 scheme.
//
// The package intentionally implements the Ed25519 BIP32 variant that supports
// soft public derivation. It is not SLIP-0010, and it does not treat child kL
// values as RFC 8032 32-byte Ed25519 seeds.
package bip32ed25519
