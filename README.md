# BIP32-ED25519 [![PkgGoDev](https://pkg.go.dev/badge/github.com/islishude/bip32)](https://pkg.go.dev/github.com/islishude/bip32) ![ci](https://github.com/islishude/bip32/workflows/test/badge.svg) [![codecov](https://codecov.io/gh/islishude/bip32/branch/master/graph/badge.svg)](https://codecov.io/gh/islishude/bip32)

golang implements for [BIP32-Ed25519](https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf)

## Notes

Use `NewRootXPrvStrict`, `XPrv.DeriveStrict`, and `XPub.DeriveStrict` when strict BIP32-Ed25519 validation is required. The legacy root constructor keeps its historical seed handling for compatibility.

The BIP32-Ed25519 paper limits key-tree depth to `2^20`; callers should enforce that limit when deriving long paths.
