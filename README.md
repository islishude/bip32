# BIP32-ED25519 [![PkgGoDev](https://pkg.go.dev/badge/github.com/islishude/bip32/v2)](https://pkg.go.dev/github.com/islishude/bip32/v2) ![ci](https://github.com/islishude/bip32/workflows/test/badge.svg) [![codecov](https://codecov.io/gh/islishude/bip32/branch/master/graph/badge.svg)](https://codecov.io/gh/islishude/bip32)

Go implementation of [Cardano/Khovratovich-Law ED25519-BIP32](https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf).

This repository provides a `bip32ed25519` package for the Ed25519 BIP32
variant used by Cardano wallets. It supports soft public derivation, hardened
private derivation, CIP-16 style binary serialization, and standard Ed25519
signing/verification with expanded private keys.

This is not SLIP-0010 and it is not secp256k1 BIP32.

For SLIP-0010 golang implementaion use [islishude/slip10](https://github.com/islishude/slip10) module instead.

## Package

```go
import "github.com/islishude/bip32/v2/bip32ed25519"
```

The main types are:

```go
type XPrv // 96 bytes: kL || kR || chainCode
type XPub // 64 bytes: publicKey || chainCode
```

`XPrv` contains an expanded Ed25519 private key. The first 32 bytes, `kL`, are
not an Ed25519 seed. Do not pass `kL` to `ed25519.NewKeyFromSeed`.

## Features

- Create an Icarus/Cardano Shelley root key from entropy.
- Derive hardened and soft children from `XPrv`.
- Derive soft children from `XPub`.
- Sign with expanded Ed25519 signing.
- Verify with standard `crypto/ed25519`.
- Parse paths such as `m/1852'/1815'/0'/0/0`.
- Serialize and import 96-byte XPrv and 64-byte XPub values.

## Master Key Generation

For Cardano Shelley-era wallets, use Icarus:

```go
root, err := bip32ed25519.NewMasterKeyIcarus(entropy, password)
if err != nil {
    panic(err)
}
```

`entropy` should be the upper-layer entropy input used by the Icarus scheme.
For a BIP39 recovery phrase, that normally means mnemonic-to-entropy output,
not the 64-byte BIP39 PBKDF2 seed.

The package also includes `NewMasterKeyRawKhovratovich` for systems that
explicitly need the paper-style raw root algorithm. Do not mix root key variants
inside the same keystore without storing variant metadata.

## Derivation

Cardano Shelley payment key example:

```go
paymentKey, err := root.DerivePath("m/1852'/1815'/0'/0/0")
if err != nil {
    panic(err)
}

pub, err := paymentKey.PublicKey()
if err != nil {
    panic(err)
}
_ = pub
```

Watch-only account public derivation:

```go
account, err := root.DerivePath("m/1852'/1815'/0'")
if err != nil {
    panic(err)
}

accountXPub, err := account.XPub()
if err != nil {
    panic(err)
}

addr0, err := accountXPub.DeriveRelativePath("0/0")
if err != nil {
    panic(err)
}
_ = addr0
```

`XPub` can derive only soft indexes. Hardened derivation from an `XPub` returns
`ErrHardenedFromXPub`.

## Signing

```go
message := []byte("hello ed25519-bip32")

sig, err := paymentKey.Sign(message)
if err != nil {
    panic(err)
}

pub, err := paymentKey.PublicKey()
if err != nil {
    panic(err)
}

if !bip32ed25519.Verify(pub, message, sig) {
    panic("invalid signature")
}
```

Signing uses:

```text
r = SHA512(kR || message) mod L
R = [r]B
h = SHA512(R || A || message) mod L
S = r + h * kL mod L
signature = R || S
```

This keeps signatures compatible with standard Ed25519 verification while using
the ED25519-BIP32 expanded private key.

## Serialization

```go
xprvBytes := paymentKey.Bytes() // 96 bytes

xprv, err := bip32ed25519.NewXPrvFromBytes(xprvBytes)
if err != nil {
    panic(err)
}

xpub, err := xprv.XPub()
if err != nil {
    panic(err)
}

xpubBytes := xpub.Bytes() // 64 bytes
_, err = bip32ed25519.NewXPubFromBytes(xpubBytes)
if err != nil {
    panic(err)
}
```

The binary formats are:

```text
XPrv = kL || kR || chainCode
XPub = publicKey || chainCode
```

Metadata such as derivation depth and child number is not included in these
binary encodings.

## Paths

Supported examples:

```text
m
m/1852'/1815'/0'/0/0
m/44h/1815h/0h/0/0
m/44H/1815H/0H/0/0
0/0
```

Rules:

- Hardened suffixes are `'`, `h`, and `H`.
- Soft indexes must be `0 <= index <= 2147483647`.
- Hardened base indexes must be `0 <= index <= 2147483647`.
- Child indexes are serialized little-endian for HMAC input.

## Security Notes

- Never log seeds, mnemonics, passwords, XPrv bytes, `kL`, `kR`, or chain codes.
- Treat XPub values as privacy-sensitive. An account XPub can derive all soft
  public descendants for that account.
- Do not expose an ancestor XPub together with any non-hardened descendant
  private key.
- Use hardened derivation for master, purpose, coin type, and account levels.
- `XPrv.Wipe` is best-effort only. The Go runtime may retain copies in memory.

## Tests

Run:

```sh
go test ./...
go vet ./...
```

The test suite covers CIP-0003 Icarus master vectors, serialization
round-trips, soft public/private derivation equivalence, hardened-from-XPub
failure, Cardano-style paths, expanded signing, and fuzz entry points for
import and path parsing.
