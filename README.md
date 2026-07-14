# BIP32 [![PkgGoDev](https://pkg.go.dev/badge/github.com/islishude/bip32/v2)](https://pkg.go.dev/github.com/islishude/bip32/v2) ![ci](https://github.com/islishude/bip32/workflows/test/badge.svg) [![codecov](https://codecov.io/gh/islishude/bip32/branch/master/graph/badge.svg)](https://codecov.io/gh/islishude/bip32)

Go implementations of two hierarchical deterministic key schemes:

| Package          | Scheme and format                                                                                                                                                                 |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bip32`          | Scheme-independent chain-code/index constants and absolute/relative path helpers                                                                                                 |
| `bip32secp256k1` | Standard [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) over secp256k1, including `xprv`, `xpub`, `tprv`, and `tpub`                                    |
| `bip32ed25519`   | [Cardano/Khovratovich-Law Ed25519-BIP32](https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf), including Icarus roots, CIP-16 binary keys, and expanded-key signing |

The formats and APIs are intentionally separate: a key from one package cannot
be imported by the other. Neither package implements SLIP-0010; for that scheme,
use [islishude/slip10](https://github.com/islishude/slip10).

Shared path operations are available from the root package:

```go
import bip32 "github.com/islishude/bip32/v2"

indexes, err := bip32.ParseAbsolutePath("m/44'/0'/0'")
```

The curve-specific packages keep the same constants and path functions as
compatibility wrappers.

## Standard BIP-32 secp256k1

```go
import "github.com/islishude/bip32/v2/bip32secp256k1"
```

Create and derive a mainnet key:

```go
root, err := bip32secp256k1.NewMasterKey(seed, bip32secp256k1.Mainnet)
if err != nil {
    panic(err)
}

account, err := root.DerivePath("m/44'/0'/0'")
if err != nil {
    panic(err)
}

accountXPub, err := account.XPub()
if err != nil {
    panic(err)
}

receive0, err := accountXPub.DeriveRelativePath("0/0")
if err != nil {
    panic(err)
}

xprv, err := account.Encode() // explicit xprv Base58Check encoding
if err != nil {
    panic(err)
}
xpub, err := accountXPub.Encode()
if err != nil {
    panic(err)
}
_, _, _ = receive0, xprv, xpub
```

`NewMasterKey` accepts 16 through 64 bytes of seed material. `Mainnet` selects
`xprv`/`xpub`; `Testnet` selects `tprv`/`tpub`. `Bytes` returns the standard
78-byte payload, while `Encode` adds the Base58Check checksum. `ParseXPrv`,
`ParseXPub`, `NewXPrvFromBytes`, and `NewXPubFromBytes` strictly validate their
inputs.

Private derivation supports hardened and normal indexes. Public derivation
supports normal indexes only and returns `ErrHardenedFromXPub` otherwise. A
requested index is never silently incremented: an invalid BIP-32 child returns
`ErrInvalidChild` for that exact index.

Extended private keys deliberately do not implement `fmt.Stringer` or
`encoding.TextMarshaler`; use `Encode` only where secret-key export is intended.
This package provides derivation only. It does not provide ECDSA signing,
SLIP-132/custom versions, or a curve-generic API.

## Cardano/Khovratovich-Law Ed25519-BIP32

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

### Features

- Create an Icarus/Cardano Shelley root key from entropy.
- Derive hardened and soft children from `XPrv`.
- Derive soft children from `XPub`.
- Sign with expanded Ed25519 signing.
- Verify with standard `crypto/ed25519`.
- Parse paths such as `m/1852'/1815'/0'/0/0`.
- Serialize and import 96-byte XPrv and 64-byte XPub values.

### Master Key Generation

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

### Derivation

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

### Signing

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

### Serialization

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

### Ed25519 Paths

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

- Never log seeds, mnemonics, passwords, encoded XPrv values, XPrv bytes, `kL`,
  `kR`, or chain codes.
- Treat XPub values as privacy-sensitive. An account XPub can derive all soft
  public descendants for that account.
- Do not expose an ancestor XPub together with any non-hardened descendant
  private key.
- Use hardened derivation for master, purpose, coin type, and account levels.
- `bip32secp256k1.XPrv.Wipe` is best-effort only. The Go runtime may retain
  copies in stack frames, heap moves, returned slices, or encoded strings.
- The secp256k1 implementation uses generated Fiat-Crypto field/scalar
  arithmetic and fixed-window private-key operations without `math/big` in
  production code. This does not make Go a guaranteed secret-erasure or
  side-channel-free environment.

## Tests

Run:

```sh
go test -race ./...
go vet ./...
gofmt -d .
go mod tidy -diff
go fix -diff ./...
```

The secp256k1 suite covers official BIP-32 vectors 1 through 5, leading-zero
derivations, public/private derivation equivalence, invalid-child behavior,
arithmetic cross-checks, parser boundaries, and fuzz entry points. The Ed25519
suite covers CIP-0003 Icarus vectors, serialization, derivation equivalence,
Cardano-style paths, expanded signing, and parser fuzzing.
