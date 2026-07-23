# Internal secp256k1 backend

This package contains only the secp256k1 operations required by the public
`bip32secp256k1` package:

- canonical scalar parsing and addition modulo the group order;
- compressed SEC 1 point parsing and encoding;
- constant-time fixed-base scalar multiplication;
- public-input point addition for normal XPub derivation.

The implementation is adapted from
[`github.com/islishude/secp256k1` at commit `37eab343947c638e6d5dc009c531eb43482c6af1`](https://github.com/islishude/secp256k1/tree/37eab343947c638e6d5dc009c531eb43482c6af1).
ECDSA, recovery, GLV verification, variable-time secret paths, and architecture
specific assembly are intentionally not included.

## Generated code

Field and scalar arithmetic, fixed-exponent field operations, and the pure-Go
W5 fixed-base table are checked-in generated code. From this directory,
regenerate all of them with:

```sh
go generate
```

The generators under `cmd` are:

- `genfiat`, which uses Fiat-Crypto's formally verified model to generate the
  base- and scalar-field arithmetic;
- `genaddchain`, which uses
  [`github.com/mmcloughlin/addchain`](https://github.com/mmcloughlin/addchain)
  to generate field inversion (`p - 2`) and square-root (`(p + 1) / 4`)
  routines;
- `genprecomp`, which generates the fixed-base table.

`genfiat` and `genaddchain` use the
`ghcr.io/islishude/fiat-crypto-go-tool` Docker image by default. Set
`FIAT_CRYPTO_GO_TOOL_IMAGE` to use another image, or set `FIAT_CRYPTO_BIN` and
`ADDCHAIN_BIN` to intentionally use local binaries instead. The Fiat-Crypto
version used for the checked-in arithmetic reported commit
`9d0682462646bf645cba7409fa45794dee0418aa` (`v0.1.6`).

Fiat-Crypto generated code is available under the MIT, Apache 2.0, or BSD
1-Clause license; see the Fiat-Crypto project for the full license texts and
AUTHORS file. Normal builds do not run generators, and production packages do
not use `math/big`; the table generator and arithmetic oracle tests may use it.
