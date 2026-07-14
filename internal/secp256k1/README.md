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

The adapted backend is distributed under [`LICENSE-MIT`](LICENSE-MIT).
Generator code modeled on Go's crypto packages retains the Go project terms in
[`LICENSES/BSD-3-Clause-Go.txt`](LICENSES/BSD-3-Clause-Go.txt). Fiat-Crypto's
separate selectable license texts are checked into the `fiat` directory.

Field and scalar arithmetic use checked-in Fiat-Crypto generated code. See
[`fiat/README.md`](fiat/README.md) and [`addchain/README.md`](addchain/README.md)
for their regeneration requirements and licenses. Regenerate the pure-Go W5
fixed-base table from this directory with:

```sh
go generate
```

Normal builds do not run generators and production packages do not use
`math/big`; the table generator and arithmetic oracle tests may use it.
