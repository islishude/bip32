The code generated from this directory uses github.com/mmcloughlin/addchain to
produce fixed-exponent routines for:

    field inverse: p - 2
    field square root: (p + 1) / 4
The checked-in files are generated artifacts, so normal builds and tests don't
require addchain. To regenerate them, run Docker and then:

    go generate

The generator runs addchain from:

    ghcr.io/islishude/fiat-crypto-go-tool

Set FIAT_CRYPTO_GO_TOOL_IMAGE to use a mirror or pinned tag. Set ADDCHAIN_BIN
only when intentionally bypassing Docker with a local addchain binary.
