package bip32secp256k1

import internalsecp "github.com/islishude/bip32/v2/internal/secp256k1"

const bitcoinSeedKey = "Bitcoin seed"

// NewMasterKey derives a standard BIP-32 master extended private key.
func NewMasterKey(seed []byte, network Network) (*XPrv, error) {
	return newMasterKey(seed, network, hmacSHA512)
}

func newMasterKey(seed []byte, network Network, mac hmac512Func) (*XPrv, error) {
	if len(seed) < MinSeedSize || len(seed) > MaxSeedSize {
		return nil, ErrInvalidSeed
	}
	if !validNetwork(network) {
		return nil, ErrInvalidNetwork
	}

	i := mac([]byte(bitcoinSeedKey), seed)
	defer clear(i[:])

	var key [PrivateKeySize]byte
	copy(key[:], i[:PrivateKeySize])
	if !internalsecp.ValidPrivateScalar(&key) {
		clear(key[:])
		return nil, ErrInvalidMasterKey
	}

	master := &XPrv{key: key, network: network}
	copy(master.cc[:], i[PrivateKeySize:])
	clear(key[:])
	return master, nil
}
