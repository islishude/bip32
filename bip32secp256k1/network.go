package bip32secp256k1

// Network selects the standard BIP-32 version pair used for serialization.
// Only Bitcoin mainnet and testnet version bytes are accepted.
type Network uint8

const (
	// Mainnet selects the standard xprv/xpub version bytes.
	Mainnet Network = iota + 1
	// Testnet selects the standard tprv/tpub version bytes.
	Testnet
)

var (
	mainnetPrivateVersion = [4]byte{0x04, 0x88, 0xad, 0xe4}
	mainnetPublicVersion  = [4]byte{0x04, 0x88, 0xb2, 0x1e}
	testnetPrivateVersion = [4]byte{0x04, 0x35, 0x83, 0x94}
	testnetPublicVersion  = [4]byte{0x04, 0x35, 0x87, 0xcf}
)

func validNetwork(network Network) bool {
	return network == Mainnet || network == Testnet
}

func privateVersion(network Network) [4]byte {
	if network == Testnet {
		return testnetPrivateVersion
	}
	return mainnetPrivateVersion
}

func publicVersion(network Network) [4]byte {
	if network == Testnet {
		return testnetPublicVersion
	}
	return mainnetPublicVersion
}

func networkFromPrivateVersion(version [4]byte) (Network, bool) {
	switch version {
	case mainnetPrivateVersion:
		return Mainnet, true
	case testnetPrivateVersion:
		return Testnet, true
	default:
		return 0, false
	}
}

func networkFromPublicVersion(version [4]byte) (Network, bool) {
	switch version {
	case mainnetPublicVersion:
		return Mainnet, true
	case testnetPublicVersion:
		return Testnet, true
	default:
		return 0, false
	}
}
