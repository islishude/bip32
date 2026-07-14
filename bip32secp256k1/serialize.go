package bip32secp256k1

import (
	"encoding/binary"

	internalsecp "github.com/islishude/bip32/v2/internal/secp256k1"
)

const (
	versionOffset     = 0
	depthOffset       = 4
	fingerprintOffset = 5
	childOffset       = 9
	chainCodeOffset   = 13
	keyDataOffset     = 45
)

// Bytes returns the 78-byte BIP-32 extended-private-key payload without the
// Base58Check checksum.
func (k *XPrv) Bytes() []byte {
	if k == nil || !validNetwork(k.network) {
		return nil
	}
	out := make([]byte, SerializedKeySize)
	version := privateVersion(k.network)
	copy(out[versionOffset:depthOffset], version[:])
	out[depthOffset] = k.depth
	copy(out[fingerprintOffset:childOffset], k.parentFingerprint[:])
	binary.BigEndian.PutUint32(out[childOffset:chainCodeOffset], k.childNumber)
	copy(out[chainCodeOffset:keyDataOffset], k.cc[:])
	out[keyDataOffset] = 0
	copy(out[keyDataOffset+1:], k.key[:])
	return out
}

// Bytes returns the 78-byte BIP-32 extended-public-key payload without the
// Base58Check checksum.
func (p *XPub) Bytes() []byte {
	if p == nil || !validNetwork(p.network) {
		return nil
	}
	out := make([]byte, SerializedKeySize)
	version := publicVersion(p.network)
	copy(out[versionOffset:depthOffset], version[:])
	out[depthOffset] = p.depth
	copy(out[fingerprintOffset:childOffset], p.parentFingerprint[:])
	binary.BigEndian.PutUint32(out[childOffset:chainCodeOffset], p.childNumber)
	copy(out[chainCodeOffset:keyDataOffset], p.cc[:])
	copy(out[keyDataOffset:], p.pub[:])
	return out
}

// Encode explicitly returns the xprv or tprv Base58Check representation. XPrv
// intentionally does not implement fmt.Stringer or encoding.TextMarshaler.
func (k *XPrv) Encode() (string, error) {
	if k == nil {
		return "", ErrNilKey
	}
	payload := k.Bytes()
	if payload == nil {
		return "", ErrInvalidXPrv
	}
	defer clear(payload)
	return encodeBase58Check(payload)
}

// Encode explicitly returns the xpub or tpub Base58Check representation.
func (p *XPub) Encode() (string, error) {
	if p == nil {
		return "", ErrNilKey
	}
	payload := p.Bytes()
	if payload == nil {
		return "", ErrInvalidXPub
	}
	defer clear(payload)
	return encodeBase58Check(payload)
}

// NewXPrvFromBytes imports a 78-byte standard BIP-32 private payload.
func NewXPrvFromBytes(serialized []byte) (*XPrv, error) {
	if len(serialized) != SerializedKeySize {
		return nil, ErrInvalidXPrv
	}
	var version [4]byte
	copy(version[:], serialized[versionOffset:depthOffset])
	network, ok := networkFromPrivateVersion(version)
	if !ok {
		if _, public := networkFromPublicVersion(version); public {
			return nil, ErrInvalidXPrv
		}
		return nil, ErrInvalidNetwork
	}
	if serialized[keyDataOffset] != 0 {
		return nil, ErrInvalidXPrv
	}

	var key [PrivateKeySize]byte
	copy(key[:], serialized[keyDataOffset+1:])
	if !internalsecp.ValidPrivateScalar(&key) {
		clear(key[:])
		return nil, ErrInvalidXPrv
	}

	keyOut := &XPrv{
		key:         key,
		network:     network,
		depth:       serialized[depthOffset],
		childNumber: binary.BigEndian.Uint32(serialized[childOffset:chainCodeOffset]),
	}
	copy(keyOut.parentFingerprint[:], serialized[fingerprintOffset:childOffset])
	copy(keyOut.cc[:], serialized[chainCodeOffset:keyDataOffset])
	clear(key[:])
	if keyOut.depth == 0 && (keyOut.parentFingerprint != [FingerprintSize]byte{} || keyOut.childNumber != 0) {
		keyOut.Wipe()
		return nil, ErrInvalidXPrv
	}
	return keyOut, nil
}

// NewXPubFromBytes imports a 78-byte standard BIP-32 public payload.
func NewXPubFromBytes(serialized []byte) (*XPub, error) {
	if len(serialized) != SerializedKeySize {
		return nil, ErrInvalidXPub
	}
	var version [4]byte
	copy(version[:], serialized[versionOffset:depthOffset])
	network, ok := networkFromPublicVersion(version)
	if !ok {
		if _, private := networkFromPrivateVersion(version); private {
			return nil, ErrInvalidXPub
		}
		return nil, ErrInvalidNetwork
	}

	var pub [PublicKeySize]byte
	copy(pub[:], serialized[keyDataOffset:])
	if !internalsecp.ValidPublicKey(&pub) {
		return nil, ErrInvalidXPub
	}
	keyOut := &XPub{
		pub:         pub,
		network:     network,
		depth:       serialized[depthOffset],
		childNumber: binary.BigEndian.Uint32(serialized[childOffset:chainCodeOffset]),
	}
	copy(keyOut.parentFingerprint[:], serialized[fingerprintOffset:childOffset])
	copy(keyOut.cc[:], serialized[chainCodeOffset:keyDataOffset])
	if keyOut.depth == 0 && (keyOut.parentFingerprint != [FingerprintSize]byte{} || keyOut.childNumber != 0) {
		return nil, ErrInvalidXPub
	}
	return keyOut, nil
}

// ParseXPrv decodes and validates an xprv or tprv value.
func ParseXPrv(encoded string) (*XPrv, error) {
	payload, err := decodeBase58Check(encoded)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	return NewXPrvFromBytes(payload)
}

// ParseXPub decodes and validates an xpub or tpub value.
func ParseXPub(encoded string) (*XPub, error) {
	payload, err := decodeBase58Check(encoded)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	return NewXPubFromBytes(payload)
}
