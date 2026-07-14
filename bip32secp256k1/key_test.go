package bip32secp256k1

import (
	"bytes"
	"encoding"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var testSeed = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
}

func TestMasterKeyValidationAndNetworks(t *testing.T) {
	for _, size := range []int{0, MinSeedSize - 1, MaxSeedSize + 1} {
		if _, err := NewMasterKey(make([]byte, size), Mainnet); !errors.Is(err, ErrInvalidSeed) {
			t.Fatalf("seed size %d error = %v, want ErrInvalidSeed", size, err)
		}
	}
	if _, err := NewMasterKey(testSeed, Network(99)); !errors.Is(err, ErrInvalidNetwork) {
		t.Fatalf("network error = %v, want ErrInvalidNetwork", err)
	}

	mainKey := mustMaster(t, Mainnet)
	testKey := mustMaster(t, Testnet)
	if !bytes.Equal(mainKey.PrivateKey(), testKey.PrivateKey()) || !bytes.Equal(mainKey.ChainCode(), testKey.ChainCode()) {
		t.Fatal("network selection changed derived key material")
	}
	if got := mainKey.Bytes()[:4]; !bytes.Equal(got, mainnetPrivateVersion[:]) {
		t.Fatalf("mainnet version = %x", got)
	}
	if got := testKey.Bytes()[:4]; !bytes.Equal(got, testnetPrivateVersion[:]) {
		t.Fatalf("testnet version = %x", got)
	}
	tprv, err := testKey.Encode()
	if err != nil {
		t.Fatalf("Encode tprv: %v", err)
	}
	if len(tprv) != EncodedKeySize || !strings.HasPrefix(tprv, "tprv") {
		t.Fatalf("testnet private encoding = %q", tprv)
	}
	parsedPrivate, err := ParseXPrv(tprv)
	if err != nil || parsedPrivate.Network() != Testnet {
		t.Fatalf("ParseXPrv testnet = %v, %v", parsedPrivate, err)
	}
	testPub, err := testKey.XPub()
	if err != nil {
		t.Fatalf("XPub: %v", err)
	}
	tpub, err := testPub.Encode()
	if err != nil {
		t.Fatalf("Encode tpub: %v", err)
	}
	if len(tpub) != EncodedKeySize || !strings.HasPrefix(tpub, "tpub") {
		t.Fatalf("testnet public encoding = %q", tpub)
	}
	parsedPublic, err := ParseXPub(tpub)
	if err != nil || parsedPublic.Network() != Testnet {
		t.Fatalf("ParseXPub testnet = %v, %v", parsedPublic, err)
	}
}

func TestExtendedKeyBinaryValidation(t *testing.T) {
	root := mustMaster(t, Mainnet)
	xpub, err := root.XPub()
	if err != nil {
		t.Fatalf("XPub: %v", err)
	}

	privateBytes := root.Bytes()
	privateRoundTrip, err := NewXPrvFromBytes(privateBytes)
	if err != nil || !bytes.Equal(privateRoundTrip.Bytes(), privateBytes) {
		t.Fatalf("private binary round trip: %v", err)
	}
	publicBytes := xpub.Bytes()
	publicRoundTrip, err := NewXPubFromBytes(publicBytes)
	if err != nil || !bytes.Equal(publicRoundTrip.Bytes(), publicBytes) {
		t.Fatalf("public binary round trip: %v", err)
	}

	if _, err := NewXPrvFromBytes(privateBytes[:SerializedKeySize-1]); !errors.Is(err, ErrInvalidXPrv) {
		t.Fatalf("short xprv error = %v", err)
	}
	if _, err := NewXPubFromBytes(publicBytes[:SerializedKeySize-1]); !errors.Is(err, ErrInvalidXPub) {
		t.Fatalf("short xpub error = %v", err)
	}
	if _, err := NewXPrvFromBytes(publicBytes); !errors.Is(err, ErrInvalidXPrv) {
		t.Fatalf("public version as xprv error = %v", err)
	}
	if _, err := NewXPubFromBytes(privateBytes); !errors.Is(err, ErrInvalidXPub) {
		t.Fatalf("private version as xpub error = %v", err)
	}

	unknown := append([]byte(nil), privateBytes...)
	copy(unknown[:4], []byte{1, 2, 3, 4})
	if _, err := NewXPrvFromBytes(unknown); !errors.Is(err, ErrInvalidNetwork) {
		t.Fatalf("unknown version error = %v", err)
	}
	badPrefix := append([]byte(nil), privateBytes...)
	badPrefix[keyDataOffset] = 1
	if _, err := NewXPrvFromBytes(badPrefix); !errors.Is(err, ErrInvalidXPrv) {
		t.Fatalf("bad private prefix error = %v", err)
	}
	zeroPrivate := append([]byte(nil), privateBytes...)
	clear(zeroPrivate[keyDataOffset+1:])
	if _, err := NewXPrvFromBytes(zeroPrivate); !errors.Is(err, ErrInvalidXPrv) {
		t.Fatalf("zero private error = %v", err)
	}
	badPublic := append([]byte(nil), publicBytes...)
	badPublic[keyDataOffset] = 4
	if _, err := NewXPubFromBytes(badPublic); !errors.Is(err, ErrInvalidXPub) {
		t.Fatalf("bad public prefix error = %v", err)
	}
	badRootMetadata := append([]byte(nil), privateBytes...)
	badRootMetadata[fingerprintOffset] = 1
	if _, err := NewXPrvFromBytes(badRootMetadata); !errors.Is(err, ErrInvalidXPrv) {
		t.Fatalf("bad root metadata error = %v", err)
	}
	badRootChild := append([]byte(nil), privateBytes...)
	badRootChild[chainCodeOffset-1] = 1
	if _, err := NewXPrvFromBytes(badRootChild); !errors.Is(err, ErrInvalidXPrv) {
		t.Fatalf("bad private root child error = %v", err)
	}
	badPublicRootMetadata := append([]byte(nil), publicBytes...)
	badPublicRootMetadata[fingerprintOffset] = 1
	if _, err := NewXPubFromBytes(badPublicRootMetadata); !errors.Is(err, ErrInvalidXPub) {
		t.Fatalf("bad public root metadata error = %v", err)
	}
	badPublicRootChild := append([]byte(nil), publicBytes...)
	badPublicRootChild[chainCodeOffset-1] = 1
	if _, err := NewXPubFromBytes(badPublicRootChild); !errors.Is(err, ErrInvalidXPub) {
		t.Fatalf("bad public root child error = %v", err)
	}
}

func TestBase58CheckErrorClassification(t *testing.T) {
	root := mustMaster(t, Mainnet)
	xprv, err := root.Encode()
	if err != nil {
		t.Fatalf("Encode xprv: %v", err)
	}
	xpubKey, err := root.XPub()
	if err != nil {
		t.Fatalf("XPub: %v", err)
	}
	xpub, err := xpubKey.Encode()
	if err != nil {
		t.Fatalf("Encode xpub: %v", err)
	}

	invalidCharacter := xprv[:20] + "0" + xprv[21:]
	if _, err := ParseXPrv(invalidCharacter); !errors.Is(err, ErrInvalidEncoding) {
		t.Fatalf("invalid-character error = %v", err)
	}
	if _, err := ParseXPrv(xprv[:len(xprv)-1]); !errors.Is(err, ErrInvalidEncoding) {
		t.Fatalf("short-encoding error = %v", err)
	}

	last := byte('1')
	if xprv[len(xprv)-1] == last {
		last = '2'
	}
	badChecksum := xprv[:len(xprv)-1] + string(last)
	if _, err := ParseXPrv(badChecksum); !errors.Is(err, ErrInvalidChecksum) {
		t.Fatalf("checksum error = %v", err)
	}
	if _, err := ParseXPrv(xpub); !errors.Is(err, ErrInvalidXPrv) {
		t.Fatalf("xpub-as-xprv error = %v", err)
	}
	if _, err := ParseXPub(xprv); !errors.Is(err, ErrInvalidXPub) {
		t.Fatalf("xprv-as-xpub error = %v", err)
	}
}

func TestKeyCopiesWipeAndExplicitTextOnly(t *testing.T) {
	root := mustMaster(t, Mainnet)
	originalPrivate := root.PrivateKey()
	originalPrivate[0] ^= 0xff
	if bytes.Equal(originalPrivate, root.PrivateKey()) {
		t.Fatal("PrivateKey returned an alias")
	}
	chainCode := root.ChainCode()
	chainCode[0] ^= 0xff
	if bytes.Equal(chainCode, root.ChainCode()) {
		t.Fatal("ChainCode returned an alias")
	}

	xpub, err := root.XPub()
	if err != nil {
		t.Fatalf("XPub: %v", err)
	}
	stringer := reflect.TypeFor[fmt.Stringer]()
	textMarshaler := reflect.TypeFor[encoding.TextMarshaler]()
	for _, value := range []any{root, xpub} {
		typ := reflect.TypeOf(value)
		if typ.Implements(stringer) || typ.Implements(textMarshaler) {
			t.Fatalf("%v unexpectedly supports implicit text serialization", typ)
		}
	}

	root.Wipe()
	if root.Network() != 0 || root.PrivateKey() == nil || !bytes.Equal(root.PrivateKey(), make([]byte, PrivateKeySize)) {
		t.Fatal("Wipe did not clear private state")
	}
	if _, err := root.PublicKey(); !errors.Is(err, ErrInvalidXPrv) {
		t.Fatalf("PublicKey after Wipe error = %v", err)
	}
	if _, err := root.Encode(); !errors.Is(err, ErrInvalidXPrv) {
		t.Fatalf("Encode after Wipe error = %v", err)
	}
}

func TestNilKeyMethods(t *testing.T) {
	var private *XPrv
	var public *XPub
	if _, err := private.Derive(0); !errors.Is(err, ErrNilKey) {
		t.Fatalf("nil private Derive error = %v", err)
	}
	if _, err := private.DerivePath("m"); !errors.Is(err, ErrNilKey) {
		t.Fatalf("nil private DerivePath error = %v", err)
	}
	if _, err := private.Encode(); !errors.Is(err, ErrNilKey) {
		t.Fatalf("nil private Encode error = %v", err)
	}
	if _, err := public.Derive(0); !errors.Is(err, ErrNilKey) {
		t.Fatalf("nil public Derive error = %v", err)
	}
	if _, err := public.Encode(); !errors.Is(err, ErrNilKey) {
		t.Fatalf("nil public Encode error = %v", err)
	}
	if private.Bytes() != nil || public.Bytes() != nil || private.PrivateKey() != nil || public.ChainCode() != nil {
		t.Fatal("nil key copy method returned non-nil bytes")
	}
}

func mustMaster(t *testing.T, network Network) *XPrv {
	t.Helper()
	root, err := NewMasterKey(testSeed, network)
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}
	return root
}
