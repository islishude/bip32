package bip32ed25519

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

const (
	icarusVectorEntropy = "46e62370a138a182a498b8e2885bc032379ddf38"
	icarusMasterNoPass  = "c065afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d245d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620"
	icarusMasterFooPass = "70531039904019351e1afb361cd1b312a4d0565d4ff9f8062d38acf4b15cce41d7b5738d9c893feea55512a3004acb0d222c35d3e3d5cde943a15a9824cbac59443cf67e589614076ba01e354b1a432e0e6db3b59e37fc56b5fb0222970a010e"
)

func mustDecodeHex(t *testing.T, raw string) []byte {
	t.Helper()
	out, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return out
}

func testIcarusRoot(t *testing.T) *XPrv {
	t.Helper()
	root, err := NewMasterKeyIcarus(mustDecodeHex(t, icarusVectorEntropy), nil)
	if err != nil {
		t.Fatalf("NewMasterKeyIcarus: %v", err)
	}
	return root
}

func TestNewMasterKeyIcarusCIP3Vectors(t *testing.T) {
	seed := mustDecodeHex(t, icarusVectorEntropy)

	tests := []struct {
		name     string
		password []byte
		wantHex  string
	}{
		{name: "no passphrase", password: nil, wantHex: icarusMasterNoPass},
		{name: "with passphrase", password: []byte("foo"), wantHex: icarusMasterFooPass},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, err := NewMasterKeyIcarus(seed, tt.password)
			if err != nil {
				t.Fatalf("NewMasterKeyIcarus: %v", err)
			}
			if got, want := root.Bytes(), mustDecodeHex(t, tt.wantHex); !bytes.Equal(got, want) {
				t.Fatalf("master key = %x, want %x", got, want)
			}
		})
	}
}

func TestNewMasterKeyIcarusInvalidSeed(t *testing.T) {
	if _, err := NewMasterKeyIcarus(nil, nil); !errors.Is(err, ErrInvalidSeed) {
		t.Fatalf("NewMasterKeyIcarus(nil) error = %v, want %v", err, ErrInvalidSeed)
	}
}

func TestNewMasterKeyRawKhovratovich(t *testing.T) {
	key, err := NewMasterKeyRawKhovratovich(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewMasterKeyRawKhovratovich: %v", err)
	}
	if len(key.Bytes()) != XPrvSize {
		t.Fatalf("raw master size = %d, want %d", len(key.Bytes()), XPrvSize)
	}

	if _, err := NewMasterKeyRawKhovratovich(make([]byte, 31)); !errors.Is(err, ErrInvalidSeed) {
		t.Fatalf("short raw master error = %v, want %v", err, ErrInvalidSeed)
	}
}

func TestGenerateMasterKeyRawKhovratovichSkipsRejectedSecrets(t *testing.T) {
	rejected := mustDecodeHex(t, "0200000000000000000000000000000000000000000000000000000000000000")
	valid := make([]byte, 32)

	if _, err := NewMasterKeyRawKhovratovich(rejected); !errors.Is(err, ErrRejectedMasterSecret) {
		t.Fatalf("rejected fixture error = %v, want %v", err, ErrRejectedMasterSecret)
	}

	want, err := NewMasterKeyRawKhovratovich(valid)
	if err != nil {
		t.Fatalf("valid fixture: %v", err)
	}

	reader := bytes.NewReader(append(append([]byte(nil), rejected...), valid...))
	got, err := GenerateMasterKeyRawKhovratovich(reader)
	if err != nil {
		t.Fatalf("GenerateMasterKeyRawKhovratovich: %v", err)
	}
	if !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Fatalf("generated raw master = %x, want %x", got.Bytes(), want.Bytes())
	}
}

func TestGenerateMasterKeyRawKhovratovichReturnsReaderError(t *testing.T) {
	rejected := mustDecodeHex(t, "0200000000000000000000000000000000000000000000000000000000000000")
	reader := bytes.NewReader(rejected)

	if _, err := GenerateMasterKeyRawKhovratovich(reader); err == nil {
		t.Fatal("GenerateMasterKeyRawKhovratovich: expected reader exhaustion error")
	}
}
