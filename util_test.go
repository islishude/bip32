package bip32

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

func Test_add28Mul8(t *testing.T) {
	HexDecode := MustHexDecode(t)

	type args struct {
		x string
		y string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "case 1",
			args: args{
				x: "b9d2ad48d44954b409f674a306c08da5b7e1c52005a512f5854c2593173db4a6",
				y: "1d9b4170ef340b683ddf03f847b1c1aeb8d276e271446c52c9fbd324a3fa8206",
			},
			want: "a1abbaca4ff1adf4f4ef9363464a9b1b7d777c3494c87488d02ac5b9183db4a6",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x, y := HexDecode(tt.args.x, 32), HexDecode(tt.args.y, 32)
			if got, want := add28Mul8(x, y), HexDecode(tt.want, 32); !bytes.Equal(got[:], want) {
				t.Errorf("add28Mul8() = %v, want %v", hex.EncodeToString(got[:]), tt.want)
			}
		})
	}
}

func Test_add256Bits(t *testing.T) {
	HexDecode := MustHexDecode(t)
	type args struct {
		x string
		y string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "case 1",
			args: args{
				x: "b9d2ad48d44954b409f674a306c08da5b7e1c52005a512f5854c2593173db4a6",
				y: "1d9b4170ef340b683ddf03f847b1c1aeb8d276e271446c52c9fbd324a3fa8206",
			},
			want: "d66defb8c37e5f1c47d5789b4e714f5470b43c0377e97e474f48f9b7ba3737ad",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x, y := HexDecode(tt.args.x, 32), HexDecode(tt.args.y, 32)
			if got, want := add256Bits(x, y), HexDecode(tt.want, 32); !bytes.Equal(got[:], want) {
				t.Errorf("add256Bits() = %v, want %v", hex.EncodeToString(got[:]), tt.want)
			}
		})
	}
}

func Test_isDivisibleByEd25519BaseOrder(t *testing.T) {
	if !isDivisibleByEd25519BaseOrder(make([]byte, 32)) {
		t.Fatal("isDivisibleByEd25519BaseOrder: zero should be divisible")
	}

	order := littleEndianBytesFromBigInt(new(big.Int).Set(ed25519BaseOrder))
	if !isDivisibleByEd25519BaseOrder(order) {
		t.Fatal("isDivisibleByEd25519BaseOrder: base order should be divisible")
	}

	orderPlusOne := littleEndianBytesFromBigInt(new(big.Int).Add(ed25519BaseOrder, big.NewInt(1)))
	if isDivisibleByEd25519BaseOrder(orderPlusOne) {
		t.Fatal("isDivisibleByEd25519BaseOrder: base order plus one should not be divisible")
	}
}

func Test_isIdentityPointEncoding(t *testing.T) {
	var identity [32]byte
	identity[0] = 1
	if !isIdentityPointEncoding(identity[:]) {
		t.Fatal("isIdentityPointEncoding: expected identity encoding")
	}

	if isIdentityPointEncoding(make([]byte, 32)) {
		t.Fatal("isIdentityPointEncoding: zero bytes should not be identity encoding")
	}
}

func littleEndianBytesFromBigInt(value *big.Int) []byte {
	be := value.Bytes()
	le := make([]byte, 32)
	for i := range be {
		le[i] = be[len(be)-1-i]
	}
	return le
}
