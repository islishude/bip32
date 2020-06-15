package bip32

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"testing"
)

const TestSeed = "cdc36eaa638a07b5881b62bbb8ea8c2819e2b50e0cf51de14489c6d2dc29cb7914828443112319ee3ee64c82cda51c0f0df3c9550994bf70b4383d234e6e8ffd"
const TestKey = "80660d61ec16a6ca93e05e1738082dff22a422f00e95a5dfa9d91a74fab4725a017255017df26d8ff29dbe315c838cd" +
	"3837a311e611a9dd1c8c8a82a21ad2ec314828443112319ee3ee64c82cda51c0f0df3c9550994bf70b4383d234e6e8ffd"

func MustHexDecode(t *testing.T) func(raw string, size int) []byte {
	return func(raw string, size int) []byte {
		data, err := hex.DecodeString(raw)
		if err != nil {
			t.Errorf("MustHexDecode %s", err)
			return nil
		}

		if s := len(data); s != size {
			t.Errorf("MustHexDecode size want %d but got %d", size, s)
			return nil
		}
		return data
	}
}

func TestNewXPrv(t *testing.T) {
	HexDecode := MustHexDecode(t)

	const testKey = "80660d61ec16a6ca93e05e1738082dff22a422f00e95a5dfa9d91a74fab4725a017255017df26d8ff29dbe315c838cd3837a311e611a9dd1c8c8a82a21ad2ec38754df6b746c0366e9fc73ce282e824038a3c001798af7fbb632ff6504555813"
	type args struct {
		seed []byte
	}
	tests := []struct {
		name string
		args args
		want XPrv
	}{
		{
			name: "valid seed",
			args: args{HexDecode(TestSeed, 64)},
			want: XPrv{HexDecode(testKey, 96)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewRootXPrv(tt.args.seed); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewXPrv() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestXPrv_String(t *testing.T) {
	HexDecode := MustHexDecode(t)

	type fields struct {
		key []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name:   "case 1",
			fields: fields{HexDecode(TestKey, 96)},
			want:   TestKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := XPrv{
				xprv: tt.fields.key,
			}
			if got := x.String(); got != tt.want {
				t.Errorf("XPrv.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestXPrv_Derive(t *testing.T) {
	HexDecode := MustHexDecode(t)

	type fields struct {
		key []byte
	}
	type args struct {
		index uint32
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   XPrv
	}{
		{
			name:   "soft",
			fields: fields{HexDecode(TestKey, 96)},
			args:   args{1},
			want:   XPrv{HexDecode("c02210e035578f15b48ad54d90d59a88352d3160f36d0458b3e1583302b5725a435748df6415038a8fe35c46779fea8554b747a9093a8f784cf079144fc00317594479b4ed8519d7c4378a9d7c782029f61d4ec107900b8dfb70c7d609ad5a16", 96)},
		},
		{
			name:   "soft",
			fields: fields{HexDecode(TestKey, 96)},
			args:   args{HardIndex},
			want:   XPrv{HexDecode("20eeb6d38c858686b848a2f380d52d04ed1d87dba5f01f5cabe6b86e00b5725aa9f78d23bc28ed03d356d31c3842eec69609e6b207b438e0e804ab00316eec5f1af28001980d11f2b6247ad874b217f4fd50f6b785223b658fb079ce5cdd82b2", 96)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := XPrv{
				xprv: tt.fields.key,
			}
			if got := x.Derive(tt.args.index); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("XPrv.Derive() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestXPrv_PublicKey(t *testing.T) {
	HexDecode := MustHexDecode(t)

	type fields struct {
		key []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   ed25519.PublicKey
	}{
		{
			name:   "case 1",
			fields: fields{HexDecode(TestKey, 96)},
			want:   ed25519.PublicKey(HexDecode("0b72d9a9118f4f2d59f18f5e54202461a5132a53088af94560de51dca505eea3", 32)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := XPrv{
				xprv: tt.fields.key,
			}
			if got := x.PublicKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("XPrv.PublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestXPrv_Derive_multi(t *testing.T) {
	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Error(err)
		return
	}
	xprv := NewRootXPrv(root)
	for i := uint32(0); i < 100; i++ {
		a := xprv.Derive(i).XPub().PublicKey()
		b := xprv.XPub().Derive(i).PublicKey()
		if !bytes.Equal(a, b) {
			t.Errorf("TestXPrv_Derive_multi(%d) failed", i)
		}
	}
}
