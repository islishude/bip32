package bip32

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"testing"
)

const TestSeed = "cdc36eaa638a07b5881b62bbb8ea8c2819e2b50e0cf51de14489c6d2dc29cb7914828443112319ee3ee64c82cda51c0f0df3c9550994bf70b4383d234e6e8ffd"
const TestKey = "80660d61ec16a6ca93e05e1738082dff22a422f00e95a5dfa9d91a74fab4725a017255017df26d8ff29dbe315c838cd3837a311e611a9dd1c8c8a82a21ad2ec314828443112319ee3ee64c82cda51c0f0df3c9550994bf70b4383d234e6e8ffd"
const RootKey = "48986b99067b64edbb1d7ec030efb517ac10dea8cc8574dafb5e7abeb0a83e538a3688325877ce63bd506e97957c0fd9f26d5d8fca4e98104ca6eea38a6d9f561ef8af814f221a594724932d5af74820c7062647920d448ddbe2a9c6200c983e"

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
		want   []byte
	}{
		{
			name:   "case 1",
			fields: fields{HexDecode(TestKey, 96)},
			want:   HexDecode("0b72d9a9118f4f2d59f18f5e54202461a5132a53088af94560de51dca505eea3", 32),
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

func TestXPrv_Sign(t *testing.T) {
	root, _ := hex.DecodeString(RootKey)
	xprv, err := NewXPrv(root)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello,world")
	want, _ := hex.DecodeString("31f9a9cab1b62570cb4e217eed317625a47780fcbc73405da70b84416018810360e67e4d31915fae4b25ed82a95b7600244f94a475adb0ae7644e4adaba60b06")
	if got := xprv.Sign(msg); !bytes.Equal(got, want) || !xprv.Verify(msg, got) {
		t.Errorf("XPrv.Sign: verify failed")
	}
}

func TestXPrv_Verify(t *testing.T) {
	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Errorf("XPrv.Verify: get random %s", err)
		return
	}
	xprv, msg := NewRootXPrv(root), []byte("trMZ7Zz7O5uLw6fb7BMmkQ==")
	if sig := xprv.Sign(msg); !xprv.Verify(msg, sig) {
		t.Error("verify failed")
	}
}

func TestNewXPrv(t *testing.T) {
	type args struct {
		raw []byte
	}
	tests := []struct {
		name    string
		args    args
		want    XPrv
		wantErr bool
	}{
		{
			name:    "invalid size",
			args:    args{},
			wantErr: true,
		},
		{
			name: "invalid first byte",
			args: args{raw: func() []byte {
				res := make([]byte, XPrvSize)
				res[0] = 1
				return res
			}()},
			wantErr: true,
		},
		{
			name: "invalid last byte",
			args: args{raw: func() []byte {
				res := make([]byte, XPrvSize)
				res[0] &= 0b1111_1000
				return res
			}()},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{raw: func() []byte {
				raw, _ := hex.DecodeString(RootKey)
				return raw
			}()},
			want: XPrv{xprv: func() []byte {
				raw, _ := hex.DecodeString(RootKey)
				return raw
			}()},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewXPrv(tt.args.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewXPrv() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewXPrv() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestXPrv_Bytes(t *testing.T) {
	root, _ := hex.DecodeString(RootKey)
	xprv, err := NewXPrv(root)
	if err != nil {
		t.Errorf("XPrv.Bytes: NewXPrv: %s", err)
		return
	}
	got := xprv.Bytes()
	if !bytes.Equal(got, root) {
		t.Errorf("XPrv.Bytes: not equal")
		return
	}

	if root[0] = 0x01; xprv.xprv[0] == 0x1 {
		t.Errorf("XPrv.Bytes: seed changes and internal bytes also modified")
		return
	}

	if got[0] = 0x01; xprv.xprv[0] == got[0] {
		t.Errorf("XPrv.Bytes: seed changes and internal bytes also modified")
		return
	}
}

func TestXPrv_DeriveHard(t *testing.T) {
	type fields struct {
		xprv []byte
	}
	type args struct {
		index uint32
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    XPrv
		wantErr bool
	}{
		{
			name:    "invalid",
			fields:  fields{},
			args:    args{index: HardIndex + 1},
			wantErr: true,
		},
		{
			name: "invalid",
			fields: fields{xprv: func() []byte {
				root, _ := hex.DecodeString(RootKey)
				return root
			}()},
			args: args{index: 1},
			want: func() XPrv {
				root, _ := hex.DecodeString("400735aee08188412ac794bdd9c21772812329890934a0ea9f69687fb4a83e53ae5230f575a2615a4ac24789f0cedd169a1bae0ca08f5064288f07559f68515a9bf334ab4911e2eed049c36b3b921a73c56132d6bf3134f9c5471d5654565607")
				xprv, _ := NewXPrv(root)
				return xprv
			}(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if err := recover(); err == nil && tt.wantErr {
					t.Error("XPrv.DeriveHard(): want error")
				}
			}()
			x := XPrv{
				xprv: tt.fields.xprv,
			}
			if got := x.DeriveHard(tt.args.index); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("XPrv.DeriveHard() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestXPrv_ChainCode(t *testing.T) {
	root, _ := hex.DecodeString(RootKey)
	xprv, err := NewXPrv(root)
	if err != nil {
		t.Errorf("XPrv.ChainCode: NewXPrv: %s", err)
		return
	}

	want, err := hex.DecodeString("1ef8af814f221a594724932d5af74820c7062647920d448ddbe2a9c6200c983e")
	if err != nil {
		t.Errorf("XPrv.ChainCode: NewXPrv: %s", err)
		return
	}

	got := xprv.ChainCode()
	if !bytes.Equal(got, want) {
		t.Errorf("XPrv.ChainCode: not equal")
		return
	}

	if got[0] = 0x01; xprv.xprv[64] == got[0] {
		t.Errorf("XPrv.ChainCode: got changes and internal bytes also modified")
		return
	}
}
