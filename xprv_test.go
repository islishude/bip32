package bip32

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"reflect"
	"testing"
)

const TestSeed = "cdc36eaa638a07b5881b62bbb8ea8c2819e2b50e0cf51de14489c6d2dc29cb7914828443112319ee3ee64c82cda51c0f0df3c9550994bf70b4383d234e6e8ffd"
const TestKey = "80660d61ec16a6ca93e05e1738082dff22a422f00e95a5dfa9d91a74fab4725a017255017df26d8ff29dbe315c838cd3837a311e611a9dd1c8c8a82a21ad2ec314828443112319ee3ee64c82cda51c0f0df3c9550994bf70b4383d234e6e8ffd"
const RootKey = "48986b99067b64edbb1d7ec030efb517ac10dea8cc8574dafb5e7abeb0a83e538a3688325877ce63bd506e97957c0fd9f26d5d8fca4e98104ca6eea38a6d9f561ef8af814f221a594724932d5af74820c7062647920d448ddbe2a9c6200c983e"

const RustD1 = "f8a29231ee38d6c5bf715d5bac21c750577aa3798b22d79d65bf97d6fadea15adcd1ee1abdf78bd4be64731a12deb94d3671784112eb6f364b871851fd1c9a247384db9ad6003bbd08b3b1ddc0d07a597293ff85e961bf252b331262eddfad0d"
const RustD1H0 = "60d399da83ef80d8d4f8d223239efdc2b8fef387e1b5219137ffb4e8fbdea15adc9366b7d003af37c11396de9a83734e30e05e851efa32745c9cd7b42712c890608763770eddf77248ab652984b21b849760d1da74a6f5bd633ce41adceef07a"
const RustD1H0Signature = "90194d57cde4fdadd01eb7cf161780c277e129fc7135b97779a3268837e4cd2e9444b9bb91c0e84d23bba870df3c4bda91a110ef735638fa7a34ea2046d4be04"
const RustD1XPub = "86ae05cac74c490e097646814c76a9ac813c470afb6ce6429bf836b1bf5178787384db9ad6003bbd08b3b1ddc0d07a597293ff85e961bf252b331262eddfad0d"
const RustD1Soft0 = "e86a12ba078cdbdf044b488624a50b9f681086c5e7c005222c6fb69e02dfa15a28630505d5878465269ecf096b7ec855780e6e4aed06852676e8ced5bd66d1dad6324d15fe0641021a711f3ef93865b2e41c3cef61b155d57a988156074ce2a8"
const RustD1Soft0XPub = "10abaae2cf8f9c2d0cee0a880c0c3f6fcaaae9a1edff667fc567a117f6359c20d6324d15fe0641021a711f3ef93865b2e41c3cef61b155d57a988156074ce2a8"

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
			name:   "hard",
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

func TestXPrv_RustVectors(t *testing.T) {
	HexDecode := MustHexDecode(t)

	d1 := HexDecode(RustD1, XPrvSize)
	d1H0 := HexDecode(RustD1H0, XPrvSize)
	d1Soft0 := HexDecode(RustD1Soft0, XPrvSize)
	d1XPub := HexDecode(RustD1XPub, XPubSize)
	d1Soft0XPub := HexDecode(RustD1Soft0XPub, XPubSize)
	signature := HexDecode(RustD1H0Signature, ed25519.SignatureSize)
	msg := []byte("Hello World")

	xprv, err := NewXPrv(d1)
	if err != nil {
		t.Fatalf("NewXPrv(RustD1): %s", err)
	}
	if got := xprv.XPub().Bytes(); !bytes.Equal(got, d1XPub) {
		t.Fatalf("RustD1 XPub = %x, want %x", got, d1XPub)
	}

	hard0 := xprv.Derive(HardIndex)
	if got := hard0.Bytes(); !bytes.Equal(got, d1H0) {
		t.Fatalf("RustD1.Derive(HardIndex) = %x, want %x", got, d1H0)
	}
	if got := hard0.Sign(msg); !bytes.Equal(got, signature) {
		t.Fatalf("RustD1H0.Sign() = %x, want %x", got, signature)
	}
	if !hard0.Verify(msg, signature) {
		t.Fatal("RustD1H0.Verify(): expected signature to verify")
	}
	if !hard0.XPub().Verify(msg, signature) {
		t.Fatal("RustD1H0.XPub().Verify(): expected signature to verify")
	}

	soft0 := xprv.Derive(0)
	if got := soft0.Bytes(); !bytes.Equal(got, d1Soft0) {
		t.Fatalf("RustD1.Derive(0) = %x, want %x", got, d1Soft0)
	}
	if got := soft0.XPub().Bytes(); !bytes.Equal(got, d1Soft0XPub) {
		t.Fatalf("RustD1.Derive(0).XPub() = %x, want %x", got, d1Soft0XPub)
	}
	if got := xprv.XPub().Derive(0).Bytes(); !bytes.Equal(got, d1Soft0XPub) {
		t.Fatalf("RustD1.XPub().Derive(0) = %x, want %x", got, d1Soft0XPub)
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

func TestNewRootXPrvShortSeedPanics(t *testing.T) {
	defer func() {
		if err := recover(); err == nil {
			t.Error("NewRootXPrv: expected short seed to panic")
		}
	}()

	_ = NewRootXPrv(make([]byte, 31))
}

func TestNewRootXPrvStrict(t *testing.T) {
	if _, err := NewRootXPrvStrict(make([]byte, 31)); err == nil {
		t.Fatal("NewRootXPrvStrict: expected short seed error")
	}

	if _, err := NewRootXPrvStrict(make([]byte, 33)); err == nil {
		t.Fatal("NewRootXPrvStrict: expected long seed error")
	}

	invalidThirdBit, err := hex.DecodeString("0200000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if digest := sha512.Sum512(invalidThirdBit); digest[31]&0b0010_0000 == 0 {
		t.Fatal("NewRootXPrvStrict: test seed should have third highest bit set")
	}
	if _, err := NewRootXPrvStrict(invalidThirdBit); err == nil {
		t.Fatal("NewRootXPrvStrict: expected third highest bit error")
	}

	valid := make([]byte, 32)
	digest := sha512.Sum512(valid)
	if digest[31]&0b0010_0000 != 0 {
		t.Fatal("NewRootXPrvStrict: zero seed should be valid for this test")
	}

	digest[0] &= 0b1111_1000
	digest[31] &= 0b0101_1111
	digest[31] |= 0b0100_0000

	want := make([]byte, XPrvSize)
	copy(want[:64], digest[:])
	chaincode := sha256.Sum256(append([]byte{1}, valid...))
	copy(want[64:], chaincode[:])

	got, err := NewRootXPrvStrict(valid)
	if err != nil {
		t.Fatalf("NewRootXPrvStrict: unexpected error: %s", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("NewRootXPrvStrict() = %x, want %x", got.Bytes(), want)
	}
	if !bytes.Equal(got.Bytes(), NewRootXPrv(valid).Bytes()) {
		t.Error("NewRootXPrvStrict: valid strict seed should match legacy root output")
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
			name: "invalid highest bit",
			args: args{raw: func() []byte {
				res := make([]byte, XPrvSize)
				res[31] = 0b1100_0000
				return res
			}()},
			wantErr: true,
		},
		{
			name: "valid third highest bit set",
			args: args{raw: func() []byte {
				res := make([]byte, XPrvSize)
				res[31] = 0b0110_0000
				return res
			}()},
			want: XPrv{xprv: func() []byte {
				res := make([]byte, XPrvSize)
				res[31] = 0b0110_0000
				return res
			}()},
			wantErr: false,
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
			name:    "invalid boundary",
			fields:  fields{},
			args:    args{index: HardIndex},
			wantErr: true,
		},
		{
			name: "valid",
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

	root, _ := hex.DecodeString(RootKey)
	x := XPrv{xprv: root}
	if got, want := x.DeriveHard(HardIndex-1), x.Derive(^uint32(0)); !reflect.DeepEqual(got, want) {
		t.Errorf("XPrv.DeriveHard(HardIndex-1) = %v, want %v", got, want)
	}
}

func TestXPrv_DeriveStrict(t *testing.T) {
	root, _ := hex.DecodeString(RootKey)
	x, err := NewXPrv(root)
	if err != nil {
		t.Fatal(err)
	}

	for _, index := range []uint32{0, 1, HardIndex, HardIndex + 1} {
		got, err := x.DeriveStrict(index)
		if err != nil {
			t.Fatalf("XPrv.DeriveStrict(%d): unexpected error: %s", index, err)
		}
		if want := x.Derive(index); !reflect.DeepEqual(got, want) {
			t.Errorf("XPrv.DeriveStrict(%d) = %v, want %v", index, got, want)
		}
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
