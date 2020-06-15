package bip32

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestXPub_Derive(t *testing.T) {
	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Error(err)
		return
	}
	msg := sha256.Sum256(root)

	xprv := NewRootXPrv(root)
	for i := uint32(0); i < 100; i++ {

		a, b := xprv.Derive(i).XPub(), xprv.XPub().Derive(i)
		if !bytes.Equal(a.PublicKey(), b.PublicKey()) {
			t.Errorf("XPub.Derive failed: %d", i)
			continue
		}

		if sig := xprv.Derive(i).Sign(msg[:]); !b.Verify(msg[:], sig) || !a.Verify(msg[:], sig) {
			t.Errorf("XPub.Derive: verfiy failed: %d", i)
		}
	}
	defer func() {
		if err := recover(); err == nil {
			t.Error("shuold panic for hard derivation")
		}
	}()
	_ = xprv.XPub().Derive(HardIndex + 1)
}

func TestNewXPub(t *testing.T) {
	type args struct {
		raw []byte
	}
	tests := []struct {
		name    string
		args    args
		want    XPub
		wantErr bool
	}{
		{
			name:    "invalid size",
			args:    args{},
			wantErr: true,
		},
		{
			name:    "valid",
			args:    args{raw: make([]byte, XPubSize)},
			wantErr: false,
			want:    XPub{xpub: make([]byte, XPubSize)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if err := recover(); err == nil && tt.wantErr {
					t.Errorf("NewXPub: want error")
				}
			}()

			got := NewXPub(tt.args.raw)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewXPub() = %s, want %s", got, tt.want)
				return
			}

			if tt.wantErr {
				return
			}

			if want := hex.EncodeToString(tt.args.raw); got.String() != want {
				t.Errorf("NewXPub() = %s, want %s", got, want)
				return
			}

			if want := tt.args.raw; !bytes.Equal(want, got.Bytes()) {
				t.Errorf("NewXPub() = %x, want %x", got.Bytes(), want)
				return
			}

			b := got.Bytes()
			if b[0] = 0x01; got.xpub[0] == b[0] {
				t.Errorf("XPub.Bytes(): returns changes and internal also modified")
				return
			}

			if pk := got.PublicKey(); !bytes.Equal(make([]byte, 32), pk) {
				t.Errorf("XPub.PublicKey(): not equal")
				return
			}

			if pk := got.ChainCode(); !bytes.Equal(make([]byte, 32), pk) {
				t.Errorf("XPub.ChainCode(): not equal")
				return
			}
		})
	}
}
