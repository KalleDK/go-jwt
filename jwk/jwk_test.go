package jwk

import (
	"reflect"
	"testing"

	"github.com/KalleDK/go-jwt/jwt"
)

func DoStuff() {

}

func TestKeyType_ParseSigner(t *testing.T) {
	type args struct {
		kid string
		b   []byte
	}
	tests := []struct {
		name    string
		k       jwt.KeyType
		args    args
		want    jwt.Signer
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.k.ParseSigner(tt.args.kid, tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("KeyType.ParseSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeyType.ParseSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSigner(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name       string
		args       args
		wantSigner jwt.Signer
		wantErr    bool
	}{
		{
			name: "basic fail",
			args: args{
				b: []byte(`{"kty":"EC",
				"crv":"P-256",
				"key_ops": ["sign"],
				"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
				"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
				"kid":"Public key used in JWS spec Appendix A.3 example"
			   }`),
			},
			wantSigner: nil,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSigner, err := ParseSigner(tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSigner, tt.wantSigner) {
				t.Errorf("ParseSigner() = %v, want %v", gotSigner, tt.wantSigner)
			}
		})
	}
}
