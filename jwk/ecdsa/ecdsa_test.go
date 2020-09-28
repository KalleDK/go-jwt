package ecdsa

import (
	"reflect"
	"testing"

	_ "crypto/sha256"

	_ "github.com/KalleDK/go-jwt/jwa/ecdsa"

	"github.com/KalleDK/go-jwt/jwk"
	"github.com/KalleDK/go-jwt/jwt"
)

type norand struct{}

func (r norand) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

func TestParseSigner(t *testing.T) {
	type args struct {
		data []byte
		b    []byte
	}
	tests := []struct {
		name          string
		args          args
		wantSignature []byte
		wantAlgorithm jwt.Algorithm
		wantKeyID     string
		wantErr       bool
	}{
		{
			name: "basic fail",
			args: args{
				b: []byte(`{"kty":"EC",
				"crv": "P-256",
				"key_ops": ["sign"],
				"d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
				"kid":"key01-2020-09-23"
			   }`),
				data: []byte("flaf"),
			},
			wantKeyID:     "key01-2020-09-23",
			wantSignature: []byte("'b@R\xe8\a\xc0\x91Fh\x95\x98\xb8\xce$\x8b\x14.bQ\x90G\xfd\x80\aN$4a\xa6\u007f9\xcf`S\x97иj5DE)\x84,\x92\x8d\xf1\x849\xaa\xe0e\xe97\x81ҽY\xf3T\x860\x8f"),
			wantAlgorithm: jwt.ES256,
			wantErr:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSigner, err := jwk.ParseSigner(tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			gotKeyID := gotSigner.KeyID()
			if !reflect.DeepEqual(gotKeyID, tt.wantKeyID) {
				t.Errorf("ParseSigner() = %v, want %v", gotKeyID, tt.wantKeyID)
			}
			gotAlgorithm := gotSigner.Algorithm()
			if !reflect.DeepEqual(gotAlgorithm, tt.wantAlgorithm) {
				t.Errorf("ParseSigner() = %v, want %v", gotAlgorithm.String(), tt.wantAlgorithm.String())
			}
			gotSignature, err := gotSigner.Sign(norand{}, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSigner() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(gotSignature, tt.wantSignature) {
				t.Errorf("ParseSigner() = %+#v, want %#v", string(gotSignature), string(tt.wantSignature))
			}
		})
	}
}

func TestParseVerifier(t *testing.T) {
	type args struct {
		alg       jwt.Algorithm
		kid       string
		data      []byte
		b         []byte
		signature []byte
	}
	tests := []struct {
		name             string
		args             args
		wantVerification bool
		wantAlgorithm    jwt.Algorithm
		wantKeyID        string
		wantErr          bool
		wantKidUsed      string
	}{
		{
			name: "basic fail",
			args: args{
				b: []byte(`{
					"kid": "key01-2020-09-23",
					"kty": "EC",
					"key_ops": ["verify"],
					"crv": "P-256",
					"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
					"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
				  }`),
				alg:       jwt.ES256,
				kid:       "key01-2020-09-23",
				data:      []byte("flaf"),
				signature: []byte("'b@R\xe8\a\xc0\x91Fh\x95\x98\xb8\xce$\x8b\x14.bQ\x90G\xfd\x80\aN$4a\xa6\u007f9\xcf`S\x97иj5DE)\x84,\x92\x8d\xf1\x849\xaa\xe0e\xe97\x81ҽY\xf3T\x860\x8f"),
			},
			wantKidUsed:      "key01-2020-09-23",
			wantVerification: true,
			wantKeyID:        "key01-2020-09-23",
			wantAlgorithm:    jwt.ES256,
			wantErr:          false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVerifier, err := jwk.ParseVerifier(tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseVerifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			gotKeyID := gotVerifier.KeyID()
			if !reflect.DeepEqual(gotKeyID, tt.wantKeyID) {
				t.Errorf("ParseVerifier() = %v, want %v", gotKeyID, tt.wantKeyID)
			}
			gotAlgorithm := gotVerifier.Algorithm()
			if !reflect.DeepEqual(gotAlgorithm, tt.wantAlgorithm) {
				t.Errorf("ParseVerifier() = %v, want %v", gotAlgorithm.String(), tt.wantAlgorithm.String())
			}

			gotKidUsed, err := gotVerifier.Verify(tt.args.alg, tt.args.kid, tt.args.data, tt.args.signature)
			if (err != nil) == tt.wantVerification {
				t.Errorf("ParseVerifier() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(gotKidUsed, tt.wantKidUsed) {
				t.Errorf("ParseVerifier() = %+#v, want %#v", string(gotKidUsed), string(tt.wantKidUsed))
			}
		})
	}
}
