package test

import (
	"reflect"
	"testing"

	"github.com/KalleDK/go-jwt/jwk"
	"github.com/KalleDK/go-jwt/jwt"
)

type JWKFixture struct {
	KeyID      string
	Algorithm  jwt.Algorithm
	PrivateKey []byte
	PublicKey  []byte
	Payload    []byte
	Signature  []byte
}

type KeyTest struct {
	Name string
	Args JWKFixture
}

func SignerTest(t *testing.T, args JWKFixture) {

	{
		signer, err := jwk.ParseSigner(args.PrivateKey)
		if err != nil {
			t.Errorf("ParseSigner() error = %v", err)
			return
		}

		gotKeyID := signer.KeyID()
		if !reflect.DeepEqual(gotKeyID, args.KeyID) {
			t.Errorf("ParseSigner() KeyID = %v, want %v", gotKeyID, args.KeyID)
		}

		gotAlgorithm := signer.Algorithm()
		if !reflect.DeepEqual(gotAlgorithm, args.Algorithm) {
			t.Errorf("ParseSigner() Algorithm = %v, want %v", gotAlgorithm.String(), args.Algorithm.String())
		}

		gotSignature, err := signer.Sign(NoopReader{}, args.Payload)
		if err != nil {
			t.Errorf("ParseSigner() Sign error = %v", err)
		}

		if !reflect.DeepEqual(gotSignature, args.Signature) {
			t.Errorf("ParseSigner() Signature = %#v, want %#v", string(gotSignature), string(args.Signature))
		}
	}
	{
		verifier, err := jwk.ParseVerifier(args.PublicKey)
		if err != nil {
			t.Errorf("ParseVerifier() error = %v", err)
			return
		}

		gotKeyID := verifier.KeyID()
		if !reflect.DeepEqual(gotKeyID, args.KeyID) {
			t.Errorf("ParseVerifier() KeyID = %v, want %v", gotKeyID, args.KeyID)
		}

		gotAlgorithm := verifier.Algorithm()
		if !reflect.DeepEqual(gotAlgorithm, args.Algorithm) {
			t.Errorf("ParseVerifier() Algorithm = %v, want %v", gotAlgorithm.String(), args.Algorithm.String())
		}

		gotKidUsed, err := verifier.Verify(args.Algorithm, args.KeyID, args.Payload, args.Signature)
		if err != nil {
			t.Errorf("ParseVerifier() error = %v", err)
		}

		if !reflect.DeepEqual(gotKidUsed, args.KeyID) {
			t.Errorf("ParseVerifier() = %s, want %s", gotKidUsed, args.KeyID)
		}
	}

}

type NoopReader struct{}

func (r NoopReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

func RunKeyTests(t *testing.T, tests []KeyTest) {
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			SignerTest(t, tt.Args)
		})
	}
}
