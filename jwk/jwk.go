package jwk

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/KalleDK/go-jwt/jwa"
	"github.com/KalleDK/go-jwt/jwt"
)

type signer struct {
	signer jwa.Signer
	alg    jwt.Algorithm
	kid    string
}

func (s signer) Sign(rand io.Reader, unsigned []byte) (signature []byte, err error) {
	return s.signer.Sign(rand, unsigned)
}

func (s signer) Algorithm() jwt.Algorithm {
	return s.alg
}

func (s signer) KeyID() string {
	return s.kid
}

func (s signer) MarshalJSON() ([]byte, error) {
	return nil, nil
}

type jwkheader struct {
	KeyType string   `json:"kty"`
	KeyID   string   `json:"kid"`
	KeyOps  []string `json:"key_ops"`
}

func isin(k string, s []string) bool {
	for _, v := range s {
		if k == v {
			return true
		}
	}
	return false
}

func ParseSigner(b []byte) (signer jwt.Signer, err error) {
	var header jwkheader
	if err = json.Unmarshal(b, &header); err != nil {
		return nil, err
	}

	if !isin("sign", header.KeyOps) {
		return nil, errors.New("jwk is not a signer")
	}

	keytype := jwt.GetKeyType(header.KeyType)

	return keytype.ParseSigner(header.KeyID, b)
}

func ParseVerifier(b []byte) (verifier jwt.Verifier, err error) {
	var header jwkheader
	if err = json.Unmarshal(b, &header); err != nil {
		return nil, err
	}

	if !isin("verify", header.KeyOps) {
		return nil, errors.New("jwk is not a verifier")
	}

	keytype := jwt.GetKeyType(header.KeyType)

	return keytype.ParseVerifier(header.KeyID, b)
}
