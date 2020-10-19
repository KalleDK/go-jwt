package base

import (
	"encoding/json"
	"errors"

	"github.com/KalleDK/go-jwt/jwt"
)

type jwkheader struct {
	KeyType   jwt.KeyType   `json:"kty"`
	KeyID     string        `json:"kid"`
	KeyOps    []string      `json:"key_ops"`
	Algorithm jwt.Algorithm `json:"alg"`
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

	return header.KeyType.ParseSigner(header.KeyID, b)
}

func ParseVerifier(b []byte) (verifier jwt.Verifier, err error) {
	var header jwkheader
	if err = json.Unmarshal(b, &header); err != nil {
		return nil, err
	}

	if !isin("verify", header.KeyOps) {
		return nil, errors.New("jwk is not a verifier")
	}

	return header.KeyType.ParseVerifier(header.KeyID, b)
}

type JWKBase struct {
	Kid string
	Alg jwt.Algorithm
}

func (k JWKBase) Algorithm() jwt.Algorithm { return k.Alg }
func (k JWKBase) KeyID() string            { return k.Kid }
func (k JWKBase) Available() bool          { return k.Alg.Available() }
