package jwk

import (
	"encoding/json"
	"errors"

	"github.com/KalleDK/go-jwt/jwt"
)

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

	keytype := GetKeyType(header.KeyType)

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

	keytype := GetKeyType(header.KeyType)

	return keytype.ParseVerifier(header.KeyID, b)
}
