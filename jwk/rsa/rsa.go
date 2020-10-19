package rsa

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"

	"github.com/KalleDK/go-jwt/jwk"
	"github.com/KalleDK/go-jwt/jwk/math"
	"github.com/KalleDK/go-jwt/jwt"
)

func init() {
	jwk.RegisterKeyParser(jwk.RSA, keyparser{})
}

func verify(base jwk.KeyBase, key *rsa.PublicKey, a jwt.Algorithm, signed, signature []byte) (kidUsed string, err error) {
	if a != base.Alg {
		return "", errors.New("invalid algorithm")
	}

	jwa := base.Alg.New()
	jwa.Write(signed)

	return base.KeyID(), jwa.Verify(signature, key)
}

func sign(base jwk.KeyBase, key *rsa.PrivateKey, rand io.Reader, unsigned []byte) (signature []byte, err error) {
	jwa := base.Alg.New()
	jwa.Write(unsigned)
	return jwa.Sign(rand, key)
}

// #region PrivateKey

type privateKeyJSON struct {
	KeyID    string          `json:"kid,omitempty"`
	Algoritm jwt.Algorithm   `json:"alg"`
	E        *math.NormalInt `json:"e"`
	N        *math.BigInt    `json:"n"`
	D        *math.BigInt    `json:"d"`
	Q        *math.BigInt    `json:"q"`
	P        *math.BigInt    `json:"p"`
	DP       *math.BigInt    `json:"dp"`
	DQ       *math.BigInt    `json:"dq"`
	QI       *math.BigInt    `json:"qi"`
}

type privateKey struct {
	jwk.KeyBase
	key *rsa.PrivateKey
}

func (k privateKey) Validate() error { return k.KeyBase.Alg.ValidateSignerKey(k.key) }

func (k privateKey) Verify(a jwt.Algorithm, kidSuggest string, signed, signature []byte) (kidUsed string, err error) {
	return verify(k.KeyBase, &k.key.PublicKey, a, signed, signature)
}

func (k privateKey) Sign(rand io.Reader, unsigned []byte) (signature []byte, err error) {
	return sign(k.KeyBase, k.key, rand, unsigned)
}

func (k *privateKey) UnmarshalJSON(data []byte) (err error) {

	var keyJSON privateKeyJSON
	if err := json.Unmarshal(data, &keyJSON); err != nil {
		return err
	}

	*k = privateKey{
		KeyBase: jwk.KeyBase{
			Kid: keyJSON.KeyID,
			Alg: keyJSON.Algoritm,
		},
		key: &rsa.PrivateKey{
			D:      keyJSON.D.ToBase(),
			Primes: math.BigList{keyJSON.P.ToBase(), keyJSON.Q.ToBase()}.ToBase(),
			Precomputed: rsa.PrecomputedValues{
				Dp:        keyJSON.DP.ToBase(),
				Dq:        keyJSON.DQ.ToBase(),
				Qinv:      keyJSON.QI.ToBase(),
				CRTValues: []rsa.CRTValue{},
			},
			PublicKey: rsa.PublicKey{
				E: keyJSON.E.ToBase(),
				N: keyJSON.N.ToBase(),
			},
		},
	}

	return nil
}

// #endregion

// #region PublicKey

type publicKeyJSON struct {
	KeyID    string          `json:"kid,omitempty"`
	Algoritm jwt.Algorithm   `json:"alg"`
	E        *math.NormalInt `json:"e"`
	N        *math.BigInt    `json:"n"`
}

type publicKey struct {
	jwk.KeyBase
	key *rsa.PublicKey
}

func (k publicKey) ValidateKey() error { return k.KeyBase.Alg.ValidateVerifierKey(k.key) }

func (k publicKey) Verify(a jwt.Algorithm, kidSuggest string, signed, signature []byte) (kidUsed string, err error) {
	return verify(k.KeyBase, k.key, a, signed, signature)
}

func (k *publicKey) UnmarshalJSON(data []byte) (err error) {
	var keyJSON publicKeyJSON
	if err := json.Unmarshal(data, &keyJSON); err != nil {
		return err
	}

	*k = publicKey{
		KeyBase: jwk.KeyBase{
			Kid: keyJSON.KeyID,
			Alg: keyJSON.Algoritm,
		},
		key: &rsa.PublicKey{
			E: keyJSON.E.ToBase(),
			N: keyJSON.N.ToBase(),
		},
	}

	return nil
}

// #endregion

// #region KeyParser

type keyparser struct{}

func (kp keyparser) ParseVerifier(base jwk.KeyBase, b []byte) (jwt.Verifier, error) {
	var key publicKey
	if err := json.Unmarshal(b, &key); err != nil {
		return nil, err
	}

	key.KeyBase = base

	return key, nil
}

func (kp keyparser) ParseSigner(base jwk.KeyBase, b []byte) (jwt.Signer, error) {
	var key privateKey
	if err := json.Unmarshal(b, &key); err != nil {
		return nil, err
	}

	key.KeyBase = base

	return key, nil
}

func (kp keyparser) ParseDecryptor(base jwk.KeyBase, b []byte) (jwt.Decryptor, error) {
	return nil, nil
}

func (kp keyparser) ParseEncryptor(base jwk.KeyBase, b []byte) (jwt.Encryptor, error) {
	return nil, nil
}

// #endregion
