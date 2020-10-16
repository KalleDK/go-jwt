package rsa

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"

	"github.com/KalleDK/go-jwt/jwt"
)

var b64 = base64.RawURLEncoding

func init() {
	jwt.RegisterKeyType(jwt.RSA, keyparser{})
}

func verify(base basekey, key *rsa.PublicKey, a jwt.Algorithm, signed, signature []byte) (kidUsed string, err error) {
	if a != base.alg {
		return "", errors.New("invalid algorithm")
	}

	jwa := base.alg.New()
	jwa.Write(signed)

	return base.KeyID(), jwa.Verify(signature, key)
}

func sign(base basekey, key *rsa.PrivateKey, rand io.Reader, unsigned []byte) (signature []byte, err error) {
	jwa := base.alg.New()
	jwa.Write(unsigned)
	return jwa.Sign(rand, key)
}

type basekey struct {
	kid string
	alg jwt.Algorithm
}

func (k basekey) Algorithm() jwt.Algorithm { return k.alg }
func (k basekey) KeyID() string            { return k.kid }
func (k basekey) Available() bool          { return k.alg.Available() }

type privateKeyJSON struct {
	KeyID    string        `json:"kid,omitempty"`
	Algoritm jwt.Algorithm `json:"alg"`
	E        *normalInt    `json:"e"`
	N        *bigInt       `json:"n"`
	D        *bigInt       `json:"d"`
	Q        *bigInt       `json:"q"`
	P        *bigInt       `json:"p"`
	DP       *bigInt       `json:"dp"`
	DQ       *bigInt       `json:"dq"`
	QI       *bigInt       `json:"qi"`
}

type privateKey struct {
	basekey
	key *rsa.PrivateKey
}

func (k privateKey) ValidateKey() error { return k.alg.ValidateSignerKey(k.key) }

func (k privateKey) Verify(a jwt.Algorithm, kidSuggest string, signed, signature []byte) (kidUsed string, err error) {
	return verify(k.basekey, &k.key.PublicKey, a, signed, signature)
}

func (k privateKey) Sign(rand io.Reader, unsigned []byte) (signature []byte, err error) {
	return sign(k.basekey, k.key, rand, unsigned)
}

func (k *privateKey) UnmarshalJSON(data []byte) (err error) {
	dec := json.NewDecoder(nil)
	t, _ := dec.Token()

	var keyJSON privateKeyJSON
	if err := json.Unmarshal(data, &keyJSON); err != nil {
		return err
	}

	*k = privateKey{
		basekey: basekey{
			kid: keyJSON.KeyID,
			alg: keyJSON.Algoritm,
		},
		key: &rsa.PrivateKey{
			D:      keyJSON.D.toBase(),
			Primes: []*big.Int{keyJSON.P.toBase(), keyJSON.Q.toBase()},
			Precomputed: rsa.PrecomputedValues{
				Dp:        keyJSON.DP.toBase(),
				Dq:        keyJSON.DQ.toBase(),
				Qinv:      keyJSON.QI.toBase(),
				CRTValues: []rsa.CRTValue{},
			},
			PublicKey: rsa.PublicKey{
				E: keyJSON.E.toBase(),
				N: keyJSON.N.toBase(),
			},
		},
	}

	return k.key.Validate()
}

type publicKey struct {
	basekey
	key *rsa.PublicKey
}

func (k publicKey) ValidateKey() error { return k.alg.ValidateVerifierKey(k.key) }

func (k publicKey) Verify(a jwt.Algorithm, kidSuggest string, signed, signature []byte) (kidUsed string, err error) {
	return verify(k.basekey, k.key, a, signed, signature)
}

// #region Int types

type normalInt int

func (i normalInt) toBase() int { return (int)(i) }

func (i *normalInt) UnmarshalText(text []byte) error {
	// TODO better conversion
	var v bigInt
	if err := v.UnmarshalText(text); err != nil {
		return err
	}
	if !v.toBase().IsInt64() {
		return errors.New("is not valid")
	}
	*i = normalInt(int(v.toBase().Int64()))
	return nil
}

func (i *normalInt) MarshalText() (text []byte, err error) {
	// TODO better conversion
	var v bigInt
	v.toBase().SetInt64(int64(*i))
	return v.MarshalText()
}

type bigInt big.Int

func (i *bigInt) toBase() *big.Int { return (*big.Int)(i) }

func (i *bigInt) Bytes() []byte { return i.toBase().Bytes() }

func (i *bigInt) SetBytes(b []byte) *bigInt { return (*bigInt)(i.toBase().SetBytes(b)) }

func (i *bigInt) UnmarshalText(text []byte) error {
	b := make([]byte, b64.DecodedLen(len(text)))
	n, err := b64.Decode(b, text)
	if err != nil {
		return err
	}
	i.SetBytes(b[:n])
	return nil
}

func (i *bigInt) MarshalText() (text []byte, err error) {
	str := base64.RawURLEncoding.EncodeToString(i.Bytes())
	return []byte(str), nil
}

// #endregion

type verifier struct {
	KeyID    string        `json:"kid,omitempty"`
	Algoritm jwt.Algorithm `json:"alg"`
	E        *normalInt    `json:"e"`
	N        *bigInt       `json:"n"`
}

func (v verifier) toKey() (publicKey, error) {
	return publicKey{
		basekey: basekey{
			kid: v.KeyID,
			alg: v.Algoritm,
		},
		key: &rsa.PublicKey{
			E: v.E.toBase(),
			N: v.N.toBase(),
		},
	}, nil
}

type keyparser struct {
}

func (p keyparser) ParseVerifier(kid string, b []byte) (jwt.Verifier, error) {

	var params verifier
	if err := json.Unmarshal(b, &params); err != nil {
		return nil, err
	}

	key, err := params.toKey()
	if !key.Available() {
		return nil, errors.New("algoritm not available")
	}

	return key, err
}

func (kp keyparser) ParseSigner(kid string, b []byte) (jwt.Signer, error) {
	var key privateKey
	if err := json.Unmarshal(b, &key); err != nil {
		return nil, err
	}

	return key, nil
}
