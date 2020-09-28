package rsa

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/KalleDK/go-jwt/jwk"
	"github.com/KalleDK/go-jwt/jwt"
)

func init() {
	jwk.RegisterKeyType(jwk.RSA, keyparser{})
}

type verifier struct {
	Algoritm string `json:"alg"`
	E        string `json:"e"`
	N        string `json:"n"`
}

type signer struct {
	Algoritm string `json:"alg"`
	E        string `json:"e"`
	N        string `json:"n"`
	D        string `json:"d"`
	Q        string `json:"q"`
	P        string `json:"p"`
	DP       string `json:"dp"`
	DQ       string `json:"dq"`
	QI       string `json:"qi"`
}

type keyparser struct {
}

func strtobig(s string) (i *big.Int) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	i = &big.Int{}
	i.SetBytes(b)
	return i
}

const UintSize = 32 << (^uint(0) >> 32 & 1) // 32 or 64
const MaxInt = 1<<(UintSize-1) - 1

func (p keyparser) ParseVerifier(kid string, b []byte) (jwt.Verifier, error) {
	var params verifier
	if err := json.Unmarshal(b, &params); err != nil {
		return nil, err
	}

	eb := strtobig(params.E)
	if eb == nil {
		return nil, errors.New("invalid E")
	}
	if !eb.IsInt64() {
		return nil, errors.New("invalid E")
	}
	ei := eb.Int64()
	if ei > MaxInt {
		return nil, errors.New("invalid E")
	}
	e := int(ei)

	n := strtobig(params.N)
	if n == nil {
		return nil, errors.New("invalid N")
	}

	key := &rsa.PublicKey{
		E: e,
		N: n,
	}

	alg := jwt.GetAlgorithm(params.Algoritm)

	return alg.NewVerifier(kid, key), nil
}

func (kp keyparser) ParseSigner(kid string, b []byte) (jwt.Signer, error) {
	var params signer
	if err := json.Unmarshal(b, &params); err != nil {
		return nil, err
	}

	e := strtobig(params.E)
	if e == nil {
		return nil, errors.New("invalid E")
	}

	n := strtobig(params.N)
	if n == nil {
		return nil, errors.New("invalid N")
	}

	d := strtobig(params.D)
	if d == nil {
		return nil, errors.New("invalid D")
	}

	q := strtobig(params.Q)
	if q == nil {
		return nil, errors.New("invalid Q")
	}

	p := strtobig(params.P)
	if p == nil {
		return nil, errors.New("invalid P")
	}

	dq := strtobig(params.DQ)
	if dq == nil {
		return nil, errors.New("invalid DQ")
	}

	dp := strtobig(params.DP)
	if dp == nil {
		return nil, errors.New("invalid DP")
	}

	qi := strtobig(params.QI)
	if qi == nil {
		return nil, errors.New("invalid QI")
	}

	key := &rsa.PrivateKey{
		D:      d,
		Primes: []*big.Int{p, q},
		Precomputed: rsa.PrecomputedValues{
			Dp:        dp,
			Dq:        dq,
			Qinv:      qi,
			CRTValues: []rsa.CRTValue{},
		},
		PublicKey: rsa.PublicKey{
			E: int(e.Int64()),
			N: n,
		},
	}

	err := key.Validate()
	if err != nil {
		return nil, err
	}

	alg := jwt.GetAlgorithm(params.Algoritm)

	return alg.NewSigner(kid, key), nil
}
