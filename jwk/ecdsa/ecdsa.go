package ecdsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/KalleDK/go-jwt/jwt"
)

func init() {
	jwt.RegisterKeyType(jwt.EC, keyparser{})
}

func getCurveAndAlg(s string) (elliptic.Curve, jwt.Algorithm, error) {
	switch s {
	case "P-256":
		return elliptic.P256(), jwt.ES256, nil
	default:
		return nil, 0, errors.New("invalid curve")
	}
}

type Signer struct {
	hash    crypto.Hash
	key     *ecdsa.PrivateKey
	keySize uint8
	alg     jwt.Algorithm
	kid     string
}

type signerJSON struct {
	Curve string `json:"crv"`
	D     string `json:"d"`
}

type verifierJSON struct {
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
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

func (p keyparser) ParseVerifier(kid string, b []byte) (jwt.Verifier, error) {
	var params verifierJSON
	if err := json.Unmarshal(b, &params); err != nil {
		return nil, err
	}

	c, alg, err := getCurveAndAlg(params.Curve)
	if err != nil {
		return nil, err
	}

	x := strtobig(params.X)
	if x == nil {
		return nil, errors.New("invalid X")
	}

	y := strtobig(params.Y)
	if y == nil {
		return nil, errors.New("invalid Y")
	}

	key := &ecdsa.PublicKey{
		Curve: c,
		Y:     y,
		X:     x,
	}

	return alg.NewVerifier(kid, key), nil
}

func (p keyparser) ParseSigner(kid string, b []byte) (jwt.Signer, error) {
	var params signerJSON
	if err := json.Unmarshal(b, &params); err != nil {
		return nil, err
	}

	c, alg, err := getCurveAndAlg(params.Curve)
	if err != nil {
		return nil, err
	}

	d := strtobig(params.D)
	if d == nil {
		return nil, errors.New("invalid D")
	}

	x, y := c.ScalarBaseMult(d.Bytes())

	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: c,
			Y:     y,
			X:     x,
		},
		D: d,
	}

	return alg.NewSigner(kid, key), nil
}
