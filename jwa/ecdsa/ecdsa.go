package ecdsa

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"hash"
	"io"
	"math/big"

	"github.com/KalleDK/go-jwt/jwa"
	"github.com/KalleDK/go-jwt/jwt"
)

// ErrMalformedSignature is returned when the signature length is wrong
var ErrMalformedSignature = errors.New("jwt: malformed signature")

// ErrECDSAVerification is returned when the verification failed
var ErrECDSAVerification = errors.New("crypto/ecdsa: verification error")

func init() {
	jwt.RegisterJWA(jwt.ES256, NewES256, AvailableES256)
	jwt.RegisterJWA(jwt.ES384, NewES384, AvailableES384)
	jwt.RegisterJWA(jwt.ES512, NewES512, AvailableES512)
}

func packSignature(r, s *big.Int, keySize int) (signature []byte, err error) {
	signature = make([]byte, keySize*2)
	r.FillBytes(signature[:keySize])
	s.FillBytes(signature[keySize:])
	return signature, nil
}

func unpackSignature(signature []byte, keySize int) (r, s *big.Int, err error) {
	if len(signature) != int(2*keySize) {
		return nil, nil, ErrMalformedSignature
	}
	r = big.NewInt(0).SetBytes(signature[:keySize])
	s = big.NewInt(0).SetBytes(signature[keySize:])

	return r, s, nil
}

func verifyEC(signature []byte, pub *ecdsa.PublicKey, h hash.Hash, keySize int) error {
	sum := h.Sum(nil)
	r, s, err := unpackSignature(signature, keySize)
	if err != nil {
		return err
	}
	if !ecdsa.Verify(pub, sum, r, s) {
		return ErrECDSAVerification
	}
	return nil
}

func verify(signature []byte, pub crypto.PublicKey, h hash.Hash, keySize int) error {
	switch epub := pub.(type) {
	case *ecdsa.PublicKey:
		return verifyEC(signature, epub, h, keySize)
	}
	return errors.New("unknown keytype")
}

func signEC(rand io.Reader, priv *ecdsa.PrivateKey, h hash.Hash, keySize int) ([]byte, error) {
	if (priv.Params().BitSize+7)/8 != keySize {
		return nil, errors.New("invalid signature size")
	}

	sum := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand, priv, sum)
	if err != nil {
		return nil, err
	}

	return packSignature(r, s, keySize)
}

func sign(rand io.Reader, priv crypto.PrivateKey, h hash.Hash, keySize int) ([]byte, error) {
	switch epriv := priv.(type) {
	case *ecdsa.PrivateKey:
		return signEC(rand, epriv, h, keySize)
	}
	return nil, errors.New("unknown keytype")
}

func validateEC(name string, priv *ecdsa.PrivateKey) error {
	if priv.Params().Name != name {
		return errors.New("invalid curve")
	}
	return nil
}

func validate(name string, priv interface{}) error {
	switch epriv := priv.(type) {
	case *ecdsa.PrivateKey:
		return validateEC(name, epriv)
	}
	return errors.New("unknown keytype")
}

// #region ES256

const (
	es256KeySize = (256 + 7) / 8
	es256Hash    = crypto.SHA256
	es256Curve   = "P-256"
)

type es256 struct{ h hash.Hash }

// NewES256 creates a new jwa.Algorithm computing the signature for the ES256 JWA
func NewES256() jwa.JWA { return es256{h: es256Hash.New()} }

// AvailableES256 reports whether the given algorithm and hash function is linked into the binary.
func AvailableES256() bool { return es256Hash.Available() }

func (es es256) Write(b []byte) (n int, err error)           { return es.h.Write(b) }
func (es es256) Reset()                                      { es.h.Reset() }
func (es es256) BlockSize() int                              { return es.h.BlockSize() }
func (es es256) Size(priv crypto.PrivateKey) int             { return es256KeySize * 2 }
func (es es256) Validate(priv crypto.PrivateKey) (err error) { return validate(es256Curve, priv) }
func (es es256) Sign(rand io.Reader, priv crypto.PrivateKey) (signature []byte, err error) {
	return sign(rand, priv, es.h, es256KeySize)
}
func (es es256) Verify(signature []byte, pub crypto.PublicKey) (err error) {
	return verify(signature, pub, es.h, es256KeySize)
}

// #endregion ES256

// #region ES384

const (
	es384KeySize = (384 + 7) / 8
	es384Hash    = crypto.SHA384
	es384Curve   = "P-384"
)

type es384 struct{ h hash.Hash }

// NewES384 creates a new jwa.Algorithm computing the signature for the ES384 JWA
func NewES384() jwa.JWA { return es384{h: es384Hash.New()} }

// AvailableES384 reports whether the given algorithm and hash function is linked into the binary.
func AvailableES384() bool { return es384Hash.Available() }

func (es es384) Write(b []byte) (n int, err error)           { return es.h.Write(b) }
func (es es384) Reset()                                      { es.h.Reset() }
func (es es384) BlockSize() int                              { return es.h.BlockSize() }
func (es es384) Size(priv crypto.PrivateKey) int             { return es384KeySize * 2 }
func (es es384) Validate(priv crypto.PrivateKey) (err error) { return validate(es384Curve, priv) }
func (es es384) Sign(rand io.Reader, priv crypto.PrivateKey) (signature []byte, err error) {
	return sign(rand, priv, es.h, es384KeySize)
}
func (es es384) Verify(signature []byte, pub crypto.PublicKey) (err error) {
	return verify(signature, pub, es.h, es384KeySize)
}

// #endregion ES384

// #region ES512

const (
	es512KeySize = (521 + 7) / 8
	es512Hash    = crypto.SHA512
	es512Curve   = "P-521"
)

type es512 struct{ h hash.Hash }

// NewES512 creates a new jwa.Algorithm computing the signature for the ES512 JWA
func NewES512() jwa.JWA { return es512{h: es512Hash.New()} }

// AvailableES512 reports whether the given algorithm and hash function is linked into the binary.
func AvailableES512() bool { return es512Hash.Available() }

func (es es512) Write(b []byte) (n int, err error)           { return es.h.Write(b) }
func (es es512) Reset()                                      { es.h.Reset() }
func (es es512) BlockSize() int                              { return es.h.BlockSize() }
func (es es512) Size(priv crypto.PrivateKey) int             { return es512KeySize * 2 }
func (es es512) Validate(priv crypto.PrivateKey) (err error) { return validate(es512Curve, priv) }
func (es es512) Sign(rand io.Reader, priv crypto.PrivateKey) (signature []byte, err error) {
	return sign(rand, priv, es.h, es512KeySize)
}
func (es es512) Verify(signature []byte, pub crypto.PublicKey) (err error) {
	return verify(signature, pub, es.h, es512KeySize)
}

// #endregion ES512
