package ecdsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"hash"
	"io"
	"math/big"
	"strconv"

	"github.com/KalleDK/go-jwt/jwa"
	"github.com/KalleDK/go-jwt/jwt"
)

type verifier struct {
	key     *ecdsa.PublicKey
	hash    crypto.Hash
	keySize uint8
}

func (v verifier) Verify(signed, signature []byte) error {
	if len(signature) != int(2*v.keySize) {
		return ErrMalformedSignature
	}
	r := big.NewInt(0).SetBytes(signature[:v.keySize])
	s := big.NewInt(0).SetBytes(signature[v.keySize:])

	sum := func(b []byte) []byte {
		hasher := v.hash.New()
		hasher.Write(b)
		return hasher.Sum(nil)
	}(signed)

	if !ecdsa.Verify(v.key, sum, r, s) {
		return ErrECDSAVerification
	}

	return nil
}

type signer struct {
	hash    crypto.Hash
	key     *ecdsa.PrivateKey
	keySize uint8
}

func (signer signer) Sign(rand io.Reader, unsigned []byte) (signature []byte, err error) {
	sum := func() []byte {
		hasher := signer.hash.New()
		hasher.Write(unsigned)
		return hasher.Sum(nil)
	}()

	r, s, err := ecdsa.Sign(rand, signer.key, sum)
	if err != nil {
		return nil, err
	}

	signature = make([]byte, signer.keySize*2)
	r.FillBytes(signature[:signer.keySize])
	s.FillBytes(signature[signer.keySize:])
	return signature, nil
}

// ErrMalformedSignature is returned when the signature length is wrong
var ErrMalformedSignature = errors.New("jwt: malformed signature")

// ErrECDSAVerification is returned when the verification failed
var ErrECDSAVerification = errors.New("crypto/ecdsa: verification error")

type ESDSA struct {
	hash    crypto.Hash
	keySize uint8
	name    string
}

func (e ESDSA) Available() bool {
	return e.hash.Available()
}

func (e ESDSA) NewVerifier(key crypto.PublicKey) jwa.Verifier {

	pkey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		panic("invalid key type")
	}

	if pkey.Params().Name != e.name {
		panic("invalid key params: " + pkey.Params().Name)
	}

	if !e.hash.Available() {
		panic("crypto: requested hash function #" + strconv.Itoa(int(e.hash)) + " is unavailable")
	}

	return verifier{
		key:     pkey,
		hash:    e.hash,
		keySize: e.keySize,
	}
}

func (e ESDSA) NewSigner(key crypto.PrivateKey) jwa.Signer {

	privkey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		panic("invalid key type")
	}

	if privkey.Params().Name != e.name {
		panic("invalid key curve: " + privkey.Params().Name + " expected key curve to be " + e.name)
	}

	if !e.hash.Available() {
		panic("crypto: requested hash function #" + strconv.Itoa(int(e.hash)) + " is unavailable")
	}

	return signer{
		key:     privkey,
		hash:    e.hash,
		keySize: e.keySize,
	}
}

func NewES256() ESDSA {
	return ESDSA{hash: crypto.SHA256, keySize: 32, name: elliptic.P256().Params().Name}
}

func NewES384() ESDSA {
	return ESDSA{hash: crypto.SHA384, keySize: 48, name: elliptic.P384().Params().Name}
}

func NewES512() ESDSA {
	return ESDSA{hash: crypto.SHA512, keySize: 66, name: elliptic.P521().Params().Name}
}

func init() {
	jwt.RegisterAlgorithm(jwt.ES256, NewES256())
	jwt.RegisterAlgorithm(jwt.ES384, NewES384())
	jwt.RegisterAlgorithm(jwt.ES512, NewES512())
	jwt.RegisterJWA(jwt.ES256, NewES256A, AvailableES256)
	jwt.RegisterJWA(jwt.ES384, NewES384A, AvailableES384)
	jwt.RegisterJWA(jwt.ES512, NewES512A, AvailableES512)
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

const (
	es256KeySize = (256 + 7) / 8
	es256Hash    = crypto.SHA256
	es256Curve   = "P-256"

	es384KeySize = (384 + 7) / 8
	es384Hash    = crypto.SHA384
	es384Curve   = "P-384"

	es512KeySize = (521 + 7) / 8
	es512Hash    = crypto.SHA512
	es512Curve   = "P-521"
)

type es256 struct{ h hash.Hash }

func NewES256A() jwa.JWA                                     { return es256{h: es256Hash.New()} }
func AvailableES256() bool                                   { return es256Hash.Available() }
func (es es256) Write(b []byte) (n int, err error)           { return es.h.Write(b) }
func (es es256) Reset()                                      { es.h.Reset() }
func (es es256) BlockSize() int                              { return es.h.BlockSize() }
func (es es256) Size() int                                   { return es256KeySize * 2 }
func (es es256) Validate(priv crypto.PrivateKey) (err error) { return validate(es256Curve, priv) }
func (es es256) Sign(rand io.Reader, priv crypto.PrivateKey) (signature []byte, err error) {
	return sign(rand, priv, es.h, es256KeySize)
}
func (es es256) Verify(signature []byte, pub crypto.PublicKey) (err error) {
	return verify(signature, pub, es.h, es256KeySize)
}

type es384 struct{ h hash.Hash }

func NewES384A() jwa.JWA                                     { return es384{h: es384Hash.New()} }
func AvailableES384() bool                                   { return es384Hash.Available() }
func (es es384) Write(b []byte) (n int, err error)           { return es.h.Write(b) }
func (es es384) Reset()                                      { es.h.Reset() }
func (es es384) BlockSize() int                              { return es.h.BlockSize() }
func (es es384) Size() int                                   { return es384KeySize * 2 }
func (es es384) Validate(priv crypto.PrivateKey) (err error) { return validate(es384Curve, priv) }
func (es es384) Sign(rand io.Reader, priv crypto.PrivateKey) (signature []byte, err error) {
	return sign(rand, priv, es.h, es384KeySize)
}
func (es es384) Verify(signature []byte, pub crypto.PublicKey) (err error) {
	return verify(signature, pub, es.h, es384KeySize)
}

type es512 struct{ h hash.Hash }

func NewES512A() jwa.JWA                                     { return es512{h: es512Hash.New()} }
func AvailableES512() bool                                   { return es512Hash.Available() }
func (es es512) Write(b []byte) (n int, err error)           { return es.h.Write(b) }
func (es es512) Reset()                                      { es.h.Reset() }
func (es es512) BlockSize() int                              { return es.h.BlockSize() }
func (es es512) Size() int                                   { return es512KeySize * 2 }
func (es es512) Validate(priv crypto.PrivateKey) (err error) { return validate(es512Curve, priv) }
func (es es512) Sign(rand io.Reader, priv crypto.PrivateKey) (signature []byte, err error) {
	return sign(rand, priv, es.h, es512KeySize)
}
func (es es512) Verify(signature []byte, pub crypto.PublicKey) (err error) {
	return verify(signature, pub, es.h, es512KeySize)
}

/*
type EC256 struct{}

const ec256Hash = crypto.SHA256
const ec256KeySize = 32

var ec256Curve = elliptic.P256()

func (ec EC256) Sign(rand io.Reader, unsigned []byte, key *ecdsa.PrivateKey) (signature []byte, err error) {
	sum := func() []byte {
		hasher := ec256Hash.New()
		hasher.Write(unsigned)
		return hasher.Sum(nil)
	}()

	r, s, err := ecdsa.Sign(rand, key, sum)
	if err != nil {
		return nil, err
	}

	signature = make([]byte, ec256KeySize*2)
	r.FillBytes(signature[:ec256KeySize])
	s.FillBytes(signature[ec256KeySize:])
	return signature, nil
}

*/
