package ecdsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
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
