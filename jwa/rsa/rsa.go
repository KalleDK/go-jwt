package rsa

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"io"
	"strconv"

	"github.com/KalleDK/go-jwt/jwa"
	"github.com/KalleDK/go-jwt/jwt"
)

type verifier struct {
	key     *rsa.PublicKey
	hash    crypto.Hash
	keySize uint8
}

func (v verifier) Verify(signed, signature []byte) error {

	sum := func(b []byte) []byte {
		hasher := v.hash.New()
		hasher.Write(b)
		return hasher.Sum(nil)
	}(signed)

	return rsa.VerifyPKCS1v15(v.key, v.hash, sum, signature)
}

type signer struct {
	hash    crypto.Hash
	key     *rsa.PrivateKey
	keySize uint8
}

func (signer signer) Sign(rand io.Reader, unsigned []byte) (signature []byte, err error) {
	sum := func() []byte {
		hasher := signer.hash.New()
		hasher.Write(unsigned)
		return hasher.Sum(nil)
	}()

	return rsa.SignPKCS1v15(rand, signer.key, signer.hash, sum)
}

// ErrMalformedSignature is returned when the signature length is wrong
var ErrMalformedSignature = errors.New("jwt: malformed signature")

type RSA struct {
	hash    crypto.Hash
	keySize uint8
}

func (e RSA) Available() bool {
	return e.hash.Available()
}

func (e RSA) NewVerifier(key crypto.PublicKey) jwa.Verifier {

	pkey, ok := key.(*rsa.PublicKey)
	if !ok {
		panic("invalid key type")
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

func (e RSA) NewSigner(key crypto.PrivateKey) jwa.Signer {

	privkey, ok := key.(*rsa.PrivateKey)
	if !ok {
		panic("invalid key type")
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

func NewRS256() RSA {
	return RSA{hash: crypto.SHA256, keySize: 256 / 8}
}

func NewRS384() RSA {
	return RSA{hash: crypto.SHA384, keySize: 384 / 8}
}

func NewRS512() RSA {
	return RSA{hash: crypto.SHA512, keySize: 512 / 8}
}

func init() {
	jwt.RegisterAlgorithm(jwt.RS256, NewRS256())
	jwt.RegisterAlgorithm(jwt.RS384, NewRS384())
	jwt.RegisterAlgorithm(jwt.RS512, NewRS512())
}
