package rsa

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"hash"
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
	jwt.RegisterJWA(jwt.RS256, NewRS256A, AvailableRS256)
	jwt.RegisterJWA(jwt.RS384, NewRS384A, AvailableRS384)
	jwt.RegisterJWA(jwt.RS512, NewRS512A, AvailableRS512)
}

func verifyRSA(signature []byte, pub *rsa.PublicKey, h hash.Hash, ha crypto.Hash) error {
	sum := h.Sum(nil)
	return rsa.VerifyPKCS1v15(pub, ha, sum, signature)
}

func verify(signature []byte, pub crypto.PublicKey, h hash.Hash, ha crypto.Hash) error {
	switch epub := pub.(type) {
	case *rsa.PublicKey:
		return verifyRSA(signature, epub, h, ha)
	}
	return errors.New("unknown keytype")
}

func signRSA(rand io.Reader, priv *rsa.PrivateKey, h hash.Hash, ha crypto.Hash) ([]byte, error) {
	sum := h.Sum(nil)

	return rsa.SignPKCS1v15(rand, priv, ha, sum)
}

func sign(rand io.Reader, priv crypto.PrivateKey, h hash.Hash, ha crypto.Hash) ([]byte, error) {
	switch epriv := priv.(type) {
	case *rsa.PrivateKey:
		return signRSA(rand, epriv, h, ha)
	}
	return nil, errors.New("unknown keytype")
}

func validateRSA(name string, priv *rsa.PrivateKey) error {
	return nil
}

func validate(name string, priv interface{}) error {
	switch epriv := priv.(type) {
	case *rsa.PrivateKey:
		return validateRSA(name, epriv)
	}
	return errors.New("unknown keytype")
}

func sizeRSA(priv *rsa.PrivateKey) int {
	return priv.Size()
}

func size(priv crypto.PrivateKey) int {
	switch epriv := priv.(type) {
	case *rsa.PrivateKey:
		return sizeRSA(epriv)
	}
	panic("invalid key")
}

// #region RS256

const (
	rs256Hash = crypto.SHA256
)

type rs256 struct{ h hash.Hash }

// NewRS256 creates a new jwa.Algorithm computing the signature for the RS256 JWA
func NewRS256A() jwa.JWA { return rs256{h: rs256Hash.New()} }

// AvailableRS256 reports whether the given algorithm and hash function is linked into the binary.
func AvailableRS256() bool { return rs256Hash.Available() }

func (es rs256) Write(b []byte) (n int, err error)           { return es.h.Write(b) }
func (es rs256) Reset()                                      { es.h.Reset() }
func (es rs256) BlockSize() int                              { return es.h.BlockSize() }
func (es rs256) Size(priv crypto.PrivateKey) int             { return size(priv) }
func (es rs256) Validate(priv crypto.PrivateKey) (err error) { return validate("", priv) }
func (es rs256) Sign(rand io.Reader, priv crypto.PrivateKey) (signature []byte, err error) {
	return sign(rand, priv, es.h, rs256Hash)
}
func (es rs256) Verify(signature []byte, pub crypto.PublicKey) (err error) {
	return verify(signature, pub, es.h, rs256Hash)
}

// #endregion RS256

// #region RS384

const (
	rs384Hash = crypto.SHA384
)

type rs384 struct{ h hash.Hash }

// NewRS384 creates a new jwa.Algorithm computing the signature for the RS384 JWA
func NewRS384A() jwa.JWA { return rs384{h: rs384Hash.New()} }

// AvailableRS384 reports whether the given algorithm and hash function is linked into the binary.
func AvailableRS384() bool { return rs384Hash.Available() }

func (es rs384) Write(b []byte) (n int, err error)           { return es.h.Write(b) }
func (es rs384) Reset()                                      { es.h.Reset() }
func (es rs384) BlockSize() int                              { return es.h.BlockSize() }
func (es rs384) Size(priv crypto.PrivateKey) int             { return size(priv) }
func (es rs384) Validate(priv crypto.PrivateKey) (err error) { return validate("", priv) }
func (es rs384) Sign(rand io.Reader, priv crypto.PrivateKey) (signature []byte, err error) {
	return sign(rand, priv, es.h, rs384Hash)
}
func (es rs384) Verify(signature []byte, pub crypto.PublicKey) (err error) {
	return verify(signature, pub, es.h, rs384Hash)
}

// #endregion RS384

// #region RS512

const (
	rs512Hash = crypto.SHA512
)

type rs512 struct{ h hash.Hash }

// NewRS512 creates a new jwa.Algorithm computing the signature for the RS512 JWA
func NewRS512A() jwa.JWA { return rs512{h: rs512Hash.New()} }

// AvailableRS512 reports whether the given algorithm and hash function is linked into the binary.
func AvailableRS512() bool { return rs512Hash.Available() }

func (es rs512) Write(b []byte) (n int, err error)           { return es.h.Write(b) }
func (es rs512) Reset()                                      { es.h.Reset() }
func (es rs512) BlockSize() int                              { return es.h.BlockSize() }
func (es rs512) Size(priv crypto.PrivateKey) int             { return size(priv) }
func (es rs512) Validate(priv crypto.PrivateKey) (err error) { return validate("", priv) }
func (es rs512) Sign(rand io.Reader, priv crypto.PrivateKey) (signature []byte, err error) {
	return sign(rand, priv, es.h, rs512Hash)
}
func (es rs512) Verify(signature []byte, pub crypto.PublicKey) (err error) {
	return verify(signature, pub, es.h, rs512Hash)
}

// #endregion RS512
