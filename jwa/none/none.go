package none

import (
	"crypto"
	"errors"
	"io"

	"github.com/KalleDK/go-jwt/jwa"
	"github.com/KalleDK/go-jwt/jwt"
)

var ErrNoneVerification = errors.New("crypto/none: verification error")

type noneAlg struct{}

func (n noneAlg) Verify(signed, signature []byte) error {
	if len(signature) > 0 {
		return ErrNoneVerification
	}
	return nil
}

func (n noneAlg) Sign(rand io.Reader, unsigned []byte) (signature []byte, err error) {
	return []byte{}, nil
}

type none struct{}

func (n none) Available() bool {
	return true
}

func (n none) NewVerifier(key crypto.PublicKey) jwa.Verifier {
	return noneAlg{}
}

func (n none) NewSigner(key crypto.PrivateKey) jwa.Signer {
	return noneAlg{}
}

func init() {
	jwt.RegisterAlgorithm(jwt.None, none{})
	jwt.RegisterJWA(jwt.None, NewNone, AvailableNone)
}

type noneJWA struct{}

// NewNone creates a new jwa.Algorithm computing the signature for the None JWA
func NewNone() jwa.JWA { return noneJWA{} }

// AvailableNone reports whether the given algorithm and hash function is linked into the binary.
func AvailableNone() bool { return true }

func (n noneJWA) Write(b []byte) (s int, err error)           { return len(b), nil }
func (n noneJWA) Reset()                                      {}
func (n noneJWA) BlockSize() int                              { return 256 }
func (n noneJWA) Size(priv crypto.PrivateKey) int             { return 0 }
func (n noneJWA) Validate(priv crypto.PrivateKey) (err error) { return nil }
func (n noneJWA) Sign(rand io.Reader, priv crypto.PrivateKey) (signature []byte, err error) {
	return []byte{}, nil
}
func (n noneJWA) Verify(signature []byte, pub crypto.PublicKey) (err error) {
	return nil
}
