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
}
