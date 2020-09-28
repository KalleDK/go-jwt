package jwt

import (
	"crypto"
	"io"
	"strconv"

	"github.com/KalleDK/go-jwt/jwa"
)

// Algorithm is the different JWT algoritms
type Algorithm uint8

const (
	// None is a token without a signature
	None Algorithm = 1 + iota
	// ES256 ECDSA P-256 and SHA-256
	ES256
	// ES384 ECDSA P-384 with SHA-384
	ES384
	// ES512 ECDSA P-521 with SHA-512
	ES512
	RS256
	RS384
	RS512

	maxAlgorithm
)

type Verifier interface {
	Verify(a Algorithm, kidSuggest string, signed, signature []byte) (kidUsed string, err error)
	Algorithm() Algorithm
	KeyID() string
}

type verifier struct {
	verifier jwa.Verifier
	alg      Algorithm
	kid      string
}

func (v verifier) Verify(a Algorithm, kidSuggest string, signed, signature []byte) (kidUsed string, err error) {
	if a != v.alg {
		return "", ErrInvalidSignature
	}

	if err := v.verifier.Verify(signed, signature); err != nil {
		return "", err
	}

	return v.kid, nil
}

func (v verifier) Algorithm() Algorithm {
	return v.alg
}

func (v verifier) KeyID() string {
	return v.kid
}

type Signer interface {
	Sign(rand io.Reader, unsigned []byte) (signature []byte, err error)
	Algorithm() Algorithm
	KeyID() string
}

type signer struct {
	signer jwa.Signer
	alg    Algorithm
	kid    string
}

func (s signer) Sign(rand io.Reader, unsigned []byte) (signature []byte, err error) {
	return s.signer.Sign(rand, unsigned)
}

func (s signer) Algorithm() Algorithm {
	return s.alg
}

func (s signer) KeyID() string {
	return s.kid
}

var algorithms = make([]jwa.Algoritm, maxAlgorithm)

func RegisterAlgorithm(a Algorithm, alg jwa.Algoritm) {
	if a >= maxAlgorithm {
		panic("jwt: RegisterAlgorithm of unknown algorithm")
	}
	algorithms[a] = alg
}

func (a Algorithm) NewVerifier(kid string, key crypto.PublicKey) verifier {
	if a > 0 && a < maxAlgorithm {
		f := algorithms[a]
		if f != nil {
			return verifier{f.NewVerifier(key), a, kid}
		}
	}
	panic("jwt: requested algorithm #" + strconv.Itoa(int(a)) + " is unavailable")
}

func (a Algorithm) NewSigner(kid string, key crypto.PrivateKey) signer {
	if a > 0 && a < maxAlgorithm {
		f := algorithms[a]
		if f != nil {
			return signer{f.NewSigner(key), a, kid}
		}
	}
	panic("jwt: requested algorithm #" + strconv.Itoa(int(a)) + " is unavailable")
}

func (a Algorithm) String() string {
	switch a {
	case None:
		return "none"
	case ES512:
		return "ES512"
	case ES256:
		return "ES256"
	case ES384:
		return "ES384"
	default:
		return "unknown algorithm value " + strconv.Itoa(int(a))
	}
}

func (a Algorithm) SignatureSize() int {
	switch a {
	case RS256:
		return 256 / 8
	case RS384:
		return 384 / 8
	case RS512:
		return 512 / 8
	case ES512:
		return 2 * ((521 + 7) / 8)
	case ES256:
		return 2 * ((256 + 7) / 8)
	case ES384:
		return 2 * ((384 + 7) / 8)
	case None:
		return 0
	default:
		return 0
	}
}

func GetAlgorithm(s string) Algorithm {
	switch s {
	case "RS256":
		return RS256
	case "RS384":
		return RS384
	case "RS512":
		return RS512
	case "ES512":
		return ES512
	case "ES256":
		return ES256
	case "ES384":
		return ES384
	case "none":
		return None
	default:
		return 0
	}
}
