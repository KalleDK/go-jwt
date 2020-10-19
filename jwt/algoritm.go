package jwt

import (
	"crypto"
	"errors"
	"io"
	"strconv"

	"github.com/KalleDK/go-jwt/jwa"
)

// Algorithm is the different JWT algoritms
type Algorithm uint8

const (
	Invalid Algorithm = 0 + iota
	// None is a token without a signature
	None
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

type Decryptor interface{}
type Encryptor interface{}

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
var jwasAvailable = make([]func() bool, maxAlgorithm)
var jwas = make([]func() jwa.JWA, maxAlgorithm)

func RegisterJWA(alg Algorithm, f func() jwa.JWA, a func() bool) {
	if alg >= maxAlgorithm {
		panic("jwt: RegisterAlgorithm of unknown algorithm")
	}
	jwasAvailable[alg] = a
	jwas[alg] = f
}

func RegisterAlgorithm(a Algorithm, alg jwa.Algoritm) {
	if a >= maxAlgorithm {
		panic("jwt: RegisterAlgorithm of unknown algorithm")
	}
	algorithms[a] = alg
}

func (a Algorithm) ValidateSignerKey(key crypto.PrivateKey) error {
	return a.New().Validate(key)
}

func (a Algorithm) ValidateVerifierKey(key crypto.PublicKey) error {
	return nil
}

func (a Algorithm) Available() bool {
	return a < maxAlgorithm && jwas[a] != nil && jwasAvailable[a] != nil && jwasAvailable[a]()
}

func (a Algorithm) New() jwa.JWA {
	if a > 0 && a < maxAlgorithm {
		f := jwas[a]
		if f != nil {
			return f()
		}
	}
	panic("jwt: requested algorithm #" + strconv.Itoa(int(a)) + " is unavailable")
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

func (a Algorithm) IsValid() bool {
	return Invalid < a && a < maxAlgorithm
}

func (a *Algorithm) UnmarshalText(text []byte) error {
	*a = GetAlgorithm(string(text))
	if !a.IsValid() {
		return errors.New("invalid algoritm " + string(text) + " " + a.String())
	}
	return nil
}

func (a Algorithm) MarshalText() (text []byte, err error) {
	if !a.IsValid() {
		return nil, errors.New("invalid algorithm " + strconv.FormatUint(uint64(uint8(a)), 10))
	}
	return []byte(a.String()), nil
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
	case RS512:
		return "RS512"
	case RS256:
		return "RS256"
	case RS384:
		return "RS384"
	default:
		return "unknown algorithm value " + strconv.Itoa(int(a))
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
