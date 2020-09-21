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

	maxAlgorithm
)

type Verifier struct {
	verifier jwa.Verifier
	alg      Algorithm
	kid      string
}

func (v Verifier) Verify(a Algorithm, kidSuggest string, signed, signature []byte) (kidUsed string, err error) {
	if a != v.alg {
		return "", ErrInvalidSignature
	}

	if err := v.verifier.Verify(signed, signature); err != nil {
		return "", err
	}

	return v.kid, nil
}

func (v Verifier) Algorithm() Algorithm {
	return v.alg
}

func (v Verifier) KeyID() string {
	return v.kid
}

type Signer struct {
	signer jwa.Signer
	alg    Algorithm
	kid    string
}

func (s Signer) Sign(rand io.Reader, unsigned []byte) (signature []byte, err error) {
	return s.signer.Sign(rand, unsigned)
}

func (s Signer) Algorithm() Algorithm {
	return s.alg
}

func (s Signer) KeyID() string {
	return s.kid
}

type SignVerifier struct {
	Signer
	Verifier
}

var algorithms = make([]jwa.Algoritm, maxAlgorithm)

func RegisterAlgorithm(a Algorithm, alg jwa.Algoritm) {
	if a >= maxAlgorithm {
		panic("jwt: RegisterAlgorithm of unknown algorithm")
	}
	algorithms[a] = alg
}

func (a Algorithm) NewVerifier(kid string, key crypto.PublicKey) Verifier {
	if a > 0 && a < maxAlgorithm {
		f := algorithms[a]
		if f != nil {
			return Verifier{f.NewVerifier(key), a, kid}
		}
	}
	panic("jwt: requested algorithm #" + strconv.Itoa(int(a)) + " is unavailable")
}

func (a Algorithm) NewSigner(kid string, key crypto.PrivateKey) Signer {
	if a > 0 && a < maxAlgorithm {
		f := algorithms[a]
		if f != nil {
			return Signer{f.NewSigner(key), a, kid}
		}
	}
	panic("jwt: requested algorithm #" + strconv.Itoa(int(a)) + " is unavailable")
}

func (a Algorithm) NewSignVerifier(kid string, privkey crypto.PrivateKey, pubkey crypto.PublicKey) SignVerifier {
	if a > 0 && a < maxAlgorithm {
		f := algorithms[a]
		if f != nil {
			return SignVerifier{
				Signer:   Signer{f.NewSigner(privkey), a, kid},
				Verifier: Verifier{f.NewVerifier(pubkey), a, kid},
			}
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
