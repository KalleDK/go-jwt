package jwk

import (
	"errors"
	"strconv"

	"github.com/KalleDK/go-jwt/jwt"
)

type KeyBase struct {
	Kid string        `json:"kid,omitempty"`
	Alg jwt.Algorithm `json:"alg"`
}

func (k KeyBase) Algorithm() jwt.Algorithm { return k.Alg }
func (k KeyBase) KeyID() string            { return k.Kid }
func (k KeyBase) Available() bool          { return k.Alg.Available() }

type KeyParser interface {
	ParseSigner(base KeyBase, b []byte) (jwt.Signer, error)
	ParseVerifier(base KeyBase, b []byte) (jwt.Verifier, error)
	ParseEncryptor(base KeyBase, b []byte) (jwt.Encryptor, error)
	ParseDecryptor(base KeyBase, b []byte) (jwt.Decryptor, error)
}

const (
	// InvalidKeytype is used to make sure a value can be invalid
	InvalidKeytype KeyType = iota
	// EC is Elliptic Curve
	EC
	// RSA is RSA
	RSA
	// OCT is Octet Sequence
	OCT

	maxKeyTypes
)

var keyTypes = make([]KeyParser, maxKeyTypes)

func RegisterKeyParser(k KeyType, p KeyParser) {
	if k <= 0 || maxKeyTypes <= k {
		panic("jwt: RegisterKeyType of unknown key type")
	}
	keyTypes[k] = p
}

func getKeyParser(k KeyType) (p KeyParser, err error) {
	if 0 < k && k < maxKeyTypes {
		f := keyTypes[k]
		if f != nil {
			return f, nil
		}
	}
	return nil, errors.New("jwt: requested key type #" + strconv.Itoa(int(k)) + " is unavailable")
}

func parseBase(b []byte) (KeyType, KeyBase, error) {
	kb := KeyBase{}

	kt := func() KeyType {
		switch kb.Alg {
		case jwt.RS256:
			fallthrough
		case jwt.RS384:
			fallthrough
		case jwt.RS512:
			return RSA
		case jwt.ES256:
			fallthrough
		case jwt.ES384:
			fallthrough
		case jwt.ES512:
			return EC
		default:
			return InvalidKeytype
		}
	}()

	return kt, kb, nil
}

func ParseSigner(b []byte) (jwt.Signer, error) {
	kt, base, err := parseBase(b)
	if err != nil {
		return nil, err
	}

	return kt.ParseSigner(base, b)

}
