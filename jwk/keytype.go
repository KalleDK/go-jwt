package jwk

import (
	"errors"
	"strconv"

	"github.com/KalleDK/go-jwt/jwt"
)

type KeyParser interface {
	ParseSigner(kid string, b []byte) (jwt.Signer, error)
	ParseVerifier(kid string, b []byte) (jwt.Verifier, error)
}

type KeyType uint8

const (
	// Elliptic Curve
	EC KeyType = 1 + iota
	// RSA
	RSA
	// Octet Sequence
	OCT

	maxKeyTypes
)

var keyTypes = make([]KeyParser, maxKeyTypes)

func RegisterKeyType(k KeyType, p KeyParser) {
	if k <= 0 || maxKeyTypes <= k {
		panic("jwk: RegisterKeyType of unknown key type")
	}
	keyTypes[k] = p
}

func (k KeyType) getKeyParser() (p KeyParser, err error) {
	if 0 < k && k < maxKeyTypes {
		f := keyTypes[k]
		if f != nil {
			return f, nil
		}
	}
	return nil, errors.New("jwk: requested key type #" + strconv.Itoa(int(k)) + " is unavailable")
}

func (k KeyType) ParseSigner(kid string, b []byte) (jwt.Signer, error) {
	f, err := k.getKeyParser()
	if err != nil {
		return nil, err
	}

	return f.ParseSigner(kid, b)
}

func (k KeyType) ParseVerifier(kid string, b []byte) (jwt.Verifier, error) {
	f, err := k.getKeyParser()
	if err != nil {
		return nil, err
	}

	return f.ParseVerifier(kid, b)
}

func GetKeyType(s string) KeyType {
	switch s {
	case "EC":
		return EC
	case "RSA":
		return RSA
	case "oct":
		return OCT
	default:
		return 0
	}
}
