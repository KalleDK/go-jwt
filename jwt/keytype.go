package jwt

import (
	"errors"
	"strconv"
)

type KeyParser interface {
	ParseSigner(kid string, b []byte) (Signer, error)
	ParseVerifier(kid string, b []byte) (Verifier, error)
}

type KeyType uint8

const (
	InvalidKeytype KeyType = iota
	// Elliptic Curve
	EC
	// RSA
	RSA
	// Octet Sequence
	OCT

	maxKeyTypes
)

var keyTypes = make([]KeyParser, maxKeyTypes)

func RegisterKeyType(k KeyType, p KeyParser) {
	if k <= 0 || maxKeyTypes <= k {
		panic("jwt: RegisterKeyType of unknown key type")
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
	return nil, errors.New("jwt: requested key type #" + strconv.Itoa(int(k)) + " is unavailable")
}

func (k KeyType) ParseSigner(kid string, b []byte) (Signer, error) {
	f, err := k.getKeyParser()
	if err != nil {
		return nil, err
	}

	return f.ParseSigner(kid, b)
}

func (k KeyType) ParseVerifier(kid string, b []byte) (Verifier, error) {
	f, err := k.getKeyParser()
	if err != nil {
		return nil, err
	}

	return f.ParseVerifier(kid, b)
}

func (k KeyType) IsValid() bool {
	return InvalidKeytype < k && k < maxKeyTypes
}

func (k *KeyType) UnmarshalText(text []byte) error {
	*k = GetKeyType(string(text))
	if !k.IsValid() {
		return errors.New("invalid keytype: " + string(text))
	}
	return nil
}

func (k KeyType) MarshalText() (text []byte, err error) {
	if !k.IsValid() {
		return nil, errors.New("invalid algorithm: " + k.String())
	}
	return []byte(k.String()), nil
}

func (k KeyType) String() string {
	switch k {
	case EC:
		return "EC"
	case RSA:
		return "RSA"
	case OCT:
		return "oct"
	default:
		return "unknown keytype value " + strconv.Itoa(int(k))
	}
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
