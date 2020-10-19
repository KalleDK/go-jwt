package jwk

import (
	"errors"

	"github.com/KalleDK/go-jwt/jwt"
)

type KeyType uint8

type ErrInvalidKeyType KeyType

func (e ErrInvalidKeyType) Error() string {
	return "invalid keytype"
}

func (k KeyType) ParseEncryptor(base KeyBase, b []byte) (jwt.Encryptor, error) {
	f, err := getKeyParser(k)
	if err != nil {
		return nil, err
	}

	return f.ParseEncryptor(base, b)
}

func (k KeyType) ParseDecryptor(base KeyBase, b []byte) (jwt.Decryptor, error) {
	f, err := getKeyParser(k)
	if err != nil {
		return nil, err
	}

	return f.ParseDecryptor(base, b)
}

func (k KeyType) ParseSigner(base KeyBase, b []byte) (jwt.Signer, error) {
	f, err := getKeyParser(k)
	if err != nil {
		return nil, err
	}

	return f.ParseSigner(base, b)
}

func (k KeyType) ParseVerifier(base KeyBase, b []byte) (jwt.Verifier, error) {
	f, err := getKeyParser(k)
	if err != nil {
		return nil, err
	}

	return f.ParseVerifier(base, b)
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
		return nil, ErrInvalidKeyType(k)
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
		return "unknown keytype value"
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
		return InvalidKeytype
	}
}
