package jwt

import (
	"encoding/json"
	"errors"
	"io"
)

var (
	ErrMalformedToken     = errors.New("malformed packet")
	ErrMalformedHeader    = errors.New("malformed header")
	ErrInvalidSignature   = errors.New("signature is invalid")
	ErrNoVerifiersWithKID = errors.New("no verifiers with kid")
)

func Marshal(rand io.Reader, payload interface{}, signer Signer) ([]byte, error) {
	header := header{
		Type: "JWT",
	}
	return MarshalWithHeader(rand, payload, &header, signer)
}

func MarshalWithHeader(rand io.Reader, payload interface{}, header Header, signer Signer) ([]byte, error) {

	header.SetAlg(signer.Algorithm())
	header.SetKid(signer.KeyID())
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	headerSize := len(headerJSON)

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	payloadSize := len(payloadJSON)

	signatureSize := int(signer.Algorithm().SignatureSize())

	token := newTokenBuffer(headerSize, payloadSize, signatureSize)

	// Encode the token
	encodeSegment(token.headerSlice, headerJSON)
	encodeSegment(token.payloadSlice, payloadJSON)

	// Sign the token
	signature, err := signer.Sign(rand, token.signedSlice)
	if err != nil {
		return nil, err
	}

	// Encode the signature
	encodeSegment(token.signatureSlice, signature)
	return token.buffer, nil
}

func Unmarshal(b []byte, payload interface{}, verifiers Verifiers) (string, error) {
	var header header
	return UnmarshalWithHeader(b, payload, &header, verifiers)
}

func UnmarshalPayload(b []byte, payload interface{}) error {
	token, err := parseTokenBuffer(b)
	if err != nil {
		return err
	}

	return unmarshalPayload(token.payloadSlice, payload)
}

func UnmarshalWithHeader(b []byte, payload interface{}, header Header, verifiers Verifiers) (string, error) {
	token, err := parseTokenBuffer(b)
	if err != nil {
		return "", err
	}

	if err := unmarshalHeader(token.headerSlice, header); err != nil {
		return "", err
	}

	kid, err := unmarshalSignature(header, verifiers, token.signedSlice, token.signatureSlice)
	if err != nil {
		return kid, err
	}

	if err := unmarshalPayload(token.payloadSlice, payload); err != nil {
		return kid, err
	}

	return kid, nil
}

func unmarshalSignature(header Header, verifiers Verifiers, signedSlice []byte, signatureSlice []byte) (string, error) {
	signature, err := decodeSegment(signatureSlice)
	if err != nil {
		return "", err
	}
	return verifiers.Verify(header.Alg(), header.Kid(), signedSlice, signature)
}

func unmarshalHeader(headerSlice []byte, header Header) error {
	headerbuf, err := decodeSegment(headerSlice)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(headerbuf, &header); err != nil {
		return err
	}
	if err := header.Valid(); err != nil {
		return err
	}
	return nil
}

func unmarshalPayload(payloadSlice []byte, payload interface{}) error {
	payloadbuf, err := decodeSegment(payloadSlice)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payloadbuf, payload); err != nil {
		return err
	}
	return nil
}

type Verifiers interface {
	Verify(a Algorithm, kidSuggest string, signed, signature []byte) (kidUsed string, err error)
}

func NewVerifiers(keyIDMustMatch bool, vs ...Verifier) Verifiers {
	kids := map[string]Verifier{}
	vlist := []Verifier{}

	for _, v := range vs {
		kid := v.KeyID()
		if kid != "" {
			kids[kid] = v
		}
		vlist = append(vs, v)
	}
	return verifiers{kids: kids, vlist: vlist, keyIDMustMatch: keyIDMustMatch}
}

type verifiers struct {
	kids           map[string]Verifier
	vlist          []Verifier
	keyIDMustMatch bool
}

func (vs verifiers) Verify(a Algorithm, kidSuggest string, signed, signature []byte) (kidUsed string, err error) {
	v, ok := vs.kids[kidSuggest]

	if ok && v.Algorithm() == a {
		kidUsed, err = v.Verify(a, kidSuggest, signed, signature)
		if err == nil {
			return kidUsed, nil
		}
		if vs.keyIDMustMatch {
			return v.KeyID(), err
		}
	}
	if vs.keyIDMustMatch {
		return "", ErrNoVerifiersWithKID
	}

	for _, v := range vs.vlist {
		if v.Algorithm() == a {
			if kidUsed, err := v.Verify(a, kidSuggest, signed, signature); err == nil {
				return kidUsed, nil
			}
		}
	}
	return "", ErrInvalidSignature
}
