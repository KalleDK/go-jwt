package jwt

import "errors"

var (
	// ErrInvalidHeaderType is returned when the type of the header is wrong
	ErrInvalidHeaderType = errors.New("invalid header type")
)

// Header is the interface for minimum header
type Header interface {
	Valid() error
	Alg() Algorithm
	Kid() string
	SetAlg(a Algorithm)
	SetKid(s string)
}

type header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid,omitempty"`
}

func (h header) Kid() string { return h.KeyID }

func (h *header) SetKid(s string) { h.KeyID = s }

func (h header) Alg() Algorithm { return GetAlgorithm(h.Algorithm) }

func (h *header) SetAlg(a Algorithm) { h.Algorithm = a.String() }

func (h header) Typ() string { return h.Type }

func (h header) Valid() error {
	if h.Typ() != "JWT" {
		return ErrInvalidHeaderType
	}
	return nil
}
