package jwa

import (
	"crypto"
	"io"
)

type Verifier interface {
	Verify(signed, signature []byte) error
}

type Signer interface {
	Sign(rand io.Reader, unsigned []byte) (signature []byte, err error)
}

type Algoritm interface {
	Available() bool
	NewVerifier(key crypto.PublicKey) Verifier
	NewSigner(key crypto.PrivateKey) Signer
}

type JWA interface {
	io.Writer
	Sign(rand io.Reader, priv crypto.PrivateKey) (signature []byte, err error)
	Verify(signature []byte, pub crypto.PublicKey) (err error)
	Reset()
	Size() int
	BlockSize() int
	Validate(priv crypto.PrivateKey) error
}
