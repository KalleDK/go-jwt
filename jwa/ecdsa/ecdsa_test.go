package ecdsa

import (
	"testing"

	_ "crypto/sha256"

	"github.com/KalleDK/go-jwt/jwa/test"
)

func Test_ECDSA(t *testing.T) {
	test.TestAlgorithms(t, test.ES256, test.ES384, test.ES512)
}

func Test_ECDSA_ES256(t *testing.T) {
	test.TestAlgorithm(t, NewES256, test.ES256)
}

func Test_ECDSA_ES384(t *testing.T) {
	test.TestAlgorithm(t, NewES384, test.ES384)
}

func Test_ECDSA_ES512(t *testing.T) {
	test.TestAlgorithm(t, NewES512, test.ES512)
}
