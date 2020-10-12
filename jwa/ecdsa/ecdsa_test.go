package ecdsa

import (
	"testing"

	_ "crypto/sha256"

	"github.com/KalleDK/go-jwt/jwa/test"
)

func Test_ECDSA(t *testing.T) {
	test.TestAlgorithms(t, test.EC256, test.EC384, test.EC512)
}
