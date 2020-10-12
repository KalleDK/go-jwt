package rsa

import (
	"testing"

	_ "crypto/sha256"

	"github.com/KalleDK/go-jwt/jwa/test"
)

func Test_ECDSA(t *testing.T) {
	test.TestAlgorithms(t, test.RS256, test.RS384, test.RS512)
}
