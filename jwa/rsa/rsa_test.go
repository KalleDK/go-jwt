package rsa

import (
	"testing"

	_ "crypto/sha256"

	"github.com/KalleDK/go-jwt/jwa/test"
)

func Test_RSA(t *testing.T) {
	test.TestAlgorithms(t, test.RS256, test.RS384, test.RS512)
}

func Test_RSA_RS256(t *testing.T) {
	test.TestAlgorithm(t, NewRS256A, test.RS256)
}

func Test_RSA_RS384(t *testing.T) {
	test.TestAlgorithm(t, NewRS384A, test.RS384)
}

func Test_RSA_RS512(t *testing.T) {
	test.TestAlgorithm(t, NewRS512A, test.RS512)
}
