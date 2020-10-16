package rsa

import (
	"testing"

	_ "crypto/sha256"

	_ "github.com/KalleDK/go-jwt/jwa/rsa"

	"github.com/KalleDK/go-jwt/jwk/test"
	"github.com/KalleDK/go-jwt/jwt"
)

type KeyTest = test.KeyTest
type JWKFixture = test.JWKFixture

func TestRSKeys(t *testing.T) {
	tests := []KeyTest{
		{
			Name: "RS256",
			Args: JWKFixture{
				KeyID:     "2011-04-29",
				Algorithm: jwt.RS256,
				PrivateKey: []byte(`{
					"kid":"2011-04-29",
					"kty":"RSA",
					"key_ops":[
					   "sign"
					],
					"alg":"RS256",
					"e":"AQAB",
					"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
					"d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
					"p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
					"q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
					"dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
					"dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
					"qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU"
				}`),
				PublicKey: []byte(`{
					"kid":"2011-04-29",
					"kty":"RSA",
					"key_ops": [
						"verify"
					],
					"alg":"RS256",
					"e":"AQAB",
					"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
				}`),
				Payload:   []byte(`RandomTextToBeSignedAndVerifyed`),
				Signature: []byte(" :\x9e\x02\x05\xc0\xc6\xc81\xb1Z\xd5\np+\x16\xee\x1e\x12'\xd1\xf4\xfc]bv\xf3惘+%J\x00C\xd0\b\xbd!^s\xa0\xb4}.\xa3\xb1Y\x92\xd9\xeeY i\xdeE\x83\xa4\xc7\xeb\a\x1dEіuV\x89\xe3\xc6lF\xa0\x88ڷ\x10p\x91=\xec\x05.\x03\"C\x19\x05\xb5\xc6#\xe9\x1d.\xf1\x00\xd6cg\xec\t\rY\xf8>dM!\x1d\xb1\x1d\x03\xec\xf9\xc3\xcb\xc9Ő\x13\xf2\xdf\xda]\x8a\xceB\xb8F\xa7z\xedM\xad\x161\x82t\xcft̹S\xe2\x8e\u007f\x04=\x9a\r\xb0HDQ/\xbdN4\x11t$\xbe\x0fk9\xe0\xcdTHA\x15\r?\xdd\xf7\x12`\xbe^\xf0\x9bFeXxT\x861\\N\x06\xc3b-O'\xb0\x9f\u007f\x8d\xf0>\xd9\tw*&\xdc\xed\xe1?\xaf\xa3`2\xe0c\xdb\xef]\xd0dg\x96\xc7qf\x90D\x9a\xad&\x87\x17\xac>O\xd2\xd2|\xd5W\xe1\xa84\xd25\x8c\xaa\x11~\x18?\xdc\xfd^"),
			},
		},
	}
	test.RunKeyTests(t, tests)
}
