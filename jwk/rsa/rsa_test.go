package rsa

import (
	"reflect"
	"testing"

	_ "crypto/sha256"

	_ "github.com/KalleDK/go-jwt/jwa/rsa"

	"github.com/KalleDK/go-jwt/jwk"
	"github.com/KalleDK/go-jwt/jwt"
)

type norand struct{}

func (r norand) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

func TestParseSigner(t *testing.T) {
	type args struct {
		data []byte
		b    []byte
	}
	tests := []struct {
		name          string
		args          args
		wantSignature []byte
		wantAlgorithm jwt.Algorithm
		wantKeyID     string
		wantErr       bool
	}{
		{
			name: "basic fail",
			args: args{
				b: []byte(`{"kty":"RSA",
				"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e":"AQAB",
				"d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
				"p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
				"q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
				"dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
				"dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
				"qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
				"alg":"RS256",
				"key_ops": ["sign"],
				"kid":"2011-04-29"}`),
				data: []byte("flaf"),
			},
			wantKeyID:     "2011-04-29",
			wantSignature: []byte("\x00.\x15\x95\xe2\t\x1d\x8ai2πH\xb9Zgq\xad\xb40\x94L\r=\x11ˠ\xdcLi\xfa\xa6\xe5\xa3\xfa\xd1b\xeaG\xffz\xdaq\a\x9b\xc4;\xf5\x87\xe2\x19\x84\xe4\xa4\xdd\xe6|3i\xa5\xaa\x1es\x991\x95\r\xeao\x97\xe8\xf9c\xa9i\x81\xe7\xea\xbf\xfe\x1e*'>@C\x1e\xf2\xb0\xbb\x06\xe4\xf4P.!\xf38\x97T\xb6? @,\x9c\x1d\x89:u1\xdd\xff\xc3\x0fFޑoU\xf0\xa7hɺ\xc8\xe0\x1c\x0e\xac\x82\x88\xaf\x06\xa6\x00EC\x92t\n\x12s\xa1IQ\xa2?\x16\xc2\xd7\xd9ԭ\xeb٠\x0fD\x83h\x0f%MKu\x8c\xdc\xec\x82\n:y\xa1\x1fyv\xfc\xc6Uݏu\xd8(ptk-\xf6S[\xb2!`?\x12\x1c\xe5c\xbfI\xc9,\xa2\xaf\xe6A+>\xe8nN\x10\xc6\xd2\xd0'\xc5#\x96\x15ý\x0ft\xe6\x17\xc3(\xb2\xb0K~(\xcb\v\xf1ֽDP\xba9\x15\U000a74c7f}~3Ƶ!"),
			wantAlgorithm: jwt.RS256,
			wantErr:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSigner, err := jwk.ParseSigner(tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			gotKeyID := gotSigner.KeyID()
			if !reflect.DeepEqual(gotKeyID, tt.wantKeyID) {
				t.Errorf("ParseSigner() = %v, want %v", gotKeyID, tt.wantKeyID)
			}
			gotAlgorithm := gotSigner.Algorithm()
			if !reflect.DeepEqual(gotAlgorithm, tt.wantAlgorithm) {
				t.Errorf("ParseSigner() = %v, want %v", gotAlgorithm.String(), tt.wantAlgorithm.String())
			}
			gotSignature, err := gotSigner.Sign(norand{}, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSigner() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(gotSignature, tt.wantSignature) {
				t.Errorf("ParseSigner() = %+#v, want %#v", string(gotSignature), string(tt.wantSignature))
			}
		})
	}
}

func TestParseVerifier(t *testing.T) {
	type args struct {
		alg       jwt.Algorithm
		kid       string
		data      []byte
		b         []byte
		signature []byte
	}
	tests := []struct {
		name             string
		args             args
		wantVerification bool
		wantAlgorithm    jwt.Algorithm
		wantKeyID        string
		wantErr          bool
		wantKidUsed      string
	}{
		{
			name: "basic fail",
			args: args{
				b: []byte(`{"kty":"RSA",
				"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e":"AQAB",
				"alg":"RS256",
				"key_ops": ["verify"],
				"kid":"2011-04-29"}`),
				alg:       jwt.RS256,
				kid:       "2011-04-29",
				data:      []byte("flaf"),
				signature: []byte("\x00.\x15\x95\xe2\t\x1d\x8ai2πH\xb9Zgq\xad\xb40\x94L\r=\x11ˠ\xdcLi\xfa\xa6\xe5\xa3\xfa\xd1b\xeaG\xffz\xdaq\a\x9b\xc4;\xf5\x87\xe2\x19\x84\xe4\xa4\xdd\xe6|3i\xa5\xaa\x1es\x991\x95\r\xeao\x97\xe8\xf9c\xa9i\x81\xe7\xea\xbf\xfe\x1e*'>@C\x1e\xf2\xb0\xbb\x06\xe4\xf4P.!\xf38\x97T\xb6? @,\x9c\x1d\x89:u1\xdd\xff\xc3\x0fFޑoU\xf0\xa7hɺ\xc8\xe0\x1c\x0e\xac\x82\x88\xaf\x06\xa6\x00EC\x92t\n\x12s\xa1IQ\xa2?\x16\xc2\xd7\xd9ԭ\xeb٠\x0fD\x83h\x0f%MKu\x8c\xdc\xec\x82\n:y\xa1\x1fyv\xfc\xc6Uݏu\xd8(ptk-\xf6S[\xb2!`?\x12\x1c\xe5c\xbfI\xc9,\xa2\xaf\xe6A+>\xe8nN\x10\xc6\xd2\xd0'\xc5#\x96\x15ý\x0ft\xe6\x17\xc3(\xb2\xb0K~(\xcb\v\xf1ֽDP\xba9\x15\U000a74c7f}~3Ƶ!"),
			},
			wantKidUsed:      "2011-04-29",
			wantVerification: true,
			wantKeyID:        "2011-04-29",
			wantAlgorithm:    jwt.RS256,
			wantErr:          false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVerifier, err := jwk.ParseVerifier(tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseVerifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			gotKeyID := gotVerifier.KeyID()
			if !reflect.DeepEqual(gotKeyID, tt.wantKeyID) {
				t.Errorf("ParseVerifier() = %v, want %v", gotKeyID, tt.wantKeyID)
			}
			gotAlgorithm := gotVerifier.Algorithm()
			if !reflect.DeepEqual(gotAlgorithm, tt.wantAlgorithm) {
				t.Errorf("ParseVerifier() = %v, want %v", gotAlgorithm.String(), tt.wantAlgorithm.String())
			}

			gotKidUsed, err := gotVerifier.Verify(tt.args.alg, tt.args.kid, tt.args.data, tt.args.signature)
			if (err != nil) == tt.wantVerification {
				t.Errorf("ParseVerifier() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(gotKidUsed, tt.wantKidUsed) {
				t.Errorf("ParseVerifier() = %+#v, want %#v", string(gotKidUsed), string(tt.wantKidUsed))
			}
		})
	}
}
