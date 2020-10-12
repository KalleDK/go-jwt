package test

import (
	"encoding/base64"
	"errors"
	"net/url"
	"reflect"
	"testing"
)

// #region Helpers

type noneReader struct{}

func (r noneReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

func enc(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func dec(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic("decode error")
	}
	return b
}

func makeLink(token string, signature string, key string) string {
	base := "https://jwt.io/#debugger-io"
	pubkey := url.Values{
		"publicKey": []string{key},
	}
	tok := url.Values{
		"token": []string{token + "." + signature},
	}
	return base + "?" + tok.Encode() + "&" + pubkey.Encode()
}

// #endregion Helpers

func TestAlgorithms(t *testing.T, keytestss ...[]keytest) {

	for _, keytests := range keytestss {
		for _, key := range keytests {
			alg := key.alg
			t.Run(alg.String()+"_"+key.text, func(t *testing.T) {
				if !alg.Available() {
					t.Fatalf("Alg: %s is not available", alg.String())
				}
				for name, body := range payloads {
					t.Run(name, func(t *testing.T) {
						payload := headers[alg] + "." + body
						signature := key.signatures[name]
						fail := len(signature) == 0
						t.Run("Sign", func(t *testing.T) {
							signer := alg.New()
							data := []byte(payload)
							n, err := signer.Write(data)
							if err != nil {
								t.Errorf("%s.Write() error = %v", alg.String(), err)
								return
							}
							if n != len(data) {
								t.Errorf("%s.Write() wrote %d want %d", alg.String(), n, len(data))
								return
							}

							rawSignature, err := signer.Sign(noneReader{}, key.priv)
							if (err != nil) != fail {
								if fail {
									err = errors.New("should have failed")
									t.Errorf("GOT %s", makeLink(payload, enc(rawSignature), key.pubCert))
								}
								t.Errorf("%s.Sign() error = %v", alg.String(), err)
								return
							}
							gotSignature := enc(rawSignature)
							wantSignature := signature
							if !reflect.DeepEqual(gotSignature, wantSignature) {
								t.Errorf("%s.Sign() Signature \ngot  = %s, \nwant = %s", alg.String(), gotSignature, wantSignature)
								t.Errorf("GOT %s", makeLink(payload, gotSignature, key.pubCert))
								t.Errorf("WANT %s", makeLink(payload, wantSignature, key.pubCert))
							}
						})
						t.Run("Verify", func(t *testing.T) {
							signer := alg.New()
							data := []byte(payload)
							n, err := signer.Write(data)

							if err != nil {
								t.Errorf("%s.Write() error = %v", alg.String(), err)
								return
							}
							if n != len(data) {
								t.Errorf("%s.Write() wrote %d want %d", alg.String(), n, len(data))
								return
							}

							err = signer.Verify(dec(signature), key.pub)
							if (err != nil) != fail {
								if fail {
									err = errors.New("should have failed")
								}
								t.Errorf("%s.Verify() error = %v", alg.String(), err)
								t.Errorf("GOT %s", makeLink(payload, signature, key.pubCert))
								return
							}
						})
					})
				}

			})
		}
	}
}
