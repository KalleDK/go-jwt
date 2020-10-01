package test

import (
	"crypto"
	"encoding/base64"
	"net/url"
	"reflect"
	"testing"

	"github.com/KalleDK/go-jwt/jwt"
)

// #region Helpers

type noneReader struct{}

func (r noneReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

/*
func pubKey(data string) crypto.PublicKey {
	block, _ := pem.Decode([]byte(data))
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatal("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	return pub
}

func privKey(data string) crypto.PrivateKey {
	block, _ := pem.Decode([]byte(data))
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Fatal("failed to decode PEM block containing private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		b, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			log.Fatal(err)
		}
		block := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: b,
		}
		err = pem.Encode(os.Stdout, block)
		if err != nil {
			log.Fatal(err)
		}
		log.Fatal("update key")
	}

	return priv
}
*/
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

type JWAFixtures map[jwt.Algorithm]JWAFixture
type JWAFixture struct {
	Private     crypto.PrivateKey
	PrivateCert string
	Public      crypto.PublicKey
	PublicCert  string
	Header      string
	Signatures  map[string]string
}

func TestFixtures(t *testing.T, fixtures JWAFixtures) {

	payloads := map[string]string{
		"Short":  "e30",
		"Medium": "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		"Long":   "eyJleHRyYSI6IkxvcmVtIElwc3VtIGlzIHNpbXBseSBkdW1teSB0ZXh0IG9mIHRoZSBwcmludGluZyBhbmQgdHlwZXNldHRpbmcgaW5kdXN0cnkuIExvcmVtIElwc3VtIGhhcyBiZWVuIHRoZSBpbmR1c3RyeSdzIHN0YW5kYXJkIGR1bW15IHRleHQgZXZlciBzaW5jZSB0aGUgMTUwMHMsIHdoZW4gYW4gdW5rbm93biBwcmludGVyIHRvb2sgYSBnYWxsZXkgb2YgdHlwZSBhbmQgc2NyYW1ibGVkIGl0IHRvIG1ha2UgYSB0eXBlIHNwZWNpbWVuIGJvb2suIEl0IGhhcyBzdXJ2aXZlZCBub3Qgb25seSBmaXZlIGNlbnR1cmllcywgYnV0IGFsc28gdGhlIGxlYXAgaW50byBlbGVjdHJvbmljIHR5cGVzZXR0aW5nLCByZW1haW5pbmcgZXNzZW50aWFsbHkgdW5jaGFuZ2VkLiBJdCB3YXMgcG9wdWxhcmlzZWQgaW4gdGhlIDE5NjBzIHdpdGggdGhlIHJlbGVhc2Ugb2YgTGV0cmFzZXQgc2hlZXRzIGNvbnRhaW5pbmcgTG9yZW0gSXBzdW0gcGFzc2FnZXMsIGFuZCBtb3JlIHJlY2VudGx5IHdpdGggZGVza3RvcCBwdWJsaXNoaW5nIHNvZnR3YXJlIGxpa2UgQWxkdXMgUGFnZU1ha2VyIGluY2x1ZGluZyB2ZXJzaW9ucyBvZiBMb3JlbSBJcHN1bS4ifQ",
	}

	for algc, fixture := range fixtures {
		t.Run(algc.String(), func(t *testing.T) {
			for name, body := range payloads {
				t.Run(name, func(t *testing.T) {
					payload := fixture.Header + "." + body
					signature := fixture.Signatures[name]
					t.Run("Sign", func(t *testing.T) {
						alg := algc.New()
						data := []byte(payload)
						n, err := alg.Write(data)
						if err != nil {
							t.Errorf("%s.Write() error = %v", algc.String(), err)
							return
						}
						if n != len(data) {
							t.Errorf("%s.Write() wrote %d want %d", algc.String(), n, len(data))
							return
						}

						rawSignature, err := alg.Sign(noneReader{}, fixture.Private)
						if err != nil {
							t.Errorf("%s.Sign() error = %v", algc.String(), err)
							return
						}
						gotSignature := enc(rawSignature)
						wantSignature := signature
						if !reflect.DeepEqual(gotSignature, wantSignature) {
							t.Errorf("%s.Sign() Signature \ngot  = %s, \nwant = %s", algc.String(), gotSignature, wantSignature)
							t.Errorf("GOT %s", makeLink(payload, gotSignature, fixture.PublicCert))
							t.Errorf("WANT %s", makeLink(payload, wantSignature, fixture.PublicCert))
						}
					})
					t.Run("Verify", func(t *testing.T) {
						alg := algc.New()
						data := []byte(payload)
						n, err := alg.Write(data)

						if err != nil {
							t.Errorf("%s.Write() error = %v", algc.String(), err)
							return
						}
						if n != len(data) {
							t.Errorf("%s.Write() wrote %d want %d", algc.String(), n, len(data))
							return
						}

						err = alg.Verify(dec(signature), fixture.Public)
						if err != nil {
							t.Errorf("%s.Verify() error = %v", algc.String(), err)
							t.Errorf("GOT %s", makeLink(payload, signature, fixture.PublicCert))
							return
						}
					})
				})
			}

		})

	}
}
