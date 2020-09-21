package ecdsa

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"math/rand"
	"testing"

	"github.com/KalleDK/go-jwt/jwt"
)

func Test_ECDSA_Verify(t *testing.T) {
	type args struct {
		alg       jwt.Algorithm
		key       crypto.PublicKey
		data      []byte
		signature []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ES512 Valid",
			args: args{
				alg:       jwt.ES512,
				key:       getPubKey(ES512PubPEM),
				data:      getSigned(ES512Token),
				signature: getSignature(ES512Token),
			},
			wantErr: false,
		},
		{
			name: "ES512 Invalid",
			args: args{
				alg:       jwt.ES512,
				key:       getPubKey(ES512PubPEM),
				data:      getSigned(ES512TokenInvalid),
				signature: getSignature(ES512TokenInvalid),
			},
			wantErr: true,
		},
		{
			name: "ES384 Valid",
			args: args{
				alg:       jwt.ES384,
				key:       getPubKey(ES384PubPEM),
				data:      getSigned(ES384Token),
				signature: getSignature(ES384Token),
			},
			wantErr: false,
		},
		{
			name: "ES384 Invalid",
			args: args{
				alg:       jwt.ES384,
				key:       getPubKey(ES384PubPEM),
				data:      getSigned(ES384TokenInvalid),
				signature: getSignature(ES384TokenInvalid),
			},
			wantErr: true,
		},
		{
			name: "ES256 Valid",
			args: args{
				alg:       jwt.ES256,
				key:       getPubKey(ES256PubPEM),
				data:      getSigned(ES256Token),
				signature: getSignature(ES256Token),
			},
			wantErr: false,
		},
		{
			name: "ES256 Invalid",
			args: args{
				alg:       jwt.ES256,
				key:       getPubKey(ES256PubPEM),
				data:      getSigned(ES256TokenInvalid),
				signature: getSignature(ES256TokenInvalid),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := tt.args.alg.NewVerifier(tt.args.key)
			if err := verifier.Verify(tt.args.data, tt.args.signature); (err != nil) != tt.wantErr {
				t.Errorf("%s.Verify() error = %v, wantErr %v", tt.args.alg, err, tt.wantErr)
			}
		})
	}
}

func Test_ECDSA_Sign(t *testing.T) {
	type args struct {
		alg     jwt.Algorithm
		pubkey  crypto.PublicKey
		privkey crypto.PrivateKey
		data    []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ES256 Valid",
			args: args{
				alg:     jwt.ES256,
				pubkey:  getPubKey(ES256PubPEM),
				privkey: getPrivKey(ES256PrivPEM),
				data:    getSigned(ES256Token),
			},
			wantErr: false,
		},
		{
			name: "ES256 Invalid",
			args: args{
				alg:     jwt.ES256,
				pubkey:  getPubKey(ES256PubPEMInvalid),
				privkey: getPrivKey(ES256PrivPEM),
				data:    getSigned(ES256Token),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := rand.NewSource(0)
			r := rand.New(s)
			signer := tt.args.alg.NewSigner(r, tt.args.privkey)
			verifier := tt.args.alg.NewVerifier(tt.args.pubkey)
			signature, err := signer.Sign(tt.args.data)
			if err != nil {
				t.Errorf("%s.Sign() error = %v", tt.args.alg, err)
				return
			}
			if err := verifier.Verify(tt.args.data, signature); (err != nil) != tt.wantErr {
				t.Errorf("%s.Verify() error = %v, wantErr %v", tt.args.alg, err, tt.wantErr)
			}
		})
	}
}

func getPubKey(data []byte) crypto.PublicKey {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatal("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	return pub
}

func getPrivKey(data []byte) crypto.PrivateKey {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Fatal("failed to decode PEM block containing private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	return priv
}

func getSignature(data []byte) []byte {
	idx := bytes.LastIndex(data, []byte{'.'})
	return decodeSegment(data[idx+1:])
}

func getSigned(data []byte) []byte {
	idx := bytes.LastIndex(data, []byte{'.'})
	return data[:idx]
}

func decodeSegment(data []byte) []byte {
	m := base64.RawURLEncoding.DecodedLen(len(data))
	b := make([]byte, m)
	n, err := base64.RawURLEncoding.Decode(b, data)
	if err != nil {
		log.Fatal(err)
	}
	return b[:n]
}

var ES512PubPEM = []byte(`-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ
PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47
6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM
Al8G7CqwoJOsW7Kddns=
-----END PUBLIC KEY-----`)

var ES512Token = []byte(`eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InhaRGZacHJ5NFA5dlpQWnlHMmZOQlJqLTdMejVvbVZkbTd0SG9DZ1NOZlkifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AP_CIMClixc5-BFflmjyh_bRrkloEvwzn8IaWJFfMz13X76PGWF0XFuhjJUjp7EYnSAgtjJ-7iJG4IP7w3zGTBk_AUdmvRCiWp5YAe8S_Hcs8e3gkeYoOxiXFZlSSAx0GfwW1cZ0r67mwGtso1I3VXGkSjH5J0Rk6809bn25GoGRjOPu`)
var ES512TokenInvalid = []byte(`ayJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InhaRGZacHJ5NFA5dlpQWnlHMmZOQlJqLTdMejVvbVZkbTd0SG9DZ1NOZlkifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AP_CIMClixc5-BFflmjyh_bRrkloEvwzn8IaWJFfMz13X76PGWF0XFuhjJUjp7EYnSAgtjJ-7iJG4IP7w3zGTBk_AUdmvRCiWp5YAe8S_Hcs8e3gkeYoOxiXFZlSSAx0GfwW1cZ0r67mwGtso1I3VXGkSjH5J0Rk6809bn25GoGRjOPu`)

var ES384PubPEM = []byte(`-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+
Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii
1D3jaW6pmGVJFhodzC31cy5sfOYotrzF
-----END PUBLIC KEY-----`)

var ES384Token = []byte(`eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImlUcVhYSTB6YkFuSkNLRGFvYmZoa00xZi02ck1TcFRmeVpNUnBfMnRLSTgifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.cJOP_w-hBqnyTsBm3T6lOE5WpcHaAkLuQGAs1QO-lg2eWs8yyGW8p9WagGjxgvx7h9X72H7pXmXqej3GdlVbFmhuzj45A9SXDOAHZ7bJXwM1VidcPi7ZcrsMSCtP1hiN`)
var ES384TokenInvalid = []byte(`ayJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImlUcVhYSTB6YkFuSkNLRGFvYmZoa00xZi02ck1TcFRmeVpNUnBfMnRLSTgifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.cJOP_w-hBqnyTsBm3T6lOE5WpcHaAkLuQGAs1QO-lg2eWs8yyGW8p9WagGjxgvx7h9X72H7pXmXqej3GdlVbFmhuzj45A9SXDOAHZ7bJXwM1VidcPi7ZcrsMSCtP1hiN`)

var ES256PubPEM = []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----`)

var ES256PubPEMInvalid = []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENsSF+IPaz7NjyPZNaoLlZT19NmQr
OhCLUVVajTNAfVxpyVIhT85D6l+AQxC75j4N7svx6bppXax3U7ExvL/zmA==
-----END PUBLIC KEY-----`)

var ES256PrivPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----`)

var ES256Token = []byte(`eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA`)
var ES256TokenInvalid = []byte(`ayJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA`)
