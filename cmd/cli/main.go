package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/rand"
	"os"

	_ "github.com/KalleDK/go-jwt/jwa/ecdsa"
	_ "github.com/KalleDK/go-jwt/jwa/none"
	"github.com/KalleDK/go-jwt/jwt"
)

var pubPEMData = []byte(`-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ
PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47
6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM
Al8G7CqwoJOsW7Kddns=
-----END PUBLIC KEY-----`)

var privPEMData = []byte(`-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBiyAa7aRHFDCh2qga9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx
0pDrmCV9mbroFtfEa0XVfKuMAxxfZ6LM/yKgBwYFK4EEACOhgYkDgYYABAGBzgdn
P798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPNv3SchO0lRw9Ru86x1khnVDx+
duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrearjMiZNE25pT2yWP1NUndJxPcv
VtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12ew==
-----END EC PRIVATE KEY-----`)

var tokenData = []byte(`eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InhaRGZacHJ5NFA5dlpQWnlHMmZOQlJqLTdMejVvbVZkbTd0SG9DZ1NOZlkifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AP_CIMClixc5-BFflmjyh_bRrkloEvwzn8IaWJFfMz13X76PGWF0XFuhjJUjp7EYnSAgtjJ-7iJG4IP7w3zGTBk_AUdmvRCiWp5YAe8S_Hcs8e3gkeYoOxiXFZlSSAx0GfwW1cZ0r67mwGtso1I3VXGkSjH5J0Rk6809bn25GoGRjOPu`)

func getPubKey() crypto.PublicKey {
	block, _ := pem.Decode(pubPEMData)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatal("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	return pub
}

func decodeSegment(data []byte) ([]byte, error) {
	m := base64.RawURLEncoding.DecodedLen(len(data))
	b := make([]byte, m)
	n, err := base64.RawURLEncoding.Decode(b, data)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}

func verifytest() {
	idx := bytes.LastIndex(tokenData, []byte{'.'})
	signed := tokenData[:idx]
	signature, err := decodeSegment(tokenData[idx+1:])
	if err != nil {
		log.Fatal(err)
	}

	pubkey := getPubKey()

	v := jwt.ES512.NewVerifier("KID", pubkey)
	if _, err := v.Verify(jwt.ES512, "KID", signed, signature); err != nil {
		log.Fatal(err)
	}

	fmt.Println("verified")
}

func genKeys() (crypto.PrivateKey, crypto.PublicKey) {
	s := rand.NewSource(1)
	r := rand.New(s)
	key, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		log.Fatal(err)
	}

	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}

	if err := pem.Encode(os.Stdout, block); err != nil {
		log.Fatal(err)
	}

	fmt.Println()

	b, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	}

	if err := pem.Encode(os.Stdout, block); err != nil {
		log.Fatal(err)
	}

	return key, &key.PublicKey

}

func verify(t []byte, key crypto.PublicKey) {
	v := jwt.ES256.NewVerifier("ES256-01", key)
	//vs := jwt.NewVerifiers(true, v)
	var payload map[string]string
	kid, err := jwt.Unmarshal(t, &payload, v)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(kid)
	fmt.Println(payload)

}

func verifyNone(t []byte) {
	v := jwt.None.NewVerifier("N01", nil)
	//vs := jwt.NewVerifiers(true, v)
	var payload map[string]string
	kid, err := jwt.Unmarshal(t, &payload, v)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(kid)
	fmt.Println(payload)

}

func sign(priv crypto.PrivateKey) []byte {
	s := rand.NewSource(0)
	r := rand.New(s)
	signer := jwt.ES256.NewSigner("ES256-01", priv)
	payload := map[string]string{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  "1516239022",
	}
	b, err := jwt.Marshal(r, payload, signer)
	if err != nil {
		log.Fatal(err)
	}
	os.Stdout.Write([]byte{'\n'})
	os.Stdout.Write(b)
	os.Stdout.Write([]byte{'\n'})
	os.Stdout.Write([]byte{'\n'})
	return b

}

func signNone() []byte {
	signer := jwt.None.NewSigner("N01", nil)
	payload := map[string]string{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  "1516239022",
	}
	b, err := jwt.Marshal(nil, payload, signer)
	if err != nil {
		log.Fatal(err)
	}
	os.Stdout.Write([]byte{'\n'})
	os.Stdout.Write(b)
	os.Stdout.Write([]byte{'\n'})
	os.Stdout.Write([]byte{'\n'})
	return b

}

func main() {
	verifytest()
	priv, pub := genKeys()
	t1 := sign(priv)
	verify(t1, pub)
	t2 := signNone()
	verifyNone(t2)
}
