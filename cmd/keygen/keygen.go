package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
)

type noneReader struct{}

func (r noneReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

func toInt(s string) *big.Int {
	t, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("invalid bigint")
	}
	return t
}

func printPriv(w io.Writer, priv crypto.PrivateKey) {
	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatal(err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}
	err = pem.Encode(w, block)
	if err != nil {
		log.Fatal(err)
	}
}

func printPub(w io.Writer, pub crypto.PublicKey) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatal(err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	}
	err = pem.Encode(w, block)
	if err != nil {
		log.Fatal(err)
	}
}

func makeEC(w io.Writer, c elliptic.Curve) {
	priv, _ := ecdsa.GenerateKey(c, noneReader{})

	fmt.Println("===================================================")
	fmt.Println("Curve: " + c.Params().Name)
	fmt.Println("X: " + priv.X.String())
	fmt.Println("Y: " + priv.Y.String())
	fmt.Println("D: " + priv.D.String())

	printPriv(w, priv)
	printPub(w, &priv.PublicKey)

}

func makeRSA(w io.Writer, bits int) {
	priv, _ := rsa.GenerateKey(rand.Reader, bits)
	fmt.Println("===================================================")
	fmt.Printf("Bits: %d\n", bits)
	fmt.Printf("E: %d\n", priv.E)
	fmt.Println("N: " + priv.N.String())
	fmt.Println("D: " + priv.D.String())
	fmt.Println("P0: " + priv.Primes[0].String())
	fmt.Println("P1: " + priv.Primes[1].String())
	fmt.Println("Dp: " + priv.Precomputed.Dp.String())
	fmt.Println("Dq: " + priv.Precomputed.Dq.String())
	fmt.Println("Qinv: " + priv.Precomputed.Qinv.String())

	printPriv(w, priv)
	printPub(w, &priv.PublicKey)

}

func main() {
	out := os.Stdout
	//makeEC(out, elliptic.P256())
	//makeEC(out, elliptic.P384())
	//makeEC(out, elliptic.P521())
	makeRSA(out, 640)

}
