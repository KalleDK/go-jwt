package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"

	"gopkg.in/yaml.v2"
)

type noneReader struct{}

func (r noneReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

type oneReader struct{}

var y = true

func (r oneReader) Read(b []byte) (int, error) {
	if len(b) == 1 {
		b[0] = 0
		return 1, nil
	}
	f1, _ := new(big.Int).SetString("FE976C1E6E7A0EE9", 16)
	f2, _ := new(big.Int).SetString("C3355312968D3643", 16)
	if y {
		y = false
		copy(b, f1.Bytes())
	} else {
		y = true
		copy(b, f2.Bytes())
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
	priv, _ := rsa.GenerateKey(oneReader{}, bits)
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

func newBig(s string, i int) *big.Int {
	t, ok := new(big.Int).SetString(s, i)
	if !ok {
		panic("invalid bigint")
	}
	return t
}

type soneReader struct{}

func (r soneReader) Read(b []byte) (int, error) {
	j, _ := hex.DecodeString("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60")
	copy(b, j)
	return len(b), nil
}

type RSAData struct {
	E string `yaml:"E"`
	N string `yaml:"N"`
	D string `yaml:"D"`
}

type Keys struct {
	ECDSA string             `yaml:"ECDSA"`
	RSA   map[string]RSAData `yaml:"RSA"`
}

func main() {
	out := os.Stdout
	//makeEC(out, elliptic.P256())
	//makeEC(out, elliptic.P384())
	//makeEC(out, elliptic.P521())
	makeRSA(out, 128)

	fp, err := os.Open("keys.yml")
	if err != nil {
		log.Fatal(err)
	}
	dec := yaml.NewDecoder(fp)

	m := Keys{}

	err = dec.Decode(&m)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("--- k:\n%v\n\n", m)

	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     newBig("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16),
			Y:     newBig("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16),
		},
		D: newBig("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16),
	}

	msg, _ := hex.DecodeString("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF")
	r, s, err := ecdsa.Sign(soneReader{}, key, msg)
	fmt.Fprintf(out, "%x\n", r)
	fmt.Fprintf(out, "%x\n", s)
	fmt.Fprintf(out, "%x\n", key.Params().N)
	fmt.Fprintln(out, err)

}
