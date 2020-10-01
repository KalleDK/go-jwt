package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
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

type JWAKey struct {
	Private     crypto.PrivateKey
	PrivateCert string
	Public      crypto.PublicKey
	PublicCert  string
}

const jwaKeyStr = `
type JWAKey struct {
	Private     crypto.PrivateKey
	PrivateCert string
	Public      crypto.PublicKey
	PublicCert  string
}
`

func toInt(s string) *big.Int {
	t, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("invalid bigint")
	}
	return t
}

const toIntStr = `
func toInt(s string) *big.Int {
	t := &big.Int{}
	t, ok := t.SetString(s, 10)
	if !ok {
		panic("invalid bigint")
	}

	return t
}
`

const publicKeyStr = `
&ecdsa.PublicKey{
	Curve: elliptic.%s(),
	X:     toInt("%s"),
	Y:     toInt("%s"),
}
`

const privateKeyStr = `
ecdsa.PublicKey{
	Curve: elliptic.%s(),
	X:     toInt("%s"),
	Y:     toInt("%s"),
}
`

const jwaStr = `JWAKey{
	Public: &ecdsa.PublicKey{
		Curve: elliptic.%[1]s(),
		X:     toInt("%[2]s"),
		Y:     toInt("%[3]s"),
	},
	PublicCert: ` + "`%[5]s`" + `,
	Private: &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.%[1]s(),
			X:     toInt("%[2]s"),
			Y:     toInt("%[3]s"),
		},
		D: toInt("%[4]s"),
	},
	PrivateCert: ` + "`%[6]s`" + `,
}`

func main() {
	fp := os.Stdout
	fmt.Fprint(fp, jwaKeyStr)
	fmt.Fprint(fp, toIntStr)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), noneReader{})
	if err != nil {
		panic(err)
	}
	pub := priv.PublicKey
	fmt.Printf(publicKeyStr, "P256", pub.X, pub.Y)

	fmt.Printf(jwaStr, "P256", priv.X, priv.Y, priv.D,
		`fds
fdsa
fd`,
		`fdsfds
dsfdsfdsfds
fdsfdsfds`)

	g := JWAKey{
		Public: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     toInt("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
			Y:     toInt("36134250956749795798585127919587881956611106672985015071877198253568414405109"),
		},
		PublicCert: `fds
fdsa
fd`,
		Private: &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     toInt("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
				Y:     toInt("36134250956749795798585127919587881956611106672985015071877198253568414405109"),
			},
			D: toInt("1"),
		},
		PrivateCert: `fdsfds
dsfdsfdsfds
fdsfdsfds`,
	}
}
