package math

import (
	"encoding/base64"
	"errors"
	"math/big"
)

var b64 = base64.RawURLEncoding

// #region Normal Int

type NormalInt int

func (i NormalInt) ToBase() int { return (int)(i) }

func (i *NormalInt) UnmarshalText(text []byte) error {
	// TODO better conversion
	var v BigInt
	if err := v.UnmarshalText(text); err != nil {
		return err
	}
	if !v.ToBase().IsInt64() {
		return errors.New("is not valid")
	}
	*i = NormalInt(int(v.ToBase().Int64()))
	return nil
}

func (i *NormalInt) MarshalText() (text []byte, err error) {
	// TODO better conversion
	var v BigInt
	v.ToBase().SetInt64(int64(*i))
	return v.MarshalText()
}

// #endregion

// #region Big Int

type BigInt big.Int

func (i *BigInt) ToBase() *big.Int { return (*big.Int)(i) }

func (i *BigInt) Bytes() []byte { return i.ToBase().Bytes() }

func (i *BigInt) SetBytes(b []byte) *BigInt { return (*BigInt)(i.ToBase().SetBytes(b)) }

func (i *BigInt) UnmarshalText(text []byte) error {
	b := make([]byte, b64.DecodedLen(len(text)))
	n, err := b64.Decode(b, text)
	if err != nil {
		return err
	}
	i.SetBytes(b[:n])
	return nil
}

func (i *BigInt) MarshalText() (text []byte, err error) {
	str := base64.RawURLEncoding.EncodeToString(i.Bytes())
	return []byte(str), nil
}

// #endregion

type BigList []*big.Int

func (l BigList) ToBase() []*big.Int { return ([]*big.Int)(l) }
