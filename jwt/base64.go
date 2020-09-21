package jwt

import "encoding/base64"

func decodeSegment(data []byte) ([]byte, error) {
	m := decodedSegmentLength(len(data))
	b := make([]byte, m)
	n, err := base64.RawURLEncoding.Decode(b, data)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}

func decodedSegmentLength(n int) int {
	return base64.RawURLEncoding.DecodedLen(n)
}

func encodeSegment(dst, src []byte) {
	base64.RawURLEncoding.Encode(dst, src)
}

func encodedSegmentLength(n int) int {
	return base64.RawURLEncoding.EncodedLen(n)
}
