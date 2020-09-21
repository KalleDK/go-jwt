package jwt

import "bytes"

type tokenBuffer struct {
	buffer         []byte
	headerSlice    []byte
	payloadSlice   []byte
	signedSlice    []byte
	signatureSlice []byte
}

func newTokenBuffer(headerSize int, payloadSize int, signatureSize int) tokenBuffer {
	encHS := encodedSegmentLength(headerSize)
	encPS := encodedSegmentLength(payloadSize)
	encHPS := encHS + 1 + encPS
	encSS := encodedSegmentLength(signatureSize)
	encBS := encHPS + 1 + encSS
	buffer := make([]byte, encBS)
	buffer[encHS] = '.'
	buffer[encHPS] = '.'
	return tokenBuffer{
		buffer:         buffer,
		headerSlice:    buffer[:encHS],
		payloadSlice:   buffer[encHS+1 : encHPS],
		signedSlice:    buffer[:encHPS],
		signatureSlice: buffer[encHPS+1:],
	}
}

func parseTokenBuffer(b []byte) (tokenBuffer, error) {
	idx1 := bytes.Index(b[:], []byte{'.'})
	idx2 := bytes.Index(b[idx1+1:], []byte{'.'}) + idx1 + 1

	// Verify no more dots
	if bytes.Index(b[idx2+1:], []byte{'.'}) > 0 {
		return tokenBuffer{}, ErrMalformedToken
	}

	return tokenBuffer{
		buffer:         b,
		headerSlice:    b[:idx1],
		payloadSlice:   b[idx1+1 : idx2],
		signedSlice:    b[:idx2],
		signatureSlice: b[idx2+1:],
	}, nil

}
