package util

import "encoding/base64"

func Encode(byte []byte) string {
	return base64.StdEncoding.EncodeToString(byte)
}

func Decode(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
