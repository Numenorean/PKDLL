package ecb

import (
	"bytes"
	"errors"
)

func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Trimming(encrypt []byte) ([]byte, error) {
	padding := encrypt[len(encrypt)-1]
	if (len(encrypt) - int(padding)) < 0 {
		return nil, errors.New("invalid data")
	}
	return encrypt[:len(encrypt)-int(padding)], nil
}
