/*
CBC (Cipher Block Chaining)
*/

package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"sync"
)

var ivPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 16)
	},
}

// CBCEncrypt encrypts the given plaintext using AES in CBC mode.
// It takes a plaintext string, a key in byte format, and an initialization vector (IV).
// It returns the encrypted message as a base64-encoded string or an error if something goes wrong.
func CBCEncrypt(plaintext string, keyBytes []byte, iv []byte) (string, error) {
	{
		block, err := aes.NewCipher(keyBytes)
		if err != nil {
			return "", err
		}

		mode := cipher.NewCBCEncrypter(block, iv)
		paddedPlaintext := pad([]byte(plaintext), aes.BlockSize)
		ciphertext := make([]byte, len(paddedPlaintext))
		mode.CryptBlocks(ciphertext, paddedPlaintext)

		return base64.StdEncoding.EncodeToString(ciphertext), nil
	}
}

// CBCDecrypt decrypts a base64-encoded encrypted message using AES in CBC mode.
// It takes the encrypted message as a string, along with the key and IV.
// It returns the decrypted plaintext or an error if something goes wrong.
func CBCDecrypt(encryptedMessage string, keyBytes []byte, iv []byte) (string, error) {
	{
		ciphertext, err := base64.StdEncoding.DecodeString(encryptedMessage)
		if err != nil {
			return "", err
		}

		block, err := aes.NewCipher(keyBytes)
		if err != nil {
			return "", err
		}

		mode := cipher.NewCBCDecrypter(block, iv)
		decrypted := make([]byte, len(ciphertext))
		mode.CryptBlocks(decrypted, ciphertext)
		unPaddedDecrypted := unPad(decrypted)

		return string(unPaddedDecrypted), nil
	}
}

// IV generates a new random initialization vector (IV) for use in encryption.
// It returns the IV as a byte slice or an error if something goes wrong.
// Use a new IV for each encryption to ensure security.
// Use the same IV that was used during encryption to decrypt the corresponding ciphertext.
func IV() ([]byte, error) {
	{
		iv := ivPool.Get().([]byte)
		_, err := io.ReadFull(rand.Reader, iv)
		if err != nil {
			ivPool.Put(iv)
			return nil, err
		}
		defer ivPool.Put(iv)
		return iv, nil
	}
}

// pad adds padding to ensure that the input byte slice is a multiple of blockSize.
// It returns the padded byte slice.
func pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

// unPad removes padding from the input byte slice.
// It returns the unPadded byte slice containing original data.
func unPad(src []byte) []byte {
	length := len(src)
	unPadding := int(src[length-1])
	return src[:(length - unPadding)]
}
