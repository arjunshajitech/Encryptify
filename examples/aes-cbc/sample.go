package main

import (
	"fmt"
	"github.com/arjunshajitech/encryptify/aes"
)

func main() {

	// 128-bit AES Key (16 bytes)
	key := []byte("2b7e151628aed2a6abf7158809cf4f3c")

	rawText := "Hello World!" // The message to be encrypted
	fmt.Println("Raw text : ", rawText)

	// Use a new IV for each encryption to ensure security.
	// Use the same IV that was used during encryption to decrypt the corresponding ciphertext.
	iv, err := aes.IV()
	if err != nil {
		panic(err)
	}

	encryptedMessage, err := aes.CBCEncrypt(rawText, key, iv)
	if err != nil {
		panic(err)
	}

	fmt.Println("Encrypted message : ", encryptedMessage)

	decryptedMessage, err := aes.CBCDecrypt(encryptedMessage, key, iv)
	if err != nil {
		panic(err)
	}

	fmt.Println("Decrypted message : ", decryptedMessage)
}
