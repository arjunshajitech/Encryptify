package main

import (
	"fmt"
	"github.com/arjunshajitech/encryptify/aes"
	"github.com/arjunshajitech/encryptify/curve"
	"github.com/arjunshajitech/encryptify/ecdh"
)

func main() {

	// Use the P-256 curve for ECDH
	c := curve.P256()

	// Step 1: Both Alice and Bob generate their ECDH key pairs
	aliceKeyPair, _ := ecdh.NewECDHKeyPair(c)
	bobKeyPair, _ := ecdh.NewECDHKeyPair(c)

	// Step 2: Exchange public keys between Alice and Bob
	alicePublicKey := aliceKeyPair.PublicKey // Alice shares this with Bob
	bobPublicKey := bobKeyPair.PublicKey     // Bob shares this with Alice

	// Step 3: Each computes the shared secret
	// Alice uses her private key and Bob's public key
	aliceSharedSecret, _ := ecdh.ECDH(aliceKeyPair.PrivateKey, bobPublicKey)

	// Bob uses his private key and Alice's public key
	bobSharedSecret, _ := ecdh.ECDH(bobKeyPair.PrivateKey, alicePublicKey)

	// Step 4: Encryption and decryption of a message using AES-CBC
	rawText := "Hello World!" // The message to be encrypted
	fmt.Println("Raw text: ", rawText)

	// Generate a new IV for encryption
	iv, err := aes.IV()
	if err != nil {
		panic(err)
	}

	// Encrypt the raw text using the alice shared secret and IV
	encryptedMessage, err := aes.CBCEncrypt(rawText, aliceSharedSecret, iv)
	if err != nil {
		panic(err)
	}

	fmt.Println("Encrypted message: ", encryptedMessage)

	// Decrypt the encrypted message using the bob shared secret and the same IV
	decryptedMessage, err := aes.CBCDecrypt(encryptedMessage, bobSharedSecret, iv)
	if err != nil {
		panic(err)
	}

	fmt.Println("Decrypted message: ", decryptedMessage)
}
