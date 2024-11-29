package main

import (
	"fmt"
	"github.com/arjunshajitech/encryptify/aes"
	"github.com/arjunshajitech/encryptify/curve"
	"github.com/arjunshajitech/encryptify/ecdh"
	"github.com/arjunshajitech/encryptify/ed25519"
)

func main() {

	text := "Hello World!"
	fmt.Println("Raw text : ", text)
	var iv []byte
	var encryptedText string

	//Alice Generate key pairs in client side
	c := curve.P256()
	aliceECDHKeyPairs, _ := ecdh.NewECDHKeyPair(c)
	aliceED25519KeyPairs, _ := ed25519.NewED25519KeyPair()
	aliceSignedKey := ed25519.SignMessage(aliceED25519KeyPairs.PrivateKey, aliceECDHKeyPairs.PublicKey.Bytes())

	//Bob Generate in key pairs client side
	bobECDHKeyPairs, _ := ecdh.NewECDHKeyPair(c)
	bobED25519KeyPairs, _ := ed25519.NewED25519KeyPair()
	bobSignedKey := ed25519.SignMessage(bobED25519KeyPairs.PrivateKey, bobECDHKeyPairs.PublicKey.Bytes())

	//Alice push both public keys (ecdh-aes and ed25519) and signed key to server
	//Bob push both public keys (ecdh-aes and ed25519)  and signed key to server

	//Alice verify bob keys,if ture generate shared secret
	v1 := ed25519.VerifySignedMessage(aliceED25519KeyPairs.PublicKey, aliceECDHKeyPairs.PublicKey.Bytes(), aliceSignedKey)
	if v1 {
		iv, _ = aes.IV()
		aliceSharedSecret, _ := ecdh.ECDH(aliceECDHKeyPairs.PrivateKey, bobECDHKeyPairs.PublicKey)
		encryptedText, _ = aes.CBCEncrypt(text, aliceSharedSecret, iv)
		fmt.Println("Encrypted message: ", encryptedText)
	}

	//Alice verify bob keys,if ture generate shared secret
	v2 := ed25519.VerifySignedMessage(bobED25519KeyPairs.PublicKey, bobECDHKeyPairs.PublicKey.Bytes(), bobSignedKey)
	if v2 {
		bobSharedSecret, _ := ecdh.ECDH(bobECDHKeyPairs.PrivateKey, aliceECDHKeyPairs.PublicKey)
		decryptedText, _ := aes.CBCDecrypt(encryptedText, bobSharedSecret, iv)
		fmt.Println("Decrypted message: ", decryptedText)
	}

}
