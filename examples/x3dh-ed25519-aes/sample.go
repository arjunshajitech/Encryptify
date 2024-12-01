package main

import (
	"fmt"
	"github.com/arjunshajitech/encryptify/aes"
	"github.com/arjunshajitech/encryptify/curve"
	"github.com/arjunshajitech/encryptify/ecdh"
)

func main() {

	text := "Hello World!"
	fmt.Println("Raw text : ", text)
	iv, _ := aes.IV()
	salt, _ := ecdh.Salt()

	// Alice Generate key pairs in client side
	// Share to server - public key of (identity,signedPreKey,oneTimePreKey,signingKey) and signedIdentityKey
	c := curve.P256()
	aliceIdentityKeyPair, _ := ecdh.NewECDHKeyPair(c)
	aliceSignedPreKey, _ := ecdh.NewECDHKeyPair(c)
	aliceOneTimeKeyPair, _ := ecdh.NewECDHKeyPair(c)

	bobIdentityKeyPair, _ := ecdh.NewECDHKeyPair(c)
	bobEphemeralKeyPair, _ := ecdh.NewECDHKeyPair(c)

	dh1, _ := ecdh.ECDH(bobIdentityKeyPair.PrivateKey, aliceSignedPreKey.PublicKey)
	dh2, _ := ecdh.ECDH(bobEphemeralKeyPair.PrivateKey, aliceIdentityKeyPair.PublicKey)
	dh3, _ := ecdh.ECDH(bobEphemeralKeyPair.PrivateKey, aliceSignedPreKey.PublicKey)
	dh4, _ := ecdh.ECDH(bobEphemeralKeyPair.PrivateKey, aliceOneTimeKeyPair.PublicKey)

	bobSharedSecret, _, _ := ecdh.X3DH(dh1, dh2, dh3, dh4, salt, ecdh.Bytes32)
	encryptedText, _ := aes.CBCEncrypt(text, bobSharedSecret, iv)
	fmt.Println("Encrypted message: ", encryptedText)

	dh5, _ := ecdh.ECDH(aliceSignedPreKey.PrivateKey, bobIdentityKeyPair.PublicKey)
	dh6, _ := ecdh.ECDH(aliceIdentityKeyPair.PrivateKey, bobEphemeralKeyPair.PublicKey)
	dh7, _ := ecdh.ECDH(aliceSignedPreKey.PrivateKey, bobEphemeralKeyPair.PublicKey)
	dh8, _ := ecdh.ECDH(aliceOneTimeKeyPair.PrivateKey, bobEphemeralKeyPair.PublicKey)

	aliceSharedSecret, _, _ := ecdh.X3DH(dh5, dh6, dh7, dh8, salt, ecdh.Bytes32)
	decryptedText, _ := aes.CBCDecrypt(encryptedText, aliceSharedSecret, iv)
	fmt.Println("Decrypted message: ", decryptedText)
}
