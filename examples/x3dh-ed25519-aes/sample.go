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
	var salt []byte

	// Alice Generate key pairs in client side
	// Share to server - public key of (identity,signedPreKey,oneTimePreKey,signingKey) and signedIdentityKey
	c := curve.P256()
	aliceIdentityKeyPair, _ := ecdh.NewECDHKeyPair(c)
	aliceSignedPreKey, _ := ecdh.NewECDHKeyPair(c)
	aliceOneTimeKeyPair, _ := ecdh.NewECDHKeyPair(c)
	aliceSigningKeyPair, _ := ed25519.NewED25519KeyPair()
	aliceSignature := ed25519.SignMessage(aliceSigningKeyPair.PrivateKey, aliceIdentityKeyPair.PublicKey.Bytes())

	// Bob fetch alice key paris from server
	// First verify authenticity
	// Second perform X3DH
	// Bob share public key (EphemeralKey,signingKey) and encryptedMessage
	v1 := ed25519.VerifySignedMessage(aliceSigningKeyPair.PublicKey, aliceIdentityKeyPair.PublicKey.Bytes(), aliceSignature)
	if v1 {
		// if true continue
	}

	bobEphemeralKeyPair, _ := ecdh.NewECDHKeyPair(c)
	bobSigningKeyPair, _ := ed25519.NewED25519KeyPair()
	bobSignature := ed25519.SignMessage(bobSigningKeyPair.PrivateKey, bobEphemeralKeyPair.PublicKey.Bytes())

	dh1, _ := ecdh.ECDH(bobEphemeralKeyPair.PrivateKey, aliceIdentityKeyPair.PublicKey)
	dh2, _ := ecdh.ECDH(bobEphemeralKeyPair.PrivateKey, aliceSignedPreKey.PublicKey)
	dh3, _ := ecdh.ECDH(bobEphemeralKeyPair.PrivateKey, aliceOneTimeKeyPair.PublicKey)

	salt, _ = ecdh.Salt()
	bobSharedSecret, _, _ := ecdh.X3DH(dh1, dh2, dh3, salt, ecdh.Bytes32)

	iv, _ = aes.IV()
	encryptedText, _ := aes.CBCEncrypt(text, bobSharedSecret, iv)
	fmt.Println("Encrypted message: ", encryptedText)

	// Alice verify authenticity and perform X3DH
	v2 := ed25519.VerifySignedMessage(bobSigningKeyPair.PublicKey, bobEphemeralKeyPair.PublicKey.Bytes(), bobSignature)
	if v2 {
		// continue
	}

	dh4, _ := ecdh.ECDH(aliceIdentityKeyPair.PrivateKey, bobEphemeralKeyPair.PublicKey)
	dh5, _ := ecdh.ECDH(aliceSignedPreKey.PrivateKey, bobEphemeralKeyPair.PublicKey)
	dh6, _ := ecdh.ECDH(aliceOneTimeKeyPair.PrivateKey, bobEphemeralKeyPair.PublicKey)

	aliceSharedSecret, _, _ := ecdh.X3DH(dh4, dh5, dh6, salt, ecdh.Bytes32)
	decryptedText, _ := aes.CBCDecrypt(encryptedText, aliceSharedSecret, iv)
	fmt.Println("Decrypted message: ", decryptedText)
}
