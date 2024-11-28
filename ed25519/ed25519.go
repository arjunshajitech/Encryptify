package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
)

type KeyPair struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

func NewED25519KeyPair() (*KeyPair, error) {
	{
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		return &KeyPair{
			privateKey,
			publicKey,
		}, nil
	}
}

func SignMessage(ed25519PrivateKey ed25519.PrivateKey, message []byte) []byte {
	{
		return ed25519.Sign(ed25519PrivateKey, message)
	}
}

func VerifySignedMessage(ed25519PublicKey ed25519.PublicKey, message []byte, signedMessage []byte) bool {
	{
		return ed25519.Verify(ed25519PublicKey, message, signedMessage)
	}
}
