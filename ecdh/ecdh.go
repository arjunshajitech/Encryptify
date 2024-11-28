package ecdh

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

type KeyPair struct {
	PrivateKey *ecdh.PrivateKey
	PublicKey  *ecdh.PublicKey
}

func NewECDHKeyPair(curve ecdh.Curve) (*KeyPair, error) {
	{
		privateKey, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		return &KeyPair{
			privateKey,
			privateKey.PublicKey(),
		}, nil
	}
}

func ECDH(ecdhPrivateKey *ecdh.PrivateKey, ecdhPublicKey *ecdh.PublicKey) ([]byte, error) {
	{
		secret, err := ecdhPrivateKey.ECDH(ecdhPublicKey)
		if err != nil {
			return nil, err
		}
		return secret, nil
	}
}

func X3DH(dh1, dh2, dh3, dh4 []byte) []byte {
	{
		h := hmac.New(sha256.New, nil)
		combinedSecrets := bytes.Join([][]byte{dh1, dh2, dh3, dh4}, nil)
		h.Write(combinedSecrets)
		return h.Sum(nil)
	}
}
