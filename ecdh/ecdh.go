package ecdh

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
)

type X3DHSecretOutputLength int

const (
	Bytes16 X3DHSecretOutputLength = 16
	Bytes24 X3DHSecretOutputLength = 24
	Bytes32 X3DHSecretOutputLength = 32
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

func X3DH(dh1, dh2, dh3, dh4, salt []byte, outputLen X3DHSecretOutputLength) (secret []byte, secretSalt []byte, err error) {

	h := hmac.New(sha256.New, salt)
	combinedSecrets := bytes.Join([][]byte{dh1, dh2, dh3, dh4}, nil)
	h.Write(combinedSecrets)

	prk := h.Sum(nil)

	reader := hkdf.New(sha256.New, prk, nil, nil)
	okm := make([]byte, outputLen)
	_, err = reader.Read(okm)

	if err != nil {
		return nil, nil, err
	}

	return okm, salt, nil
}

func Salt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}
