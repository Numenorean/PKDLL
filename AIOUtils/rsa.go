package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var (
	badPublicKey = errors.New("cant decode public key")
)

// PrivateKeyToBytes private key to bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

func PublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes, nil
}

func BytesToPublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	if block == nil {
		return nil, badPublicKey
	}
	ifc, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, badPublicKey
	}
	return key, nil
}

func BytesToPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	isEnc := x509.IsEncryptedPEMBlock(block)
	if isEnc {
		return nil, errors.New("private key under password")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}
