package main

import "C"
import (
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"strconv"
)

var (
	errBadPublicKey = errors.New("cant decode public key")
)

// mode

//export rsaEncrypt
func rsaEncrypt(publicKeyPtr, dataPtr, modePtr, encodingPtr, hashTypePtr, labelPtr *C.wchar_t) uintptr {
	publicKeyString := PWideCharPtrToString(publicKeyPtr)
	data := PWideCharPtrToString(dataPtr)
	mode := PWideCharPtrToString(modePtr)
	encoding := PWideCharPtrToString(encodingPtr)

	dataB, err := base64DecodeStripped(data)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	publicKeyB, err := base64DecodeStripped(publicKeyString)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}
	publicKey, err := BytesToPublicKey(publicKeyB)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	var encryptedData []byte

	switch mode {
	case "oaep":
		hashType := PWideCharPtrToString(hashTypePtr)
		h, ok := hashTypes[hashType]
		if !ok {
			return stringToPWideCharPtr(statusErr + mode + " not implemented yet")
		}
		label := PWideCharPtrToString(labelPtr)
		labelB, err := base64DecodeStripped(label)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}
		encryptedData, err = rsa.EncryptOAEP(h._hash(), crand.Reader, publicKey, dataB, labelB)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}
	case "pkcs1_v1.5":
		encryptedData, err = rsa.EncryptPKCS1v15(crand.Reader, publicKey, dataB)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}
	}
	return stringToPWideCharPtr(encodeHexBase64Raw(encryptedData, encoding))
}

//export rsaDecrypt
func rsaDecrypt(privateKeyPtr, encryptedDataPtr, modePtr, encodingPtr, hashTypePtr, labelPtr *C.wchar_t) uintptr {
	privateKeyString := PWideCharPtrToString(privateKeyPtr)
	encryptedData := PWideCharPtrToString(encryptedDataPtr)
	mode := PWideCharPtrToString(modePtr)
	encoding := PWideCharPtrToString(encodingPtr)

	encryptedDataB, err := base64DecodeStripped(encryptedData)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	privateKeyB, err := base64DecodeStripped(privateKeyString)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}
	privateKey, err := BytesToPrivateKey(privateKeyB)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	var decryptedData []byte

	switch mode {
	case "oaep":
		hashType := PWideCharPtrToString(hashTypePtr)
		h, ok := hashTypes[hashType]
		if !ok {
			return stringToPWideCharPtr(statusErr + mode + " not implemented yet")
		}
		label := PWideCharPtrToString(labelPtr)
		labelB, err := base64DecodeStripped(label)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}
		decryptedData, err = rsa.DecryptOAEP(h._hash(), crand.Reader, privateKey, encryptedDataB, labelB)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}
	case "pkcs1_v1.5":
		decryptedData, err = rsa.DecryptPKCS1v15(crand.Reader, privateKey, encryptedDataB)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}
	}
	return stringToPWideCharPtr(encodeHexBase64Raw(decryptedData, encoding))
}

//export modulusToPem
func modulusToPem(modulusPtr, expPtr *C.wchar_t) uintptr {
	modulus := PWideCharPtrToString(modulusPtr)
	exp, err := strconv.Atoi(PWideCharPtrToString(expPtr))
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	modulusB, err := base64DecodeStripped(modulus)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	publicKey := rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusB),
		E: exp,
	}
	pemData, err := PublicKeyToBytes(&publicKey)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}
	return stringToPWideCharPtr(string(pemData))
}

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
		return nil, errBadPublicKey
	}
	ifc, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, errBadPublicKey
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
