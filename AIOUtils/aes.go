package main

import "C"
import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"aioutils/ecb"
)

// keyPtr, ivPtr, dataPtr, noncePtr/GCM Tag (default - random), tagPtr/Additional Authenticated Data - base64
//
// modePtr - (ecb, cbc, gcm)
//
// encodingPtr - (base64, hex)
//
// noncePtr, tagPtr - only for gcm
//export encryptAes
func encryptAes(keyPtr, ivPtr, dataPtr, modePtr, encodingPtr, noncePtr, tagPtr *C.wchar_t) (retPtr uintptr) {
	defer func() {
		if err := recover(); err != nil {
			retPtr = stringToPWideCharPtr(statusErr + fmt.Sprintf("%v", err))
		}
	}()
	key := PWideCharPtrToString(keyPtr)
	iv := PWideCharPtrToString(ivPtr)
	data := PWideCharPtrToString(dataPtr)
	mode := PWideCharPtrToString(modePtr)
	encoding := PWideCharPtrToString(encodingPtr)
	nonce := PWideCharPtrToString(noncePtr)
	tag := PWideCharPtrToString(tagPtr)

	keyB, err := base64DecodeStripped(key)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}
	ivB, err := base64DecodeStripped(iv)
	if err != nil || len(ivB) != 16 {
		ivB = make([]byte, 16)
	}
	dataB, err := base64DecodeStripped(data)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	var encryptedData []byte

	switch mode {
	case "ecb":
		encryptedData, err = ecb.AesEncryptEcb(keyB, dataB)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}
	case "cbc":
		dataB = ecb.PKCS5Padding(dataB, aes.BlockSize, len(dataB))
		block, err := aes.NewCipher(keyB)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}
		encryptedData = make([]byte, len(dataB))
		mode := cipher.NewCBCEncrypter(block, ivB)
		mode.CryptBlocks(encryptedData, dataB)
	// gcm not stable now
	case "gcm":
		var nonceB []byte
		tagB, err := base64DecodeStripped(tag)
		if err != nil {
			tagB = nil
		}
		nonceB, err = base64DecodeStripped(nonce)
		if err != nil || len(nonceB) != 12 {
			nonceB = make([]byte, 12)
		}

		block, err := aes.NewCipher(keyB)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}

		// last 16 bytes - tag
		encryptedData = aesgcm.Seal(nil, nonceB, dataB, tagB)
	default:
		return stringToPWideCharPtr(statusErr + mode + " not implemented yet")
	}

	return stringToPWideCharPtr(encodeHexBase64Raw(encryptedData, encoding))
}

//export decryptAes
func decryptAes(keyPtr, ivPtr, dataPtr, modePtr, encodingPtr *C.wchar_t) (retPtr uintptr) {
	defer func() {
		if err := recover(); err != nil {
			retPtr = stringToPWideCharPtr(statusErr + fmt.Sprintf("%v", err))
		}
	}()
	key := PWideCharPtrToString(keyPtr)
	iv := PWideCharPtrToString(ivPtr)
	data := PWideCharPtrToString(dataPtr)
	mode := PWideCharPtrToString(modePtr)
	encoding := PWideCharPtrToString(encodingPtr)

	keyB, err := base64DecodeStripped(key)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}
	ivB, err := base64DecodeStripped(iv)
	if err != nil || len(ivB) != 16 {
		ivB = make([]byte, 16)
	}
	dataB, err := base64DecodeStripped(data)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	var decryptedData []byte

	switch mode {
	case "ecb":
		decryptedData, err = ecb.AesDecryptEcb(keyB, dataB)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}
	case "cbc":
		block, err := aes.NewCipher(keyB)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}
		decryptedData = make([]byte, len(dataB))
		mode := cipher.NewCBCDecrypter(block, ivB)
		mode.CryptBlocks(decryptedData, dataB)
	default:
		return stringToPWideCharPtr(statusErr + mode + " not implemented yet")
	}

	decryptedData, err = ecb.PKCS5Trimming(decryptedData)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	return stringToPWideCharPtr(encodeHexBase64Raw(decryptedData, encoding))
}
