package main

import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"
)

const (
	DEBUG     = true
	author    = "_Skill_"
	version   = "0.1"
	desc      = "Большое количество алгоритмов шифрования, функций кодировки и других утилит в одной библиотеке"
	statusOK  = "OK|"
	statusErr = "ERR|"
)

func init() {
	if DEBUG {
		createConsole()
	}
	rand.Seed(time.Now().UnixNano())
	f, _ := os.OpenFile("paniclog.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	redirectStderr(f)
}

//export info_getAuthor
func info_getAuthor() uintptr {
	return stringToPWideCharPtr(author)
}

//export info_getVersion
func info_getVersion() uintptr {
	return stringToPWideCharPtr(version)
}

//export info_getDescription
func info_getDescription() uintptr {
	return stringToPWideCharPtr(desc)
}

//export randNumber
func randNumber(minPtr, maxPtr *C.wchar_t) uintptr {
	minS := PWideCharPtrToString(minPtr)
	maxS := PWideCharPtrToString(maxPtr)

	min, err := strconv.ParseInt(minS, 10, 0)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	max, err := strconv.ParseInt(maxS, 10, 0)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	if (max - min) < 0 {
		return stringToPWideCharPtr(statusErr + "(max-min) must be >= 0")
	}

	r := rand.Int63n(max-min) + min
	return stringToPWideCharPtr(statusOK + strconv.FormatInt(r, 10))
}

//export base64Decode
func base64Decode(dataPtr *C.wchar_t) uintptr {
	data := PWideCharPtrToString(dataPtr)

	decodedData, err := base64DecodeStripped(data)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}
	return stringToPWideCharPtr(statusOK + string(decodedData))
}

//export hexEncode
func hexEncode(dataPtr *C.wchar_t) uintptr {
	data := PWideCharPtrToString(dataPtr)

	encodedData := hex.EncodeToString([]byte(data))
	return stringToPWideCharPtr(statusOK + string(encodedData))
}

//export hexDecode
func hexDecode(dataPtr *C.wchar_t) uintptr {
	data := PWideCharPtrToString(dataPtr)

	decodedData, err := hex.DecodeString(data)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}
	return stringToPWideCharPtr(statusOK + string(decodedData))
}

//export hexToBase64
func hexToBase64(dataPtr *C.wchar_t) uintptr {
	data := PWideCharPtrToString(dataPtr)

	decodedData, err := hex.DecodeString(data)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}
	return stringToPWideCharPtr(statusOK + base64.StdEncoding.EncodeToString(decodedData))
}

//export base64ToHex
func base64ToHex(dataPtr *C.wchar_t) uintptr {
	data := PWideCharPtrToString(dataPtr)

	decodedData, err := base64DecodeStripped(data)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}
	return stringToPWideCharPtr(statusOK + hex.EncodeToString(decodedData))
}

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
		encryptedData, err = AesEncryptEcb(keyB, dataB)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}
	case "cbc":
		dataB = PKCS5Padding(dataB, aes.BlockSize, len(dataB))
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

	return stringToPWideCharPtr(statusOK + encodeHexBase64Raw(encryptedData, encoding))
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
		decryptedData, err = AesDecryptEcb(keyB, dataB)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}

		decryptedData, err = PKCS5Trimming(decryptedData)
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
		decryptedData, err = PKCS5Trimming(decryptedData)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}
	default:
		return stringToPWideCharPtr(statusErr + mode + " not implemented yet")
	}

	return stringToPWideCharPtr(statusOK + encodeHexBase64Raw(decryptedData, encoding))
}

//export hashHmac
func hashHmac(keyPtr, dataPtr, modePtr, encodingPtr, actionPtr *C.wchar_t) uintptr {
	data := PWideCharPtrToString(dataPtr)
	mode := PWideCharPtrToString(modePtr)
	encoding := PWideCharPtrToString(encodingPtr)
	action := PWideCharPtrToString(actionPtr)

	dataB, err := base64DecodeStripped(data)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	var hashedData []byte
	h, ok := hashTypes[mode]
	if !ok {
		return stringToPWideCharPtr(statusErr + mode + " not implemented yet")
	}

	switch action {
	case "hash":
		hashFunc := h()
		hashFunc.Write(dataB)
		hashedData = hashFunc.Sum(nil)
	case "hmac":
		key := PWideCharPtrToString(keyPtr)
		keyB, err := base64DecodeStripped(key)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}

		mac := hmac.New(h, keyB)
		mac.Write(dataB)
		hashedData = mac.Sum(nil)
	default:
		return stringToPWideCharPtr(statusErr + "Choose between hash and hmac")
	}

	return stringToPWideCharPtr(statusOK + encodeHexBase64Raw(hashedData, encoding))
}

/*
//export rsaEncrypt
func rsaEncrypt(publicKeyPtr, dataPtr, modePtr, encodingPtr *C.wchar_t) *C.wchar_t {

}

//export rsaDecrypt
func rsaDecrypt(privateKeyPtr, dataPtr, modePtr, encodingPtr *C.wchar_t) *C.wchar_t {

}

//export bcryptData
func bcryptData(dataPtr, rounds, salt *C.wchar_t) *C.wchar_t {

}

//export scryptData
func scryptData(dataPtr, rounds, salt *C.wchar_t) *C.wchar_t {

}
*/

func main() {

}
