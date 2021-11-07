package main

import "C"

import (
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"strconv"
)

const (
	DEBUG   = false
	author  = "_Skill_"
	version = "0.1"
	desc    = "Большое количество алгоритмов шифрования, функций кодировки и других утилит в одной библиотеке"
)

//export info_getAuthor
func info_getAuthor() uintptr {
	if DEBUG {
		createConsole()
	}
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
		return stringToPWideCharPtr("0")
	}

	max, err := strconv.ParseInt(maxS, 10, 0)
	if err != nil {
		return stringToPWideCharPtr("0")
	}

	r := rand.Int63n(max-min) + min
	return stringToPWideCharPtr(strconv.FormatInt(r, 10))
}

//export base64Decode
func base64Decode(dataPtr *C.wchar_t) uintptr {
	data := PWideCharPtrToString(dataPtr)

	decodedData := base64DecodeStripped(data)
	return stringToPWideCharPtr(string(decodedData))
}

//export hexEncode
func hexEncode(dataPtr *C.wchar_t) uintptr {
	data := PWideCharPtrToString(dataPtr)

	encodedData := hex.EncodeToString([]byte(data))
	return stringToPWideCharPtr(string(encodedData))
}

//export hexDecode
func hexDecode(dataPtr *C.wchar_t) uintptr {
	data := PWideCharPtrToString(dataPtr)

	decodedData, _ := hex.DecodeString(data)
	return stringToPWideCharPtr(string(decodedData))
}

//export hexToBase64
func hexToBase64(dataPtr *C.wchar_t) uintptr {
	data := PWideCharPtrToString(dataPtr)

	decodedData, _ := hex.DecodeString(data)
	return stringToPWideCharPtr(base64.StdEncoding.EncodeToString(decodedData))
}

//export base64ToHex
func base64ToHex(dataPtr *C.wchar_t) uintptr {
	data := PWideCharPtrToString(dataPtr)

	decodedData := base64DecodeStripped(data)
	return stringToPWideCharPtr(hex.EncodeToString(decodedData))
}

//export encryptAes
func encryptAes(key, iv, data, mode, encoding, nonce, tag *C.wchar_t) *C.wchar_t {

}

//export decryptAes
func decryptAes(key, iv, data, mode, encoding, nonce, tag *C.wchar_t) *C.wchar_t {

}

//export hmacData
func hmacData(key, data, mode, encoding *C.wchar_t) *C.wchar_t {

}

//export rsaEncrypt
func rsaEncrypt(publicKey, data, mode, encoding *C.wchar_t) *C.wchar_t {

}

//export rsaDecrypt
func rsaDecrypt(privateKey, data, mode, encoding *C.wchar_t) *C.wchar_t {

}

//export bcryptData
func scryptData(data, rounds, salt *C.wchar_t) *C.wchar_t {

}

func main() {

}
