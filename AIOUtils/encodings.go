package main

import "C"
import (
	"encoding/base64"
	"encoding/hex"
)

//export base64Decode
func base64Decode(dataPtr *C.wchar_t) uintptr {
	data := PWideCharPtrToString(dataPtr)

	decodedData, err := base64DecodeStripped(data)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}
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

	decodedData, err := hex.DecodeString(data)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}
	return stringToPWideCharPtr(string(decodedData))
}

//export hexToBase64
func hexToBase64(dataPtr *C.wchar_t) uintptr {
	data := PWideCharPtrToString(dataPtr)

	decodedData, err := hex.DecodeString(data)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}
	return stringToPWideCharPtr(base64.StdEncoding.EncodeToString(decodedData))
}

//export base64ToHex
func base64ToHex(dataPtr *C.wchar_t) uintptr {
	data := PWideCharPtrToString(dataPtr)

	decodedData, err := base64DecodeStripped(data)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}
	return stringToPWideCharPtr(hex.EncodeToString(decodedData))
}
