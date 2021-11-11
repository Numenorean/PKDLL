package main

import "C"
import "crypto/hmac"

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
		hashFunc := h._hash()
		hashFunc.Write(dataB)
		hashedData = hashFunc.Sum(nil)
	case "hmac":
		key := PWideCharPtrToString(keyPtr)
		keyB, err := base64DecodeStripped(key)
		if err != nil {
			return stringToPWideCharPtr(statusErr + err.Error())
		}

		mac := hmac.New(h._hash, keyB)
		mac.Write(dataB)
		hashedData = mac.Sum(nil)
	default:
		return stringToPWideCharPtr(statusErr + "Choose between hash and hmac")
	}

	return stringToPWideCharPtr(encodeHexBase64Raw(hashedData, encoding))
}
