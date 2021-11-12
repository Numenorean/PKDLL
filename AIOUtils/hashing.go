package main

import "C"
import (
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

var (
	hashTypes map[string]hashType
)

type hashType struct {
	_hash   func() hash.Hash
	_crypto crypto.Hash
}

func init() {
	hashTypes = map[string]hashType{
		"md4":            {md4.New, crypto.MD4},
		"md5":            {md5.New, crypto.MD5},
		"sha1":           {sha1.New, crypto.SHA1},
		"sha224":         {sha256.New224, crypto.SHA224},
		"sha256":         {sha256.New, crypto.SHA256},
		"sha384":         {sha512.New384, crypto.SHA384},
		"sha512":         {sha512.New, crypto.SHA512},
		"sha3-224":       {sha3.New224, crypto.SHA3_224},
		"sha3-256":       {sha3.New256, crypto.SHA3_256},
		"sha3-384":       {sha3.New384, crypto.SHA3_384},
		"sha3-512":       {sha3.New512, crypto.SHA3_512},
		"sha3-keccak256": {sha3.NewLegacyKeccak256, 0},
		"sha3-keccak512": {sha3.NewLegacyKeccak512, 0},
		"ripemd160":      {ripemd160.New, crypto.RIPEMD160},
	}
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
