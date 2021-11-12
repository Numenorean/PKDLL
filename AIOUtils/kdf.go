package main

import "C"
import (
	"aioutils/bcrypt"
	"strconv"

	"golang.org/x/crypto/scrypt"
)

//export bcryptPassword
func bcryptPassword(passwordPtr, roundsPtr, saltPtr, encodingPtr *C.wchar_t) uintptr {
	password := PWideCharPtrToString(passwordPtr)
	encoding := PWideCharPtrToString(encodingPtr)
	salt := PWideCharPtrToString(saltPtr)
	rounds := PWideCharPtrToString(roundsPtr)

	passwordB, err := base64DecodeStripped(password)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	saltB, err := base64DecodeStripped(salt)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	roundsInt, err := strconv.Atoi(rounds)
	if err != nil {
		roundsInt = bcrypt.DefaultCost
	}
	hashedData, err := bcrypt.GenerateFromPassword(passwordB, roundsInt, saltB)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	return stringToPWideCharPtr(encodeHexBase64Raw(hashedData, encoding))
}

//export scryptPassword
func scryptPassword(passwordPtr, NPtr, rPtr, pPtr, keyLenPtr, encodingPtr *C.wchar_t) uintptr {
	password := PWideCharPtrToString(passwordPtr)
	encoding := PWideCharPtrToString(encodingPtr)

	passwordB, err := base64DecodeStripped(password)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	N, err := strconv.Atoi(PWideCharPtrToString(NPtr))
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	r, err := strconv.Atoi(PWideCharPtrToString(rPtr))
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	p, err := strconv.Atoi(PWideCharPtrToString(pPtr))
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}
	keyLen, err := strconv.Atoi(PWideCharPtrToString(keyLenPtr))
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	salt, err := GenerateRandomBytes(16)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	hashedData, err := scrypt.Key(passwordB, salt, N, r, p, keyLen)
	if err != nil {
		return stringToPWideCharPtr(statusErr + err.Error())
	}

	return stringToPWideCharPtr(encodeHexBase64Raw(hashedData, encoding) + "|" + encodeHexBase64Raw(salt, encoding))
}
