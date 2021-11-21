package main

import "C"
import (
	"math/rand"
	"strconv"
)

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
	return stringToPWideCharPtr(strconv.FormatInt(r, 10))
}
