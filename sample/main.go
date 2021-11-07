package main

/*
#include <stdlib.h>
#include <windows.h>
*/
import "C"

import (
	"math/rand"
	"strconv"
)

const (
	DEBUG   = false
	author  = "_Skill_"
	version = "0.1"
	desc    = "desc"
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

//export showMessageBox
func showMessageBox(title, text *C.wchar_t) {
	C.MessageBox(nil, C.CString(PWideCharPtrToString(text)), C.CString(PWideCharPtrToString(title)), 0)
}

//export returnSameData
func returnSameData(data *C.wchar_t) uintptr {
	return stringToPWideCharPtr(PWideCharPtrToString(data))
}

//export killPK
func killPK() {
	C.system(C.CString(`taskkill /F /T /IM "Private Keeper.exe"`))
}

func main() {

}
