package main

/*
#include <windows.h>
*/
import "C"

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func stringToPWideCharPtr(data string) uintptr {
	p, _ := windows.UTF16PtrFromString(data)
	return uintptr(unsafe.Pointer((*C.wchar_t)(p)))
}

func PWideCharPtrToString(ptr *C.wchar_t) string {
	return windows.UTF16PtrToString((*uint16)(ptr))
}

func createConsole() {
	C.AllocConsole()
	InitConsoleHandles()
}

func InitConsoleHandles() error {
	// Retrieve standard handles.
	hIn, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err != nil {
		return errors.New("Failed to retrieve standard input handler.")
	}
	hOut, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return errors.New("Failed to retrieve standard output handler.")
	}
	hErr, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
	if err != nil {
		return errors.New("Failed to retrieve standard error handler.")
	}

	// Wrap handles in files. /dev/ prefix just to make it conventional.
	stdInF := os.NewFile(uintptr(hIn), "/dev/stdin")
	if stdInF == nil {
		return errors.New("Failed to create a new file for standard input.")
	}
	stdOutF := os.NewFile(uintptr(hOut), "/dev/stdout")
	if stdOutF == nil {
		return errors.New("Failed to create a new file for standard output.")
	}
	stdErrF := os.NewFile(uintptr(hErr), "/dev/stderr")
	if stdErrF == nil {
		return errors.New("Failed to create a new file for standard error.")
	}

	// Set handles for standard input, output and error devices.
	err = windows.SetStdHandle(windows.STD_INPUT_HANDLE, windows.Handle(stdInF.Fd()))
	if err != nil {
		return errors.New("Failed to set standard input handler.")
	}
	err = windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(stdOutF.Fd()))
	if err != nil {
		return errors.New("Failed to set standard output handler.")
	}
	err = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(stdErrF.Fd()))
	if err != nil {
		return errors.New("Failed to set standard error handler.")
	}

	// Update golang standard IO file descriptors.
	os.Stdin = stdInF
	os.Stdout = stdOutF
	os.Stderr = stdErrF

	return nil
}

func base64DecodeStripped(s string) []byte {
	if i := len(s) % 4; i != 0 {
		s += strings.Repeat("=", 4-i)
	}
	decoded, _ := base64.StdEncoding.DecodeString(s)
	return decoded
}
