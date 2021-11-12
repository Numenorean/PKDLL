package main

/*
#include <windows.h>
*/
import "C"

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32         = syscall.MustLoadDLL("kernel32.dll")
	procSetStdHandle = kernel32.MustFindProc("SetStdHandle")
)

func init() {
	f, _ := os.OpenFile("C:\\Users\\Skill\\Programs\\Sources\\Golang\\PKDLL\\AIOUtils\\paniclog.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	redirectStderr(f)
}

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

func base64DecodeStripped(s string) ([]byte, error) {
	if i := len(s) % 4; i != 0 {
		s += strings.Repeat("=", 4-i)
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	return decoded, err
}

func setStdHandle(stdhandle int32, handle syscall.Handle) error {
	r0, _, e1 := syscall.Syscall(procSetStdHandle.Addr(), 2, uintptr(stdhandle), uintptr(handle), 0)
	if r0 == 0 {
		if e1 != 0 {
			return error(e1)
		}
		return syscall.EINVAL
	}
	return nil
}

// redirectStderr to the file passed in
func redirectStderr(f *os.File) {
	err := setStdHandle(syscall.STD_ERROR_HANDLE, syscall.Handle(f.Fd()))
	if err != nil {
		log.Fatalf("Failed to redirect stderr to file: %v", err)
	}
	// SetStdHandle does not affect prior references to stderr
	os.Stderr = f
}

func encodeHexBase64Raw(encryptedData []byte, encoding string) string {
	switch encoding {
	case "base64":
		return base64.StdEncoding.EncodeToString(encryptedData)
	case "hex":
		return hex.EncodeToString(encryptedData)
	case "raw":
		return string(encryptedData)
	default:
		return base64.StdEncoding.EncodeToString(encryptedData)
	}
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := crand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
