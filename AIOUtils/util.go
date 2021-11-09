package main

/*
#include <windows.h>
*/
import "C"

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sys/windows"
)

var (
	kernel32         = syscall.MustLoadDLL("kernel32.dll")
	procSetStdHandle = kernel32.MustFindProc("SetStdHandle")
	hashTypes        map[string]func() hash.Hash
)

func init() {
	hashTypes = map[string]func() hash.Hash{
		"md5":            md5.New,
		"md4":            md4.New,
		"sha1":           sha1.New,
		"sha224":         sha256.New224,
		"sha256":         sha256.New,
		"sha384":         sha512.New384,
		"sha512":         sha512.New,
		"sha3-224":       sha3.New224,
		"sha3-256":       sha3.New256,
		"sha3-384":       sha3.New384,
		"sha3-512":       sha3.New512,
		"sha3-keccak256": sha3.NewLegacyKeccak256,
		"sha3-keccak512": sha3.NewLegacyKeccak512,
		"ripemd160":      ripemd160.New,
	}
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

func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Trimming(encrypt []byte) ([]byte, error) {
	padding := encrypt[len(encrypt)-1]
	if (len(encrypt) - int(padding)) < 0 {
		return nil, errors.New("invalid data")
	}
	return encrypt[:len(encrypt)-int(padding)], nil
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
