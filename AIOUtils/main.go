package main

import "C"

import (
	"math/rand"
	"time"
)

const (
	DEBUG     = true
	author    = "_Skill_"
	version   = "0.1"
	desc      = "Большое количество алгоритмов шифрования, функций кодировки и других утилит в одной библиотеке"
	statusErr = "ERR|"
)

func init() {
	if DEBUG {
		createConsole()
	}
	rand.Seed(time.Now().UnixNano())
}

//export info_getAuthor
func info_getAuthor() uintptr {
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

func main() {

}
