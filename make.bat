@echo off

:: Изменить на свое название
SET BINARYNAME=testdll

:: Т.к. киппер x86
set GOARCH=386
set GOGCCFLAGS="-m32 -mthreads -fmessage-length=0"
set CGO_ENABLED=1
go build --ldflags "-s -w" -o %BINARYNAME%.dll -buildmode=c-shared
del /f %BINARYNAME%.h