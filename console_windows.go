//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func setupConsole() {
	windows.SetConsoleOutputCP(65001)
	if p, err := windows.UTF16PtrFromString("RelayPing"); err == nil {
		windows.NewLazySystemDLL("kernel32.dll").NewProc("SetConsoleTitleW").Call(uintptr(unsafe.Pointer(p)))
	}
}
