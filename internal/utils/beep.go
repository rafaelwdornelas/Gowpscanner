// internal\utils\beep.go
package utils

import (
	"syscall"
)

// Se quiser fazer condicional para Windows:
// // +build windows

var (
	user32, _      = syscall.LoadLibrary("user32.dll")
	messageBeep, _ = syscall.GetProcAddress(user32, "MessageBeep")
)

// BeepAlert toca um beep simples (apenas Windows)
func BeepAlert() {
	ret, _, _ := syscall.Syscall(uintptr(messageBeep), 1, 0x00000000, 0, 0)
	if ret == 0 {
		// se falhar
		return
	}
}
