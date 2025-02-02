package utils

import (
	"fmt"
)

// Definição de cores via ANSI escape codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
)

// Info exibe uma mensagem de informação em azul.
func Info(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s[INFO]%s %s\n", ColorBlue, ColorReset, msg)
}

// Ok exibe uma mensagem de sucesso em verde.
func Ok(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s[OK]%s %s\n", ColorGreen, ColorReset, msg)
}

// Warning exibe uma mensagem de aviso em amarelo.
func Warning(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s[WARNING]%s %s\n", ColorYellow, ColorReset, msg)
}

// Error exibe uma mensagem de erro em vermelho.
func Error(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s[ERROR]%s %s\n", ColorRed, ColorReset, msg)
}
