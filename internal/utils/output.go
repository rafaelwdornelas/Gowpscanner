package utils

import (
	"fmt"
	"time"
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
	fmt.Printf("%s - %s[INFO]%s %s\n", GetTime(), ColorBlue, ColorReset, msg)
}

// Ok exibe uma mensagem de sucesso em verde.
func Ok(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s - %s[OK]%s %s\n", GetTime(), ColorGreen, ColorReset, msg)
}

// Warning exibe uma mensagem de aviso em amarelo.
func Warning(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s - %s[WARNING]%s %s\n", GetTime(), ColorYellow, ColorReset, msg)
}

// Error exibe uma mensagem de erro em vermelho.
func Error(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s - %s[ERROR]%s %s\n", GetTime(), ColorRed, ColorReset, msg)
}

// função que retorna HH:MM:SS:MS
func GetTime() string {
	return time.Now().Format("15:04:05.000")
}
