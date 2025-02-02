// internal\utils\logs.go
package utils

import (
	"fmt"
	"os"
)

// LogSave salva texto no arquivo filename (appending)
func LogSave(texto, filename string) {
	path := "./retornos/"
	if _, err := os.Stat(path + filename); os.IsNotExist(err) {
		// cria o arquivo se não existir
		_, err := os.Create(path + filename)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	file, err := os.OpenFile(path+filename, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	file.WriteString(texto + "\n")
}
