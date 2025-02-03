// internal\utils\logs.go
package utils

import (
	"fmt"
	"os"
	"sync"
)

// fileMutexes é um mapa global que associa cada arquivo a um mutex específico.
var fileMutexes sync.Map // key: string (caminho completo), value: *sync.Mutex

// LogSave salva o texto no arquivo filename (append) com proteção de mutex específico para cada arquivo.
func LogSave(texto, filename string) {
	path := "./retornos/"
	fullPath := path + filename

	// Obter ou criar o mutex específico para o fullPath.
	mutexIface, _ := fileMutexes.LoadOrStore(fullPath, &sync.Mutex{})
	fileMutex := mutexIface.(*sync.Mutex)

	// Bloqueia o mutex para esse arquivo.
	fileMutex.Lock()
	defer fileMutex.Unlock()

	// Verifica se o arquivo existe; se não, cria-o.
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		file, err := os.Create(fullPath)
		if err != nil {
			fmt.Println("Erro ao criar arquivo:", err)
			return
		}
		file.Close()
	}

	// Abre o arquivo para escrita em modo append.
	file, err := os.OpenFile(fullPath, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Erro ao abrir arquivo:", err)
		return
	}
	defer file.Close()

	// Escreve o texto no arquivo.
	if _, err := file.WriteString(texto + "\n"); err != nil {
		fmt.Println("Erro ao escrever no arquivo:", err)
	}
}
