package main

import (
	"fmt"
	"log"

	// Ajuste de acordo com o nome do seu módulo:
	"Gowpscanner/internal/scanner"
)

func main() {

	// 3) Executa o scanner (lendo dominios.txt)
	err := scanner.Run("dominios.txt")
	if err != nil {
		log.Fatalf("Erro ao executar o scanner: %v", err)
	}

	fmt.Println("Scan finalizado.")
}
