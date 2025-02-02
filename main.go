package main

import (
	"fmt"
	"log"

	// Ajuste de acordo com o nome do seu módulo:
	"Gowpscanner/internal/scanner"
	"Gowpscanner/internal/utils"
	"Gowpscanner/pkg/update"
)

func main() {

	// 1) Atualiza a base de dados (ou verifica se está atualizada)
	update.BaixaDatabase()

	// 2) Cria as pastas de retornos (antes de rodar)
	utils.CreateFolders()

	// 3) Executa o scanner (lendo dominios.txt)
	err := scanner.Run("dominios.txt")
	if err != nil {
		log.Fatalf("Erro ao executar o scanner: %v", err)
	}

	fmt.Println("Scan finalizado.")
}
