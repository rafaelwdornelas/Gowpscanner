package wpdetect

import (
	"fmt"
	"regexp"
	"strings"

	"Gowpscanner/internal/utils"
)

// CheckFirebaseIO procura por links Firebase na string de entrada e os salva em firebaseio.txt.
func CheckFirebaseIO(content string) {
	// Definindo as expressões regulares (com flag case-insensitive)
	patternFirebaseio := `(?i)[a-z0-9.-]+\.firebaseio\.com`
	patternFirebaseapp := `(?i)[a-z0-9.-]+\.firebaseapp\.com`

	// Compilando as regexes
	reFirebaseio, err := regexp.Compile(patternFirebaseio)
	if err != nil {
		fmt.Printf("Erro compilando regex firebaseio: %v\n", err)
		return
	}
	reFirebaseapp, err := regexp.Compile(patternFirebaseapp)
	if err != nil {
		fmt.Printf("Erro compilando regex firebaseapp: %v\n", err)
		return
	}

	// Encontrando todos os matches na string de entrada
	matchesFirebaseio := reFirebaseio.FindAllString(content, -1)
	matchesFirebaseapp := reFirebaseapp.FindAllString(content, -1)

	// Usando um mapa para remover duplicatas
	matchesMap := make(map[string]bool)
	for _, match := range matchesFirebaseio {
		matchesMap[match] = true
	}
	for _, match := range matchesFirebaseapp {
		matchesMap[match] = true
	}

	// Se não houver nenhum match, encerra a função.
	if len(matchesMap) == 0 {
		return
	}

	// Converte o mapa em slice de strings
	var results []string
	for link := range matchesMap {
		results = append(results, link)
	}

	// Junta os resultados em uma única string separada por quebras de linha
	resultStr := strings.Join(results, "\n")

	// Salva os links encontrados no arquivo firebaseio.txt
	utils.LogSave(resultStr, "firebaseio.txt")
	utils.Warning("Links Firebase encontrados: %s", resultStr)
	utils.BeepAlert()
}
