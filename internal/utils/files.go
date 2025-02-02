// internal\utils\files.go
package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// CreateFolders cria as pastas (retornos/plugins, retornos/themes) se não existirem
func CreateFolders() {
	// Pasta retornos
	if _, err := os.Stat("./retornos"); os.IsNotExist(err) {
		err := os.Mkdir("./retornos", 0755)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	// Pasta plugins
	if _, err := os.Stat("./retornos/plugins"); os.IsNotExist(err) {
		err := os.Mkdir("./retornos/plugins", 0755)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	// Pasta themes
	if _, err := os.Stat("./retornos/themes"); os.IsNotExist(err) {
		err := os.Mkdir("./retornos/themes", 0755)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	// Pasta de versões
	if _, err := os.Stat("./retornos/version"); os.IsNotExist(err) {
		err := os.Mkdir("./retornos/version", 0755)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}

// CarregarListas lê um arquivo .txt (uma string por linha) e retorna slice.
func CarregarListas(filePath string) []string {
	var lista []string
	f, err := os.Open(filePath)
	if err != nil {
		return lista
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())
		if linha == "" || strings.HasPrefix(linha, "#") {
			continue
		}
		lista = append(lista, linha)
	}
	return lista
}

type Plugin struct {
	Slug        string
	Comparator  string
	Version     string
	Description string
}

// CarregarPluginsVulneraveis lê o arquivo plugins.txt/themes.txt no formato "slug|<= 1.5.6|Descrição"
func CarregarPluginsVulneraveis(filePath string) []Plugin {

	var lista []Plugin

	f, err := os.Open(filePath)
	if err != nil {
		return []Plugin{}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())
		if linha == "" || strings.HasPrefix(linha, "#") {
			continue
		}
		partes := strings.Split(linha, "|")
		if len(partes) < 3 {
			continue
		}
		comp, vers := parseComparatorAndVersion(partes[1])
		lista = append(lista, Plugin{
			Slug:        partes[0],
			Comparator:  comp,
			Version:     vers,
			Description: partes[2],
		})
	}
	// Convertendo para slice “puro” ou usando a struct do seu scanner.
	// Aqui devolve slice de Plugin anônima, mas adapte conforme seu struct.
	return lista
}

// parseComparatorAndVersion separa "<= 1.5.6" em ("<=", "1.5.6")
func parseComparatorAndVersion(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "all" {
		return "all", "0"
	}
	// Exemplo simples
	// Procure adaptá-lo com regex, se preferir
	if strings.HasPrefix(raw, "<=") {
		return "<=", strings.TrimSpace(raw[2:])
	} else if strings.HasPrefix(raw, ">=") {
		return ">=", strings.TrimSpace(raw[2:])
	} else if strings.HasPrefix(raw, "<") {
		return "<", strings.TrimSpace(raw[1:])
	} else if strings.HasPrefix(raw, ">") {
		return ">", strings.TrimSpace(raw[1:])
	} else if strings.HasPrefix(raw, "=") {
		return "=", strings.TrimSpace(raw[1:])
	}
	// fallback
	return "=", raw
}
