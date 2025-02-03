// internal\scanner\yaml.go
package scanner

import (
	"fmt"
	"strings"

	"Gowpscanner/internal/utils"
)

// yamlList contém os caminhos (ou nomes de arquivos) para verificar arquivos YAML/YML.
// Esses caminhos podem ser definidos na função init ou carregados de outro modo.
var yamlList []string

// CheckYaml verifica se o domínio possui um arquivo YAML/YML com informações sensíveis
// e salva a URL do arquivo encontrado no arquivo env-production.txt.
func CheckYaml(baseURL string) {
	// Itera sobre cada caminho definido em yamlList.
	for _, p := range yamlList {
		yamlURL := fmt.Sprintf("%s%s", baseURL, p)

		// Tenta obter o conteúdo usando GetBody.
		content, err := utils.GetBody(yamlURL)
		if err != nil {
			// Se ocorrer algum erro, pula para o próximo caminho.
			continue
		}

		// Converte o conteúdo para minúsculas para facilitar a comparação.
		lowerContent := strings.ToLower(content)

		// Verifica se o conteúdo contém HTML, o que indicaria uma resposta inválida.
		if strings.Contains(lowerContent, "<html") || strings.Contains(lowerContent, "<!doctype html") {
			continue
		}

		// Verifica se o conteúdo possui chaves sensíveis típicas de arquivos de configuração em YAML.
		if strings.Contains(lowerContent, "api_key:") ||
			strings.Contains(lowerContent, "db_password:") ||
			strings.Contains(lowerContent, "secret:") ||
			strings.Contains(lowerContent, "token:") ||
			strings.Contains(lowerContent, "private_key:") ||
			strings.Contains(lowerContent, "password:") {
			// Se passou nos testes, considera-se um arquivo YAML com dados sensíveis.
			utils.LogSave(yamlURL, "yaml-production.txt")
			utils.Warning("Arquivo YAML sensível encontrado em %s", yamlURL)
			utils.BeepAlert()
		}
	}
}
