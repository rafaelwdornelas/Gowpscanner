// internal\scanner\env.go
package scanner

import (
	"fmt"
	"strings"

	"Gowpscanner/internal/utils"
)

// envList (carregadas em init ou por outro método)
var envList []string

// CheckEnv verifica se o domínio possui um arquivo .env válido em diferentes caminhos
// e salva a URL do .env válido no arquivo env-production.txt.
func CheckEnv(baseURL string) {
	var contador int = 0

	// Itera sobre cada caminho e faz a verificação
	for _, p := range envList {
		contador++
		//caso o contador seja multiplo de 100, exibe mensagem
		if contador%100 == 0 {
			utils.Info("Verificando Env %s -  %d/%d", baseURL, contador, len(shellList))
		}

		envURL := fmt.Sprintf("%s%s", baseURL, p)

		// Tenta obter o conteúdo usando GetBody (que já retorna erro se o status não for 200)
		content, err := utils.GetBody(envURL)
		if err != nil {
			// Se ocorrer algum erro, não há .env acessível nesse caminho
			continue
		}

		// Converte para minúsculas para facilitar as comparações
		lowerContent := strings.ToLower(content)

		// Verifica se o conteúdo não contém HTML (indicativo de uma resposta inválida)
		if strings.Contains(lowerContent, "<html") || strings.Contains(lowerContent, "<!doctype html") {
			// Se encontrar HTML, ignora esse caminho
			continue
		}

		// Verifica se o conteúdo contém algumas chaves típicas de um arquivo .env
		if strings.Contains(lowerContent, "app_name=") ||
			strings.Contains(lowerContent, "app_key=") ||
			strings.Contains(lowerContent, "api=") ||
			strings.Contains(lowerContent, "password=") ||
			strings.Contains(lowerContent, "senha=") ||
			strings.Contains(lowerContent, "key=") ||
			strings.Contains(lowerContent, "app_secret=") ||
			strings.Contains(lowerContent, "smtp=") ||
			strings.Contains(lowerContent, "mail_host=") ||
			strings.Contains(lowerContent, "mail_user=") ||
			strings.Contains(lowerContent, "mail_username=") ||
			strings.Contains(lowerContent, "smtp_host=") ||
			strings.Contains(lowerContent, "smtp_user=") ||
			strings.Contains(lowerContent, "smtp_username=") ||
			strings.Contains(lowerContent, "db_name=") ||
			strings.Contains(lowerContent, "db_user=") ||
			strings.Contains(lowerContent, "db_pass=") ||
			strings.Contains(lowerContent, "db_host=") {
			// Se passou nos testes, considera-se um .env válido
			utils.LogSave(envURL, "env-production.txt")
			utils.Warning("Arquivo .env válido encontrado em %s", envURL)
			utils.BeepAlert()
		}
	}
}
