package scanner

import (
	"fmt"
	"strings"

	"Gowpscanner/internal/utils"
)

// CheckEnv verifica se o domínio possui um arquivo .env válido e salva a URL no arquivo env-production.txt.
func CheckEnv(baseURL string) {
	// Monta a URL para o arquivo .env
	envURL := fmt.Sprintf("%s/.env", baseURL)

	// Tenta obter o conteúdo usando GetBody (que já retorna erro se o status não for 200)
	content, err := utils.GetBody(envURL)
	if err != nil {
		// Se ocorrer algum erro, não há .env acessível
		return
	}

	// Converte para minúsculas para facilitar as comparações
	lowerContent := strings.ToLower(content)

	// Verifica se o conteúdo não contém HTML (indicativo de uma resposta inválida) e contém, por exemplo, "app_name="
	if strings.Contains(lowerContent, "<html") || strings.Contains(lowerContent, "<!doctype html") {
		// Se encontrar HTML, não é um arquivo .env
		return
	}

	if strings.Contains(lowerContent, "app_name=") ||
		strings.Contains(lowerContent, "app_key=") ||
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
	}
	return
}
