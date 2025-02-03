package scanner

import (
	"fmt"
	"strings"

	"Gowpscanner/internal/utils"
)

// CheckEnv verifica se o domínio possui um arquivo .env válido em diferentes caminhos
// e salva a URL do .env válido no arquivo env-production.txt.
func CheckEnv(baseURL string) {
	// Lista de caminhos a serem verificados
	// Lista de caminhos e nomes de arquivos para verificar
	paths := []string{
		"/.env",
		"/.env.example",
		"/.env.production",
		"/.env.development",
		"/.env.local",
		"/admin/.env",
		"/shop/.env",
		"/api/.env",
		"/config/.env",
		"/backup/.env",
		"/env",
		"/config.env",
		"/configuration/.env",
	}

	// Itera sobre cada caminho e faz a verificação
	for _, p := range paths {
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
		}
	}
}
