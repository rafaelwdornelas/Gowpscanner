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
			strings.Contains(lowerContent, "access_key:") ||
			strings.Contains(lowerContent, "access_token:") ||
			strings.Contains(lowerContent, "consumer_key:") ||
			strings.Contains(lowerContent, "consumer_secret:") ||
			strings.Contains(lowerContent, "smtp:") ||
			strings.Contains(lowerContent, "password:") {
			// Se passou nos testes, considera-se um arquivo YAML com dados sensíveis.
			utils.LogSave(yamlURL, "yaml-production.txt")
			utils.Warning("Arquivo YAML sensível encontrado em %s", yamlURL)
			utils.BeepAlert()
		}
		//circleci-config
		if strings.Contains(lowerContent, "jobs:") && strings.Contains(lowerContent, "version:") {
			// Se passou nos testes, considera-se um arquivo YAML com dados sensíveis.
			utils.LogSave(yamlURL, "yaml-production.txt")
			utils.Warning("Arquivo YAML sensível encontrado em %s", yamlURL)
			utils.BeepAlert()
		}
		//Detect Drone Configuration
		if strings.Contains(lowerContent, "kind:") && strings.Contains(lowerContent, "name:") {
			// Se passou nos testes, considera-se um arquivo YAML com dados sensíveis.
			utils.LogSave(yamlURL, "yaml-production.txt")
			utils.Warning("Arquivo YAML sensível encontrado em %s", yamlURL)
			utils.BeepAlert()
		}
		//Rails Secret Token
		if strings.Contains(lowerContent, "secret_key_base") || strings.Contains(lowerContent, "config.secret_token") {
			// Se passou nos testes, considera-se um arquivo YAML com dados sensíveis.
			utils.LogSave(yamlURL, "yaml-production.txt")
			utils.Warning("Arquivo YAML sensível encontrado em %s", yamlURL)
			utils.BeepAlert()
		}
		//Openstack User Secrets
		if strings.Contains(lowerContent, "#NOTE: Please uncomment those") || strings.Contains(lowerContent, "may break your OpenStack environment") || strings.Contains(lowerContent, "OS_AUTH_URL") || strings.Contains(lowerContent, "OS_USERNAME") || strings.Contains(lowerContent, "OS_TENANT_NAME") || strings.Contains(lowerContent, "OS_REGION_NAME") || strings.Contains(lowerContent, "OS_PROJECT_NAME") || strings.Contains(lowerContent, "OS_IDENTITY_API_VERSION") {
			// Se passou nos testes, considera-se um arquivo YAML com dados sensíveis.
			utils.LogSave(yamlURL, "yaml-production.txt")
			utils.Warning("Arquivo YAML sensível encontrado em %s", yamlURL)
			utils.BeepAlert()
		}
		//Detect Redmine Database Configuration
		if strings.Contains(lowerContent, "production:") || strings.Contains(lowerContent, "adapter:") || strings.Contains(lowerContent, "database:") || strings.Contains(lowerContent, "username:") || strings.Contains(lowerContent, "password:") || strings.Contains(lowerContent, "host:") {
			// Se passou nos testes, considera-se um arquivo YAML com dados sensíveis.
			utils.LogSave(yamlURL, "yaml-production.txt")
			utils.Warning("Arquivo YAML sensível encontrado em %s", yamlURL)
			utils.BeepAlert()
		}
		//Akkadian Provisioning Manager MariaDB Credentials
		if strings.Contains(lowerContent, "host:") || strings.Contains(lowerContent, "name:") || strings.Contains(lowerContent, "pass:") {
			// Se passou nos testes, considera-se um arquivo YAML com dados sensíveis.
			utils.LogSave(yamlURL, "yaml-production.txt")
			utils.Warning("Arquivo YAML sensível encontrado em %s", yamlURL)
			utils.BeepAlert()
		}

	}
}
