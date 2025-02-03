package scanner

import (
	"fmt"
	"strings"

	"Gowpscanner/internal/utils"
)

// yamlList contém os caminhos (ou nomes de arquivos) para verificar arquivos YAML/YML.
// Esses caminhos podem ser definidos na função init ou carregados de outro modo.
var yamlList []string

// CheckYaml verifica se o domínio possui um arquivo YAML/YML com informações sensíveis.
// Se for encontrado, registra a URL e as vulnerabilidades detectadas no arquivo yaml-production.txt.
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

		// Converte o conteúdo para minúsculas para facilitar as comparações.
		lowerContent := strings.ToLower(content)

		// Se o conteúdo contiver HTML, ignora esse caminho.
		if strings.Contains(lowerContent, "<html") || strings.Contains(lowerContent, "<!doctype html") {
			continue
		}

		// Acumula os nomes das vulnerabilidades detectadas.
		var vulnerabilities []string

		// Exemplos de testes simples (cada um adiciona um rótulo caso seja detectado):
		if strings.Contains(lowerContent, "api_key:") {
			vulnerabilities = append(vulnerabilities, "API Key")
		}
		if strings.Contains(lowerContent, "db_password:") {
			vulnerabilities = append(vulnerabilities, "DB Password")
		}
		if strings.Contains(lowerContent, "secret:") {
			vulnerabilities = append(vulnerabilities, "Secret")
		}
		if strings.Contains(lowerContent, "token:") {
			vulnerabilities = append(vulnerabilities, "Token")
		}
		if strings.Contains(lowerContent, "private_key:") {
			vulnerabilities = append(vulnerabilities, "Private Key")
		}
		if strings.Contains(lowerContent, "access_key:") {
			vulnerabilities = append(vulnerabilities, "Access Key")
		}
		if strings.Contains(lowerContent, "access_token:") {
			vulnerabilities = append(vulnerabilities, "Access Token")
		}
		if strings.Contains(lowerContent, "consumer_key:") {
			vulnerabilities = append(vulnerabilities, "Consumer Key")
		}
		if strings.Contains(lowerContent, "consumer_secret:") {
			vulnerabilities = append(vulnerabilities, "Consumer Secret")
		}
		if strings.Contains(lowerContent, "smtp:") {
			vulnerabilities = append(vulnerabilities, "SMTP")
		}
		if strings.Contains(lowerContent, "password:") {
			vulnerabilities = append(vulnerabilities, "Password")
		}

		// Testes com múltiplas condições:
		if strings.Contains(lowerContent, "jobs:") && strings.Contains(lowerContent, "version:") {
			vulnerabilities = append(vulnerabilities, "CircleCI Config")
		}
		if strings.Contains(lowerContent, "kind:") && strings.Contains(lowerContent, "name:") {
			vulnerabilities = append(vulnerabilities, "Drone Config")
		}
		if strings.Contains(lowerContent, "secret_key_base") || strings.Contains(lowerContent, "config.secret_token") {
			vulnerabilities = append(vulnerabilities, "Rails Secret")
		}
		if strings.Contains(lowerContent, "#note: please uncomment those") ||
			strings.Contains(lowerContent, "may break your openstack environment") ||
			strings.Contains(lowerContent, "os_auth_url") ||
			strings.Contains(lowerContent, "os_username") ||
			strings.Contains(lowerContent, "os_tenant_name") ||
			strings.Contains(lowerContent, "os_region_name") ||
			strings.Contains(lowerContent, "os_project_name") ||
			strings.Contains(lowerContent, "os_identity_api_version") {
			vulnerabilities = append(vulnerabilities, "OpenStack Secrets")
		}
		if strings.Contains(lowerContent, "production:") ||
			strings.Contains(lowerContent, "adapter:") ||
			strings.Contains(lowerContent, "database:") ||
			strings.Contains(lowerContent, "username:") ||
			strings.Contains(lowerContent, "password:") ||
			strings.Contains(lowerContent, "host:") {
			vulnerabilities = append(vulnerabilities, "Redmine DB Config")
		}
		if strings.Contains(lowerContent, "host:") ||
			strings.Contains(lowerContent, "name:") ||
			strings.Contains(lowerContent, "pass:") {
			vulnerabilities = append(vulnerabilities, "MariaDB Credentials")
		}
		if strings.Contains(lowerContent, "user_name") && strings.Contains(lowerContent, "password") && strings.Contains(lowerContent, "redmine") {
			vulnerabilities = append(vulnerabilities, "Redmine Config")
		}
		if strings.Contains(lowerContent, "paths:") && strings.Contains(lowerContent, "settings:") {
			vulnerabilities = append(vulnerabilities, "Codeception Config")
		}
		if strings.Contains(lowerContent, "service:") && strings.Contains(lowerContent, "local:") {
			vulnerabilities = append(vulnerabilities, "Rails Storage Config")
		}
		if strings.Contains(lowerContent, "adapter:") && strings.Contains(lowerContent, "database:") && strings.Contains(lowerContent, "production:") {
			vulnerabilities = append(vulnerabilities, "Rails DB Config")
		}
		if strings.Contains(lowerContent, "linters:") && strings.Contains(lowerContent, "linters-settings:") {
			vulnerabilities = append(vulnerabilities, "GolangCI Config")
		}
		if strings.Contains(lowerContent, "build:") && strings.Contains(lowerContent, "filter:") && strings.Contains(lowerContent, "tools:") {
			vulnerabilities = append(vulnerabilities, "Scrutinizer Config")
		}
		if strings.Contains(lowerContent, "version:") && strings.Contains(lowerContent, "os:") && strings.Contains(lowerContent, "files:") {
			vulnerabilities = append(vulnerabilities, "Appspec Config")
		}
		if strings.Contains(lowerContent, "options:") && strings.Contains(lowerContent, "formatter:") && strings.Contains(lowerContent, "files:") {
			vulnerabilities = append(vulnerabilities, "Sass Lint Config")
		}
		if strings.Contains(lowerContent, "class:") && strings.Contains(lowerContent, "param:") {
			vulnerabilities = append(vulnerabilities, "Symfony DB Config")
		}
		if strings.Contains(lowerContent, "parameters:") && strings.Contains(lowerContent, "database_user:") && strings.Contains(lowerContent, "database_password:") {
			vulnerabilities = append(vulnerabilities, "Parameters Config")
		}
		if strings.Contains(lowerContent, "install:") && strings.Contains(lowerContent, "test_script:") {
			vulnerabilities = append(vulnerabilities, "AppVeyor Config")
		}
		if strings.Contains(lowerContent, "paths:") && strings.Contains(lowerContent, "environments:") && strings.Contains(lowerContent, "development:") {
			vulnerabilities = append(vulnerabilities, "Phinx Config")
		}
		if strings.Contains(lowerContent, "trigger:") && strings.Contains(lowerContent, "pool:") && strings.Contains(lowerContent, "variables:") {
			vulnerabilities = append(vulnerabilities, "Azure Pipelines Config")
		}
		if strings.Contains(lowerContent, "jekyll:") && strings.Contains(lowerContent, "title:") && strings.Contains(lowerContent, "baseurl:") {
			vulnerabilities = append(vulnerabilities, "Github Pages Config")
		}
		if strings.Contains(lowerContent, "ssh_authorized_keys") && strings.Contains(lowerContent, "#cloud-config") {
			vulnerabilities = append(vulnerabilities, "Cloud Config")
		}
		if strings.Contains(lowerContent, "default:") && strings.Contains(lowerContent, "paths:") && strings.Contains(lowerContent, "suites:") {
			vulnerabilities = append(vulnerabilities, "Behat Config")
		}
		if strings.Contains(lowerContent, "host:") && strings.Contains(lowerContent, "name:") && strings.Contains(lowerContent, "pass:") {
			vulnerabilities = append(vulnerabilities, "CakePHP Config")
		}
		if strings.Contains(lowerContent, "database:") && strings.Contains(lowerContent, "protected_web_paths:") {
			vulnerabilities = append(vulnerabilities, "Pantheon Config")
		}
		if strings.Contains(lowerContent, "dsn:") && strings.Contains(lowerContent, "username:") && strings.Contains(lowerContent, "password:") {
			vulnerabilities = append(vulnerabilities, "qdPM DB Credentials")
		}
		if strings.Contains(lowerContent, "version:") && strings.Contains(lowerContent, "services:") {
			vulnerabilities = append(vulnerabilities, "Docker Compose")
		}
		if strings.Contains(lowerContent, "suites:") && strings.Contains(lowerContent, "main:") && strings.Contains(lowerContent, "namespace:") {
			vulnerabilities = append(vulnerabilities, "Phpspec Config")
		}
		if strings.Contains(lowerContent, "allcops:") && strings.Contains(lowerContent, "include:") && strings.Contains(lowerContent, "exclude:") {
			vulnerabilities = append(vulnerabilities, "Rubocop Config")
		}
		if strings.Contains(lowerContent, "pipelines:") && strings.Contains(lowerContent, "step:") {
			vulnerabilities = append(vulnerabilities, "BitBucket Pipelines")
		}
		if strings.Contains(lowerContent, "security:") && strings.Contains(lowerContent, "providers:") {
			vulnerabilities = append(vulnerabilities, "Symfony Security")
		}

		// Se houver vulnerabilidades, registra a URL com os detalhes.
		if len(vulnerabilities) > 0 {
			logLine := fmt.Sprintf("%s - Vulnerabilidades: %s", yamlURL, strings.Join(vulnerabilities, ", "))
			utils.LogSave(logLine, "yaml-production.txt")
			utils.Warning("Arquivo YAML sensível encontrado: %s", logLine)
			utils.BeepAlert()
		}
	}
}
