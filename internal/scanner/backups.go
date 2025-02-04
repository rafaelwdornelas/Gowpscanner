// internal\scanner\backups.go
package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"Gowpscanner/internal/utils"
)

// ConfigLists (carregadas em init ou por outro método)
var configList []string
var dbExportsList []string

// CheckConfigBackups verifica se existem arquivos de configuração expostos
func CheckConfigBackups(baseURL string) {
	var contador int = 0
	for _, config := range configList {
		contador++
		//caso o contador seja multiplo de 100, exibe mensagem
		if contador%100 == 0 {
			utils.Info("Verificando Backups %s -  %d/%d", baseURL, contador, len(configList))
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

		// Remove espaços em branco e verifica por SMTP
		conteudo = strings.ReplaceAll(conteudo, " ", "")
		pattern := `(?m)^define\(\s*'(SMTP_[^']+)'\s*,\s*'([^']*)'\s*\)\s*;`
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(conteudo, -1)

		// Se encontrar algum match, salva no arquivo smtpconfigs.txt
		if len(matches) > 0 {
			var smtpLinhas []string
			for _, match := range matches {
				linha := fmt.Sprintf("%s => %s", match[1], match[2])
				smtpLinhas = append(smtpLinhas, linha)
			}
			smtpTexto := fmt.Sprintf("URL: %s\n%s\n\n", urlConfig, strings.Join(smtpLinhas, "|"))
			utils.LogSave(smtpTexto, "smtpconfigs.txt")
			utils.BeepAlert()
			utils.Warning("Configuração SMTP encontrada em %s e salva em smtpconfig.txt", urlConfig)
		}
	}
}
