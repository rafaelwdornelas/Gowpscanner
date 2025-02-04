// internal\scanner\buscashell.go
package scanner

import (
	"fmt"
	"strings"

	"Gowpscanner/internal/utils"
)

// shellList (carregadas em init ou por outro método)
var shellList []string

// CheckShell verifica se existem arquivos shell expostos
func CheckShell(baseURL string) {
	var contador int = 0
	for _, shellpath := range shellList {
		contador++
		//caso o contador seja multiplo de 100, exibe mensagem
		if contador%100 == 0 {
			utils.Info("Verificando Shell %s -  %d/%d", baseURL, contador, len(shellList))
		}
		var buscatmp string
		if strings.Contains(shellpath, "|") {
			parts := strings.Split(shellpath, "|")
			shellpath = parts[0]
			buscatmp = parts[1]
		}
		urlConfig := fmt.Sprintf("%s/%s", baseURL, shellpath)
		conteudo, err := utils.GetBody(urlConfig)
		if err != nil {
			continue
		}

		containsLeaf := strings.Contains(strings.ToLower(conteudo), "leafmailer")
		containsPHPMailer := strings.Contains(strings.ToLower(conteudo), "phpmailer")
		containsUpload := strings.Contains(strings.ToLower(conteudo), " type=\"file\"")
		containsForm := strings.Contains(strings.ToLower(conteudo), " type=\"submit\"")
		containsOutros := strings.Contains(strings.ToLower(conteudo), strings.ToLower(buscatmp))

		if containsLeaf || containsPHPMailer {
			utils.Warning("Encontrado Leafmailer ou PHPMailer: %s", urlConfig)
			utils.LogSave(urlConfig, "shellmails.txt")
			utils.BeepAlert()
			utils.Warning("Shell %s encontrada em %s", shellpath, baseURL)
			//sai do loop
			break
		} else if containsUpload && containsForm {
			utils.Warning("Encontrado Upload ou Form: %s", urlConfig)
			utils.LogSave(urlConfig, "shellupload.txt")
			utils.BeepAlert()
			utils.Warning("Shell %s encontrada em %s", shellpath, baseURL)
			//sai do loop
			break
		} else if buscatmp != "" && containsOutros {
			utils.Warning("Encontrado Outros: %s", urlConfig)
			utils.LogSave(urlConfig, "shellupload.txt")
			utils.BeepAlert()
			utils.Warning("Shell %s encontrada em %s", shellpath, baseURL)
			//sai do loop
			break
		}
	}
}
