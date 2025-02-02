// internal\scanner\domain.go
package scanner

import (
	"Gowpscanner/internal/utils"
	"Gowpscanner/internal/wpdetect"
)

// processDomain verifica HTTP/HTTPS, detecta WordPress, etc.
func processDomain(dominio string) {
	// Testa HTTPS
	urlHTTPS := "https://" + dominio
	okHTTPS := utils.TestURL(urlHTTPS)

	if okHTTPS {
		valido, novaURL := wpdetect.IsWordPress(urlHTTPS)
		if valido {
			utils.LogSave(novaURL, "wordpress.txt")
			CheckConfigBackups(novaURL)
			CheckPlugins(novaURL, dominio)
			CheckThemes(novaURL, dominio)
			CheckShell(novaURL)
		} else {
			utils.Info("%s não parece ser WordPress", dominio)
		}
	} else {
		// Tenta HTTP
		urlHTTP := "http://" + dominio
		okHTTP := utils.TestURL(urlHTTP)
		if okHTTP {
			valido, novaURL := wpdetect.IsWordPress(urlHTTP)
			if valido {
				utils.LogSave(novaURL, "wordpress.txt")
				CheckConfigBackups(novaURL)
				CheckPlugins(novaURL, dominio)
				CheckThemes(novaURL, dominio)
				CheckShell(novaURL)
			} else {
				utils.Info("%s não parece ser WordPress", dominio)
			}
		} else {
			utils.Error("%s não está acessível em HTTP nem HTTPS", dominio)
		}
	}
}
