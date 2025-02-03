// internal\scanner\domain.go
package scanner

import (
	"Gowpscanner/internal/utils"
	"Gowpscanner/internal/wpdetect"
	"strings"
)

// processDomain verifica HTTP/HTTPS, detecta WordPress, etc.
func processDomain(dominio string) {
	//retira o http:// e https:// do dominio
	dominio = strings.Replace(dominio, "http://", "", -1)
	dominio = strings.Replace(dominio, "https://", "", -1)
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
			CheckShell(urlHTTPS)
			CheckEnv(urlHTTPS)
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
				CheckYaml(novaURL)
			} else {
				utils.Info("%s não parece ser WordPress", dominio)
				CheckShell(urlHTTP)
				CheckEnv(urlHTTP)
				CheckYaml(urlHTTP)
			}
		} else {
			// Tenta HTTPS com www
			urlHTTPS2 := "https://www." + dominio
			okHTTPS2 := utils.TestURL(urlHTTPS2)
			if okHTTPS2 {
				valido, novaURL := wpdetect.IsWordPress(urlHTTPS2)
				if valido {
					utils.LogSave(novaURL, "wordpress.txt")
					CheckConfigBackups(novaURL)
					CheckPlugins(novaURL, dominio)
					CheckThemes(novaURL, dominio)
					CheckShell(novaURL)
					CheckYaml(novaURL)
				} else {
					utils.Info("%s não parece ser WordPress", dominio)
					CheckShell(urlHTTPS2)
					CheckEnv(urlHTTPS2)
					CheckYaml(urlHTTPS2)
				}
			} else {
				// Tenta HTTPS com www
				urlHTTP2 := "http://www." + dominio
				okHTTP2 := utils.TestURL(urlHTTPS2)
				if okHTTP2 {
					valido, novaURL := wpdetect.IsWordPress(urlHTTP2)
					if valido {
						utils.LogSave(novaURL, "wordpress.txt")
						CheckConfigBackups(novaURL)
						CheckPlugins(novaURL, dominio)
						CheckThemes(novaURL, dominio)
						CheckShell(novaURL)
						CheckYaml(novaURL)
					} else {
						utils.Info("%s não parece ser WordPress", dominio)
						CheckShell(urlHTTP2)
						CheckEnv(urlHTTP2)
						CheckYaml(urlHTTP2)
					}
				} else {
					utils.Error("%s não está acessível em HTTP nem HTTPS", dominio)
				}
			}
		}
	}
}
