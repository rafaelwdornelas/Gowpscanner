// internal\scanner\themes.go
package scanner

import (
	"fmt"
	"strings"

	"Gowpscanner/internal/utils"
)

var themesList []PluginVulneravel
var themesCheck []string

// CheckThemes faz a varredura de temas vulneráveis
func CheckThemes(baseURL, dominio string) {
	var contador int
	for _, slug := range themesCheck {
		contador++
		//caso o contador seja multiplo de 100, exibe mensagem
		if contador%100 == 0 {
			utils.Info("Verificando Themes %s -  %d/%d", baseURL, contador, len(shellList))
		}
		version := extrairVersaoThemes(baseURL, slug)
		if version != "" {
			var encontrouFalha bool
			for _, themeInfo := range themesList {
				if themeInfo.Slug == slug {
					if themeInfo.Description == "Timthumb" {
						utils.LogSave(fmt.Sprintf("%s/wp-content/themes/%s/style.css | version:%s", baseURL, slug, version), "TemasTimthumb.txt")
						if processarTimThumbThemes(baseURL, slug) {
							encontrouFalha = true
						}
					} else {
						vulneravel := utils.CompararVersao(version, themeInfo.Version, themeInfo.Comparator)
						if vulneravel {
							encontrouFalha = true
							salvaRetornoThemes(
								themeInfo.Slug,
								fmt.Sprintf("%s/wp-content/themes/%s/style.css", baseURL, slug),
								version,
								themeInfo.Description,
							)
							utils.BeepAlert()
							utils.Warning("Tema %s rodando versão %s em %s - %s", slug, version, dominio, themeInfo.Description)
						}
					}
				}
			}
			if !encontrouFalha {
				utils.Ok("Tema %s instalado (%s) na versão %s sem vulnerabilidades conhecidas", slug, dominio, version)
			}
		}
	}
}

func salvaRetornoThemes(themeSlug, urlRef, versao, descricao string) {
	line := fmt.Sprintf("%s - versão encontrada: %s - %s", urlRef, versao, descricao)
	utils.LogSave(line, "themes/"+themeSlug+".txt")
}

func extrairVersaoThemes(baseURL, themeSlug string) string {
	urlStyle := fmt.Sprintf("%s/wp-content/themes/%s/style.css", baseURL, themeSlug)

	conteudo, err := utils.GetBody(urlStyle)
	if err != nil {
		return ""
	}
	if strings.Contains(conteudo, "<head") ||
		strings.Contains(conteudo, "<body") ||
		strings.Contains(conteudo, "Invalid Request") ||
		strings.Contains(conteudo, "Parse error") {
		return ""
	}

	stable := utils.FromStableTagOrVersion(conteudo)
	if stable != "" {
		return stable
	}
	chg := utils.FromChangelogSection(conteudo)
	if chg != "" {
		return chg
	}
	utils.LogSave(urlStyle, "erros.txt")
	return ""
}

// processarTimThumbThemes verifica Timthumb em temas
func processarTimThumbThemes(dominio, slug string) bool {
	for _, timthumb := range timthumbPaths {
		if strings.Contains(timthumb, "wp-content/themes/"+slug) {
			urlTimthumb := fmt.Sprintf("%s/%s", dominio, timthumb)
			utils.Info("Verificando Timthumb em %s", urlTimthumb)
			found, err := detectTimThumb(urlTimthumb)
			if err != nil {
				continue
			}
			if found {
				utils.LogSave(urlTimthumb, "timthumbs.txt")
				utils.BeepAlert()
				utils.Warning("Timthumb encontrado em %s", dominio)
				return true
			}
		}
	}
	return false
}
