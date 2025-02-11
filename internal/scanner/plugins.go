// internal\scanner\plugins.go
package scanner

import (
	"fmt"
	"strings"
	"sync"

	"Gowpscanner/internal/utils"
)

type PluginVulneravel struct {
	Slug        string
	Comparator  string
	Version     string
	Description string
}

var pluginList []PluginVulneravel
var pluginsCheck []string

var (
	dynamicFindersMap map[interface{}]interface{}
	dfErr             error
	dfOnce            sync.Once
)

// CheckPlugins faz a varredura de plugins vulneráveis
func CheckPlugins(baseURL, dominio string) {
	var contador int
	//proteção contra sites que retornam plugins falsos
	version, _ := extrairVersaoPlugins(baseURL, "plugin-nao-existe")
	if version != "" {
		utils.Warning("Plugin inexistente encontrado em %s", dominio)
		return
	}
	for _, slug := range pluginsCheck {
		contador++
		//caso o contador seja multiplo de 100, exibe mensagem
		if contador%100 == 0 {
			utils.Info("Verificando Plugins %s -  %d/%d", baseURL, contador, len(pluginsCheck))
		}
		version, urlReadme := extrairVersaoPlugins(baseURL, slug)
		if version != "" {
			var encontrouFalha bool
			for _, pluginInfo := range pluginList {
				if pluginInfo.Slug == slug {
					if pluginInfo.Description == "Timthumb" {
						utils.Warning("Plugin %s encontrado (Timthumb) em %s", slug, dominio)
						utils.BeepAlert()
						if processarTimThumbPlugins(baseURL, slug) {
							encontrouFalha = true
						}
					} else {
						vulneravel := utils.CompararVersao(version, pluginInfo.Version, pluginInfo.Comparator)
						if vulneravel {
							encontrouFalha = true
							salvaRetornoPlugin(
								pluginInfo.Slug,
								urlReadme,
								version,
								pluginInfo.Description,
							)
							utils.BeepAlert()
							utils.Warning("Plugin %s rodando versão %s em %s - %s", slug, version, dominio, pluginInfo.Description)
						}
					}
				}
			}
			if !encontrouFalha {
				utils.Ok("Plugin %s instalado (%s) na versão %s sem vulnerabilidades conhecidas", slug, dominio, version)
			}
		}
	}
}

// extrairVersaoPlugins tenta ler readme.txt e achar a versão
func extrairVersaoPlugins(baseURL, pluginSlug string) (string, string) {
	// Obtém o caminho do readme a partir do arquivo YAML (ou "readme.txt" caso não encontre)
	readmeFilename := GetPluginReadmePath(pluginSlug)
	urlReadme := fmt.Sprintf("%s/wp-content/plugins/%s/%s", baseURL, pluginSlug, readmeFilename)

	conteudo, err := utils.GetBody(urlReadme)
	if err != nil {
		return "", urlReadme
	}
	// Se conter tags HTML ou erros comuns, ignoramos
	if strings.Contains(conteudo, "<head") ||
		strings.Contains(conteudo, "<body") ||
		strings.Contains(conteudo, "Invalid Request") ||
		strings.Contains(conteudo, "Parse error") {
		return "", urlReadme
	}

	// Tenta pegar via "Stable tag" ou "Version"
	stable := utils.FromStableTagOrVersion(conteudo)
	if stable != "" {
		return stable, urlReadme
	}
	// Tenta pegar do changelog
	chg := utils.FromChangelogSection(conteudo)
	if chg != "" {
		return chg, urlReadme
	}
	return "", urlReadme
}

// GetPluginReadmePath retorna o valor do campo "path" do Readme para o plugin dado.
// Se não encontrar ou ocorrer algum erro, retorna "readme.txt".
func GetPluginReadmePath(pluginSlug string) string {
	if dynamicFindersMap == nil || dfErr != nil {
		return "readme.txt"
	}

	// Extrai a seção "plugins"
	pluginsSection, ok := dynamicFindersMap["plugins"]
	if !ok {
		// Se não houver a seção "plugins", retorna o padrão
		return "readme.txt"
	}
	pluginsMap, ok := pluginsSection.(map[interface{}]interface{})
	if !ok {
		return "readme.txt"
	}

	// Procura pelo plugin solicitado
	pluginEntry, ok := pluginsMap[pluginSlug]
	if !ok {
		// Se não encontrar o plugin, retorna o padrão
		return "readme.txt"
	}
	pluginMap, ok := pluginEntry.(map[interface{}]interface{})
	if !ok {
		return "readme.txt"
	}

	// Extrai o campo "Readme"
	readmeVal, ok := pluginMap["Readme"]
	if !ok {
		return "readme.txt"
	}
	readmeMap, ok := readmeVal.(map[interface{}]interface{})
	if !ok {
		return "readme.txt"
	}

	// Extrai a chave "path" dentro de "Readme"
	pathVal, ok := readmeMap["path"]
	if !ok {
		return "readme.txt"
	}
	pathStr, ok := pathVal.(string)
	if !ok {
		return "readme.txt"
	}
	return pathStr
}

// processarTimThumbPlugins verifica se há timthumbs associados ao plugin
func processarTimThumbPlugins(dominio, slug string) bool {
	for _, timthumb := range timthumbPaths {
		if strings.Contains(timthumb, "wp-content/plugins/"+slug) {
			urlTimthumb := fmt.Sprintf("%s/%s", dominio, timthumb)
			found, err := detectTimThumb(urlTimthumb)
			if err != nil {
				continue
			}
			if found {
				utils.LogSave(urlTimthumb, "timthumbs.txt")
				utils.BeepAlert()
				fmt.Printf("[INFO] Timthumb encontrado em %s\n", dominio)
				return true
			}
		}
	}
	return false
}

func salvaRetornoPlugin(pluginSlug, urlRef, versao, descricao string) {
	line := fmt.Sprintf("%s - versão encontrada: %s - %s", urlRef, versao, descricao)
	utils.LogSave(line, "plugins/"+pluginSlug+".txt")
}
