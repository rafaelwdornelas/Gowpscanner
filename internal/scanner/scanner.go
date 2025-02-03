// internal\scanner\scanner.go
package scanner

import (
	"Gowpscanner/internal/utils"
	"Gowpscanner/pkg/update"
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

var (
	//LIMITE DE CONCORRÊNCIA
	concurrencyLimit = 400
	// Testar plugins?
	testarPlugins = true
	// Testar temas?
	testarTemas = true
	// Testar shells?
	testarShells = true
	// Testar .env?
	testarEnv = true
	// Testar timthumbs?
	testarTimthumbs = true
)

// Códigos ANSI para cores
const (
	ColorReset   = "\033[0m"
	ColorCyan    = "\033[36m"
	ColorYellow  = "\033[33m"
	ColorMagenta = "\033[35m"
)

func init() {
	// 1) Atualiza a base de dados (ou verifica se está atualizada)
	update.BaixaDatabase()

	// 2) Cria as pastas de retornos (antes de rodar)
	utils.CreateFolders()
	// Carrega variáveis de ambiente
	// Tenta carregar o arquivo .env (ele deve estar na raiz do projeto)
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Nenhum arquivo .env encontrado, usando valores padrão")
	}

	// Atualiza as variáveis se as variáveis de ambiente estiverem definidas
	if val := os.Getenv("CONCURRENCY_LIMIT"); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			concurrencyLimit = n
		}
	}
	if val := os.Getenv("TESTAR_PLUGINS"); val != "" {
		testarPlugins = strings.ToLower(val) == "true"
	}
	if val := os.Getenv("TESTAR_TEMAS"); val != "" {
		testarTemas = strings.ToLower(val) == "true"
	}
	if val := os.Getenv("TESTAR_SHELLS"); val != "" {
		testarShells = strings.ToLower(val) == "true"
	}
	if val := os.Getenv("TESTAR_ENV"); val != "" {
		testarEnv = strings.ToLower(val) == "true"
	}
	if val := os.Getenv("TESTAR_TIMTHUMBS"); val != "" {
		testarTimthumbs = strings.ToLower(val) == "true"
	}

	// Exemplo:
	configList = utils.CarregarListas("database/config_backups.txt")
	dbExportsList = utils.CarregarListas("database/db_exports.txt")
	timthumbPaths = utils.CarregarListas("database/timthumbs-v3.txt")
	if testarShells {
		shellList = utils.CarregarListas("shells.txt")
	}

	if testarEnv {
		envList = utils.CarregarListas("envs.txt")
	}
	dynamicFindersMap = utils.LoadDynamicFinders()

	if testarPlugins {
		// Carrega plugins
		pList := utils.CarregarPluginsVulneraveis("plugins.txt")
		for _, p := range pList {
			pluginList = append(pluginList, PluginVulneravel{
				Slug: p.Slug, Comparator: p.Comparator, Version: p.Version, Description: p.Description,
			})
		}
	}

	if testarTemas {
		// Carrega themes
		tList := utils.CarregarPluginsVulneraveis("themes.txt")
		for _, t := range tList {
			themesList = append(themesList, PluginVulneravel{
				Slug: t.Slug, Comparator: t.Comparator, Version: t.Version, Description: t.Description,
			})
		}
	}

	if testarTimthumbs {
		//faz um for em todos os timthumbs e pega todos que começam com wp-content/plugins/ e adiciona na lista de plugins a serem verificados
		for _, timthumb := range timthumbPaths {
			if strings.Contains(timthumb, "wp-content/plugins/") {
				plugin := strings.Split(timthumb, "/")
				// Na hora de inserir:
				if !existsPlugin(pluginList, plugin[2], "Timthumb") {

					//fmt.Println(plugin[2])
					pluginList = append(pluginList, PluginVulneravel{
						Slug:        plugin[2],
						Comparator:  "all",
						Version:     "0",
						Description: "Timthumb",
					})
				}
			} else if strings.Contains(timthumb, "wp-content/themes/") {
				theme := strings.Split(timthumb, "/")
				//fmt.Println(theme[2])
				if !existsPlugin(themesList, theme[2], "Timthumb") {
					//fmt.Println("Adicionando theme")
					themesList = append(themesList, PluginVulneravel{
						Slug:        theme[2],
						Comparator:  "all",
						Version:     "0",
						Description: "Timthumb",
					})
				}
			}
		}
	}

	// Gera a lista de slugs
	for _, plg := range pluginList {
		if !strings.Contains(strings.Join(pluginsCheck, " "), plg.Slug) {
			pluginsCheck = append(pluginsCheck, plg.Slug)
		}
	}
	for _, th := range themesList {
		if !strings.Contains(strings.Join(themesCheck, " "), th.Slug) {
			themesCheck = append(themesCheck, th.Slug)
		}
	}

	// Banner ASCII com cores (exibido em CIANO)
	fmt.Println(string(ColorCyan))
	fmt.Println(` #####    #####   ##   ##  ######    #####    #####     ###    ##   ##  ##   ##  #######  ######   
##   ##  ##   ##  ##   ##  ##   ##  ##   ##  ##   ##   ## ##   ###  ##  ###  ##  ##       ##   ##  
##       ##   ##  ##   ##  ##   ##  ##       ##       ##   ##  #### ##  #### ##  ##       ##   ##  
##  ###  ##   ##  ## # ##  ##   ##   #####   ##       ##   ##  ## ####  ## ####  #####    ##   ##  
##   ##  ##   ##  #######  ######        ##  ##       #######  ##  ###  ##  ###  ##       ######   
##   ##  ##   ##  ### ###  ##       ##   ##  ##   ##  ##   ##  ##   ##  ##   ##  ##       ##  ##   
 #####    #####   ##   ##  ##        #####    #####   ##   ##  ##   ##  ##   ##  #######  ##   ##  
                                                                                                   
 
by @rafaelwdornelas`)
	fmt.Println(string(ColorReset))

	// Exibe uma tabela formatada com cores (utilizando amarelo para os separadores)
	printTable()

	// Pausa para leitura (5 segundos)
	time.Sleep(5 * time.Second)

}

func printTable() {
	// Cabeçalho da tabela
	separator := string(ColorYellow) + "=============================================================" + string(ColorReset)
	subSeparator := string(ColorYellow) + "-------------------------------------------------------------" + string(ColorReset)

	fmt.Println(separator)
	fmt.Printf("| %-35s | %-12s |\n", "Informação", "Valor")
	fmt.Println(separator)

	// Linhas com contadores
	fmt.Printf("| %-35s | %-12d |\n", "Plugins Carregados", len(pluginList))
	fmt.Printf("| %-35s | %-12d |\n", "Themes Carregados", len(themesList))
	fmt.Println(subSeparator)
	fmt.Printf("| %-35s | %-12s |\n", "Quantidade de Checagens Únicas:", "")
	fmt.Println(subSeparator)
	fmt.Printf("| %-35s | %-12d |\n", "Plugins", len(pluginsCheck))
	fmt.Printf("| %-35s | %-12d |\n", "Themes", len(themesCheck))
	fmt.Printf("| %-35s | %-12d |\n", "Shells", len(shellList))
	fmt.Printf("| %-35s | %-12d |\n", ".Envs", len(envList))
	fmt.Println(separator)
}

func existsPlugin(pluginList []PluginVulneravel, slug, description string) bool {
	for _, p := range pluginList {
		if p.Slug == slug && p.Description == description {
			return true
		}
	}
	return false
}

// Run lê o arquivo de domínios e coordena o processo de escaneamento
func Run(domainsFile string) error {
	file, err := os.Open(domainsFile)
	if err != nil {
		return fmt.Errorf("erro ao abrir %s: %w", domainsFile, err)
	}
	defer file.Close()

	limitCh := make(chan struct{}, concurrencyLimit)
	var wg sync.WaitGroup

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := scanner.Text()
		if domain == "" {
			continue
		}

		limitCh <- struct{}{}
		wg.Add(1)

		go func(d string) {
			defer wg.Done()
			processDomain(d)
			<-limitCh
		}(domain)
	}

	wg.Wait()
	return scanner.Err()
}
