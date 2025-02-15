package wpdetect

import (
	"fmt"
	"net/http"
	"regexp"
	"time"

	"Gowpscanner/internal/utils"

	browser "github.com/EDDYCJY/fake-useragent"
)

// CheckDigitalOceanToken verifica a presença de tokens da DigitalOcean em um conteúdo fornecido.
func CheckDigitalOceanToken(content string) {
	// Expressão regular para capturar tokens de acesso pessoal da DigitalOcean
	patternDO := `(?i)\b(dop_v1_[a-z0-9]{64})\b`

	// Compilando a regex
	reDO, err := regexp.Compile(patternDO)
	if err != nil {
		fmt.Printf("Erro compilando regex DigitalOcean: %v\n", err)
		return
	}

	// Encontrando todos os matches no conteúdo
	matchesDO := reDO.FindAllString(content, -1)

	// Usando um mapa para remover duplicatas
	matchesMap := make(map[string]bool)
	for _, match := range matchesDO {
		matchesMap[match] = true
	}

	// Se não houver nenhum match, encerra a função.
	if len(matchesMap) == 0 {
		return
	}

	// Itera sobre cada token encontrado e os salva
	for token := range matchesMap {
		test := TestDigitalOceanToken(token)
		if !test {
			utils.LogSave(token, "digitalocean_tokens_die.txt")
		} else {

			utils.LogSave(token, "digitalocean_tokens_live.txt")
		}
		utils.Warning("Token DigitalOcean exposto encontrado: %s", token)
		utils.BeepAlert()
	}
}

// TestDigitalOceanToken verifica se um token DigitalOcean é válido.
func TestDigitalOceanToken(token string) bool {
	// Endpoint da API DigitalOcean para validação de token
	apiURL := "https://api.digitalocean.com/v2/account"

	// Criando um client HTTP com timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Criando a requisição GET com o token no cabeçalho de autorização
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", browser.Computer())

	// Executando a requisição
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Retorna verdadeiro se o status code for 200 (token válido)
	return resp.StatusCode == 200
}
