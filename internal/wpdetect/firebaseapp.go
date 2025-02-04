package wpdetect

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"

	"Gowpscanner/internal/utils"

	browser "github.com/EDDYCJY/fake-useragent"
)

// CheckFirebaseIO procura por links Firebase na string de entrada, testa cada um e salva os que estão vulneráveis em firebaseio.txt.
func CheckFirebaseIO(content string) {
	// Expressões regulares para capturar links com firebaseio.com
	patternFirebaseio := `(?i)[a-z0-9.-]+\.firebaseio\.com`

	// Compilando as regexes
	reFirebaseio, err := regexp.Compile(patternFirebaseio)
	if err != nil {
		fmt.Printf("Erro compilando regex firebaseio: %v\n", err)
		return
	}

	// Encontrando todos os matches na string de entrada
	matchesFirebaseio := reFirebaseio.FindAllString(content, -1)

	// Usando um mapa para remover duplicatas
	matchesMap := make(map[string]bool)
	for _, match := range matchesFirebaseio {
		matchesMap[match] = true
	}

	// Se não houver nenhum match, encerra a função.
	if len(matchesMap) == 0 {
		return
	}

	// Itera sobre cada link encontrado e testa a vulnerabilidade

	for link := range matchesMap {
		if TestInsecureFirebase(link) {
			// Salva os links vulneráveis no arquivo firebaseio.txt
			utils.LogSave("https://"+link+"/.json - InsecureFirebase", "firebaseio.txt")
			utils.Warning("Links Firebase vulneráveis encontrados: %s", link)
			utils.BeepAlert()
		} else if TestFirebaseOpenRead(link) {
			utils.LogSave("https://"+link+"/.json - OpenRead", "firebaseio.txt")
			utils.Warning("Link Firebase com leitura aberta encontrado: %s", link)
			utils.BeepAlert()
		} else {
			utils.Info("Link Firebase encontrado, mas não vulnerável: %s", link)
		}
	}
}

// TestInsecureFirebase testa se o host Firebase (por exemplo, "example.firebaseio.com")
// está vulnerável (i.e. com regras inseguras que permitem PUT e GET sem restrição)
// conforme a definição do teste "insecure-firebase-database".
func TestInsecureFirebase(host string) bool {
	// Garante que o host possua protocolo HTTPS.
	urlBase := "https://" + host

	// Gera uma string aleatória para o teste.
	randStr := RandString(8)
	testPath := fmt.Sprintf("/%s.json", randStr)
	testURL := urlBase + testPath

	// Prepara o payload para o teste.
	payload := `{"id":"insecure-firebase-database"}`

	// Cria um client HTTP com timeout e configuração para ignorar verificação TLS.
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Executa a requisição PUT para tentar escrever um item.
	reqPUT, err := http.NewRequest("PUT", testURL, strings.NewReader(payload))
	if err != nil {
		return false
	}
	reqPUT.Header.Set("Content-Type", "application/json")
	reqPUT.Header.Set("User-Agent", browser.Computer())

	respPUT, err := client.Do(reqPUT)
	if err != nil {
		return false
	}
	// Descarta o corpo da resposta do PUT.
	io.Copy(io.Discard, respPUT.Body)
	respPUT.Body.Close()

	// Aguarda um curto período para garantir que o PUT seja processado.
	time.Sleep(500 * time.Millisecond)

	// Executa a requisição GET para ler o item inserido.
	reqGET, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return false
	}
	reqGET.Header.Set("User-Agent", browser.Computer())
	respGET, err := client.Do(reqGET)
	if err != nil {
		return false
	}
	defer respGET.Body.Close()

	// Verifica se o status code é 200.
	if respGET.StatusCode != 200 {
		return false
	}

	// Verifica se o header Content-Type contém "application/json".
	contentType := respGET.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "application/json") {
		return false
	}

	// Lê o corpo da resposta.
	bodyBytes, err := io.ReadAll(respGET.Body)
	if err != nil {
		return false
	}
	bodyStr := string(bodyBytes)

	// Verifica se o corpo contém a string do payload, indicando que o PUT foi bem-sucedido.
	if strings.Contains(bodyStr, `"id":"insecure-firebase-database"`) {
		return true
	}
	return false
}

// RandString gera uma string aleatória de tamanho n.
func RandString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	// Inicializa a semente do rand se ainda não estiver.
	rand.Seed(time.Now().UnixNano())
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// TestFirebaseOpenRead testa se o host Firebase possui leitura aberta
// ao acessar "https://{host}/.json". Retorna true se o status code for 200.
func TestFirebaseOpenRead(host string) bool {
	// Constrói a URL de teste.
	testURL := "https://" + host + "/.json"

	// Cria um client HTTP com timeout e configuração para ignorar verificação TLS.
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Prepara a requisição GET.
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", browser.Computer())

	// Executa a requisição.
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Retorna true se o status code for 200, indicando acesso aberto.
	return resp.StatusCode == 200
}
