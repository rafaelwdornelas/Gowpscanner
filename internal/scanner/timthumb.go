// internal\scanner\timthumb.go
package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	browser "github.com/EDDYCJY/fake-useragent"
)

// Lista de caminhos do timthumb (carregada em algum momento)
var timthumbPaths []string

// detectTimThumb faz uma requisição e tenta identificar TimThumb e sua versão
func detectTimThumb(url string) (isFound bool, err error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, errReq := http.NewRequest("GET", url, nil)
	if errReq != nil {
		return false, fmt.Errorf("erro ao criar requisição: %v", errReq)
	}
	computer := browser.Computer()
	req.Header.Set("User-Agent", computer)

	resp, errDo := client.Do(req)
	if errDo != nil {
		return false, fmt.Errorf("erro ao acessar %s: %v", url, errDo)
	}
	defer resp.Body.Close()

	body, errRead := io.ReadAll(resp.Body)
	if errRead != nil {
		return false, fmt.Errorf("erro ao ler o body: %v", errRead)
	}
	content := string(body)

	// Heurística para identificar TimThumb
	if strings.Contains(content, "TimThumb") ||
		strings.Contains(content, "define('FILE_CACHE_TIME_BETWEEN_CLEANS'") ||
		strings.Contains(content, "no image specified") ||
		strings.Contains(content, "No image specified") {
		isFound = true
	}

	return isFound, nil
}
