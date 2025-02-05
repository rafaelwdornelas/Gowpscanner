package utils

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	browser "github.com/EDDYCJY/fake-useragent"
)

func init() {
	// Redireciona a saída global dos logs para descartar todas as mensagens.
	log.SetOutput(io.Discard)
}

// Global http.Client reutilizável para todas as requisições, com timeout reduzido para acelerar o scan.
var client = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true, // Desabilita a reutilização de conexões
		MaxIdleConns:        100,  // Limita o número total de conexões inativas
		MaxIdleConnsPerHost: 10,   // Limita o número de conexões inativas por host
		MaxConnsPerHost:     100,  // Limita o número total de conexões por host
	},
	// Evita seguir redirecionamentos automaticamente.
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// TestURL faz uma requisição HEAD e retorna true se o status code estiver entre 200 e 399.
// Se a requisição HEAD falhar (por exemplo, se o servidor não suportar HEAD), tenta GET como fallback.
func TestURL(url string) bool {
	// Tenta primeiro com HEAD.
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", browser.Computer())

	resp, err := client.Do(req)
	if err != nil {
		// Fallback: tenta GET se HEAD falhar.
		req, err = http.NewRequest("GET", url, nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", browser.Computer())
		resp, err = client.Do(req)
		if err != nil {
			return false
		}
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

// GetBody retorna o conteúdo da URL se o status code for 200.
// Caso o status não seja 200, retorna um erro.
func GetBody(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", browser.Computer())
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status code %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
