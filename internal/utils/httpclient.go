package utils

import (
	"crypto/tls" // apenas para constantes e compatibilidade; não usamos o handshake padrão
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	browser "github.com/EDDYCJY/fake-useragent"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

func init() {
	// Redireciona a saída global dos logs para descartar todas as mensagens.
	log.SetOutput(io.Discard)
}

// dialTLS utiliza uTLS para criar uma conexão TLS customizada, imitando o handshake do Chrome.
func dialTLS(network, addr string) (net.Conn, error) {
	// Estabelece conexão TCP com timeout.
	conn, err := net.DialTimeout(network, addr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	// Extraí o hostname a partir do endereço "host:port".
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	// Configuração uTLS com definição explícita dos cipher suites.
	utlsConfig := &utls.Config{
		InsecureSkipVerify: true, // Use com cautela!
		ServerName:         host,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}

	// Se utls.HelloChrome_112 não estiver disponível, utilize utls.HelloChrome_118 ou outro preset disponível.
	uConn := utls.UClient(conn, utlsConfig, utls.HelloChrome_Auto)
	if err := uConn.Handshake(); err != nil {
		return nil, err
	}
	return uConn, nil
}

// newHTTPTransport cria um http.Transport customizado, utilizando uTLS para o handshake TLS
// e configurado para suportar HTTP/2.
func newHTTPTransport() *http.Transport {
	transport := &http.Transport{
		// DialContext para conexões não-TLS (caso necessário).
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		// Substitui o DialTLS padrão pela nossa implementação com uTLS.
		DialTLS: dialTLS,
		// Timeouts e configurações do transporte.
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       100,
	}

	// Habilita HTTP/2 no transporte.
	if err := http2.ConfigureTransport(transport); err != nil {
		log.Printf("Erro ao configurar HTTP/2: %v", err)
	}

	return transport
}

// Global http.Client reutilizável para todas as requisições, com timeout reduzido para acelerar o scan.
var client = &http.Client{
	Timeout:   10 * time.Second,
	Transport: newHTTPTransport(),
	// Evita seguir redirecionamentos automaticamente.
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// setDefaultHeaders adiciona cabeçalhos para simular um navegador real, com Client Hints e outros.
func setDefaultHeaders(req *http.Request) {
	req.Header.Set("User-Agent", browser.Computer())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")
	// Define o Referer e Origin com base no domínio da URL.
	if req.URL != nil {
		referer := fmt.Sprintf("%s://%s/", req.URL.Scheme, req.URL.Host)
		req.Header.Set("Referer", referer)
		req.Header.Set("Origin", fmt.Sprintf("%s://%s", req.URL.Scheme, req.URL.Host))
	}
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Cache-Control", "max-age=0")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Pragma", "no-cache")
	// Cabeçalhos Client Hints (disponíveis em navegadores modernos)
	req.Header.Set("Sec-CH-UA", `"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"`)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
}

// TestURL faz uma requisição HEAD e retorna true se o status code estiver entre 200 e 399.
// Se a requisição HEAD falhar (por exemplo, se o servidor não suportar HEAD), tenta GET como fallback.
func TestURL(url string) bool {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false
	}
	setDefaultHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		// Fallback: tenta GET se HEAD falhar.
		req, err = http.NewRequest("GET", url, nil)
		if err != nil {
			return false
		}
		setDefaultHeaders(req)
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
	setDefaultHeaders(req)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status code %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
