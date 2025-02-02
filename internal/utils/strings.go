// internal\utils\strings.go
package utils

import (
	"fmt"
	"net/url"
	"strings"
)

// ExtrairNomeBase remove TLD e retorna a parte "principal"
func ExtrairNomeBase(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("URL inválida: %v", err)
	}
	host := u.Host
	// remove :porta
	if idx := strings.IndexRune(host, ':'); idx != -1 {
		host = host[:idx]
	}
	// remove www.
	host = strings.TrimPrefix(host, "www.")

	if !strings.Contains(host, ".") {
		return host, nil
	}
	partes := strings.Split(host, ".")
	n := len(partes)

	tldSimples := map[string]bool{
		"com": true, "net": true, "org": true, "gov": true,
	}

	if partes[n-1] == "br" && n >= 2 {
		if tldSimples[partes[n-2]] {
			partes = partes[:n-2]
		} else {
			partes = partes[:n-2]
		}
	} else {
		if tldSimples[partes[n-1]] {
			partes = partes[:n-1]
		}
	}
	if len(partes) == 0 {
		return "", fmt.Errorf("não há nome-base após remover TLD")
	}
	return partes[len(partes)-1], nil
}
