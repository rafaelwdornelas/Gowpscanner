// internal\wpdetect\detect.go
package wpdetect

import (
	"net/url"
	"regexp"
	"strings"

	"Gowpscanner/internal/utils"
)

func IsWordPress(baseURL string) (bool, string) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return false, ""
	}

	// Monta variações
	urlsToTry := []string{
		parsedURL.String(),
	}

	// /blog
	blogURL := *parsedURL
	blogURL.Path = "/blog"
	urlsToTry = append(urlsToTry, blogURL.String())

	// /wp
	wpURL := *parsedURL
	wpURL.Path = "/wp"
	urlsToTry = append(urlsToTry, wpURL.String())

	// www
	wwwURL := *parsedURL
	wwwURL.Host = "www." + wwwURL.Host
	urlsToTry = append(urlsToTry, wwwURL.String())

	// www/blog
	wwwBlogURL := *parsedURL
	wwwBlogURL.Path = "/blog"
	wwwBlogURL.Host = "www." + wwwBlogURL.Host
	urlsToTry = append(urlsToTry, wwwBlogURL.String())

	// www/wp
	wwwWPURL := *parsedURL
	wwwWPURL.Path = "/wp"
	wwwWPURL.Host = "www." + wwwWPURL.Host
	urlsToTry = append(urlsToTry, wwwWPURL.String())

	// subdomínio blog.
	host := parsedURL.Host
	if strings.HasPrefix(host, "www.") {
		host = host[4:]
	}
	subdomainURL := *parsedURL
	subdomainURL.Host = "blog." + host
	urlsToTry = append(urlsToTry, subdomainURL.String())

	for _, u := range urlsToTry {
		body, err := utils.GetBody(u)
		if err != nil {
			continue
		}
		CheckFirebaseIO(body)
		CheckDigitalOceanToken(body)
		// Checa sinais de WordPress
		if strings.Contains(body, "wp-content") ||
			strings.Contains(body, "wp-includes") ||
			strings.Contains(body, `generator" content="WordPress`) {
			// Extrai a versão a partir do meta tag generator.
			// Essa expressão regular procura por:
			//   <meta name="generator" content="WordPress 6.7.1">
			// O (?i) torna a busca case-insensitive.
			re := regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']WordPress\s*([\d\.]+)["']`)
			match := re.FindStringSubmatch(body)
			if len(match) > 1 {
				version := match[1]
				utils.Ok("%s parece ser WordPress", u)
				utils.Ok("Versão do WordPress: %s", version)
				// Salva na pasta ./retornos/version/+version.txt
				utils.LogSave(u, "version/"+version+".txt")
			} else {
				utils.Info("%s parece ser WordPress", u)
				utils.Info("Versão do WordPress não encontrada no meta tag generator.")
			}

			return true, u
		}
	}
	return false, ""
}
