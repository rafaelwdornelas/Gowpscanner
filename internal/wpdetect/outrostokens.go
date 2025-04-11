package wpdetect

import (
	"fmt"
	"regexp"

	"Gowpscanner/internal/utils"
)

// TokenPattern representa o padrão de cada token que queremos buscar.
type TokenPattern struct {
	ItemTitle  string
	FieldTitle string
	FieldType  string
	Pattern    *regexp.Regexp
}

// Definimos nossa lista de tokens importantes (o máximo possível) que podem representar falhas de segurança ao serem expostos.
var tokenPatterns = []TokenPattern{
	{
		ItemTitle:  "AWS",
		FieldTitle: "Access Key ID",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	},
	{
		ItemTitle:  "AWS",
		FieldTitle: "Secret Access Key",
		FieldType:  "concealed",
		// Permite valor direto ou entre aspas simples/duplas
		Pattern: regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*['"]?([0-9a-zA-Z/+=]{40})['"]?`),
	},
	{
		ItemTitle:  "AWS",
		FieldTitle: "Session Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)aws_session_token\s*=\s*['"]?([A-Za-z0-9/+=]{16,})['"]?`),
	},
	{
		ItemTitle:  "Azure",
		FieldTitle: "Shared Key",
		FieldType:  "concealed",
		// Não há atribuição; o padrão permanece o mesmo
		Pattern: regexp.MustCompile(`(?i)SharedKey\s+[^\s]+:[A-Za-z0-9+/=]+`),
	},
	{
		ItemTitle:  "Azure",
		FieldTitle: "Connection String",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)DefaultEndpointsProtocol=.*;AccountName=.*;AccountKey=.*;EndpointSuffix=.*`),
	},
	{
		ItemTitle:  "GCP",
		FieldTitle: "Service Account Key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`"type": "service_account",\s*"project_id": ".*",\s*"private_key_id": "[a-z0-9]+",\s*"private_key": "-----BEGIN PRIVATE KEY-----\\n.*\\n-----END PRIVATE KEY-----`),
	},
	{
		ItemTitle:  "GCP",
		FieldTitle: "Client ID",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com`),
	},
	{
		ItemTitle:  "GitHub",
		FieldTitle: "token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(gh[pous]_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{76})`),
	},
	{
		ItemTitle:  "GitHub",
		FieldTitle: "OAuth Access Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`gho_[A-Za-z0-9_]{36,}`),
	},
	{
		ItemTitle:  "GitHub",
		FieldTitle: "Refresh Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`ghr_[A-Za-z0-9_]{76}`),
	},
	{
		ItemTitle:  "GitLab",
		FieldTitle: "Personal Access Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`glpat-[A-Za-z0-9-_=]{20,}`),
	},
	{
		ItemTitle:  "Slack",
		FieldTitle: "API Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`xox[p|b|o|a]-[0-9]{12}-[0-9]{12,13}-[a-zA-Z0-9]{23,32}`),
	},
	{
		ItemTitle:  "Slack",
		FieldTitle: "Webhook",
		FieldType:  "url",
		Pattern:    regexp.MustCompile(`https:\/\/hooks\\.slack\\.com\/services\/[A-Z0-9]{9}\/[A-Z0-9]{9,11}\/[a-zA-Z0-9]+`),
	},
	/*{
		ItemTitle:  "Stripe",
		FieldTitle: "Publishable Key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`pk_(test|live)_[0-9a-zA-Z]{24,99}`),
	},
	{
		ItemTitle:  "Stripe",
		FieldTitle: "Secret Key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`sk_(test|live)_[0-9a-zA-Z]{24,99}`),
	},*/
	{
		ItemTitle:  "Square",
		FieldTitle: "Access Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`sq0atp-[0-9A-Za-z-_]{22}`),
	},
	{
		ItemTitle:  "Square",
		FieldTitle: "OAuth Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`sq0csp-[0-9A-Za-z-_]{43}`),
	},
	{
		ItemTitle:  "Twilio",
		FieldTitle: "API Key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
	},
	{
		ItemTitle:  "Twilio",
		FieldTitle: "Account SID",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`AC[0-9a-fA-F]{32}`),
	},
	{
		ItemTitle:  "Twilio",
		FieldTitle: "Webhook",
		FieldType:  "url",
		Pattern:    regexp.MustCompile(`https://chat\\.twilio\\.com/v2/Services/[A-Z0-9]{32}`),
	},
	{
		ItemTitle:  "SendGrid",
		FieldTitle: "API Key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`SG\\.[0-9A-Za-z-._]{66}`),
	},
	{
		ItemTitle:  "Mailchimp",
		FieldTitle: "API Key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`),
	},
	{
		ItemTitle:  "Mailgun",
		FieldTitle: "API Key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
	},
	{
		ItemTitle:  "DigitalOcean",
		FieldTitle: "Access Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`dop_v1_[a-z0-9]{64}`),
	},
	{
		ItemTitle:  "Heroku",
		FieldTitle: "API Key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)heroku_api_key\s*=\s*['"]?([0-9a-fA-F]{32})['"]?`),
	},
	{
		ItemTitle:  "Google",
		FieldTitle: "OAuth Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`ya29\\.[0-9A-Za-z-_]+`),
	},
	{
		ItemTitle:  "PayPal Braintree",
		FieldTitle: "Access Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`access_token\\$(production|sandbox)\\[0-9a-z]{16}\\$[0-9a-f]{32}`),
	},
	{
		ItemTitle:  "PayPal Braintree",
		FieldTitle: "Client ID",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`client_id\\$(production|sandbox)\\$[0-9a-z]{16}`),
	},
	{
		ItemTitle:  "PayPal Braintree",
		FieldTitle: "Client Secret",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`client_secret\\$(production|sandbox)\\$[0-9a-z]{32}`),
	},
	{
		ItemTitle:  "PayPal Braintree",
		FieldTitle: "Tokenization Key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(production|sandbox)_[0-9a-z]{8}_[0-9a-z]{16}`),
	},
	{
		ItemTitle:  "Supabase",
		FieldTitle: "API Key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`sbp_[a-zA-Z0-9]{40}`),
	},
	{
		ItemTitle:  "Typeform",
		FieldTitle: "Personal Access Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`tfp_[a-zA-Z0-9]{44}_[a-zA-Z0-9]{14}`),
	},
	{
		ItemTitle:  "HubSpot",
		FieldTitle: "Webhook",
		FieldType:  "url",
		Pattern:    regexp.MustCompile(`https://api\\.hubapi\\.com/webhooks/v1/[a-z0-9]+/`),
	},
	{
		ItemTitle:  "HubSpot",
		FieldTitle: "Private App Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`pat-(na|eu)1-[a-fA-F\d]{4}(?:[a-fA-F\d]{4}-){4}[a-fA-F\d]{12}`),
	},
	{
		ItemTitle:  "SSH Key",
		FieldTitle: "Private Key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`[-]{3,}BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE)? ?(PRIVATE)? KEY[-]{3,}[\\D\\d\\s]*[-]{3,}END (RSA|DSA|EC|OPENSSH|PRIVATE)? ?(PRIVATE)? KEY[-]{3,}(\\n)?`),
	},
	{
		ItemTitle:  "Amazon MWS",
		FieldTitle: "Auth Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	},
	// Figma tokens (exemplo)
	{
		ItemTitle:  "Figma",
		FieldTitle: "Personal Access Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`FIGMA_TOKEN_[0-9a-zA-Z_-]+`),
	},
	// Okta tokens (exemplo)
	{
		ItemTitle:  "Okta",
		FieldTitle: "API Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`00[0-9a-zA-Z]{28}\.[0-9a-zA-Z]{6}\.[0-9a-zA-Z-]{43}`),
	},
	/* // Zoom JWT token (exemplo)
	{
		ItemTitle:  "Zoom",
		FieldTitle: "JWT Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+`),
	}, */
	// Tokens Getnet para ambiente sem aspas e com prefixo GETNET_
	{
		ItemTitle:  "Getnet",
		FieldTitle: "Client ID",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)getnet[_]?client[_]?id\s*[:=]\s*['"]?([a-f0-9-]+)['"]?`),
	},
	{
		ItemTitle:  "Getnet",
		FieldTitle: "Client Secret",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)getnet[_]?client[_]?secret\s*[:=]\s*['"]?([A-Za-z0-9]+)['"]?`),
	},
	{
		ItemTitle:  "Getnet",
		FieldTitle: "Seller ID",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)getnet[_]?seller[_]?id\s*[:=]\s*['"]?([a-f0-9-]+)['"]?`),
	},
	// Detecção da URL da API Getnet permanece igual:
	{
		ItemTitle:  "Getnet",
		FieldTitle: "API URL",
		FieldType:  "url",
		Pattern:    regexp.MustCompile(`https:\/\/api\.getnet\.com\.br`),
	},

	// APIs de pagamento adicionais

	// Mercado Pago
	{
		ItemTitle:  "Mercado Pago",
		FieldTitle: "Access Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)mercado[_-]?pago[_-]?access[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9-]+)['"]?`),
	},
	// PagSeguro
	{
		ItemTitle:  "PagSeguro",
		FieldTitle: "Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)pagseguro\s*token\s*[:=]\s*['"]?([A-Za-z0-9]+)['"]?`),
	},
	// Cielo - Merchant ID
	{
		ItemTitle:  "Cielo",
		FieldTitle: "Merchant ID",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)merchant_id\s*[:=]\s*['"]?([A-Za-z0-9-]+)['"]?`),
	},
	// Cielo - Merchant Key
	{
		ItemTitle:  "Cielo",
		FieldTitle: "Merchant Key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)merchant_key\s*[:=]\s*['"]?([A-Za-z0-9-]+)['"]?`),
	},
	// Pagar.me
	{
		ItemTitle:  "Pagar.me",
		FieldTitle: "API Key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)pagar\.?me[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]+)['"]?`),
	},
	// Adyen
	{
		ItemTitle:  "Adyen",
		FieldTitle: "API Key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)adyen[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]+)['"]?`),
	},
	// Iugu
	{
		ItemTitle:  "Iugu",
		FieldTitle: "API Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)iugu[_-]?api[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9]+)['"]?`),
	},
	// Rede - Merchant ID
	{
		ItemTitle:  "Rede",
		FieldTitle: "Merchant ID",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)rede[_-]?merchant[_-]?id\s*[:=]\s*['"]?([A-Za-z0-9-]+)['"]?`),
	},
	// Rede - Access Token
	{
		ItemTitle:  "Rede",
		FieldTitle: "Access Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)rede[_-]?access[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9]+)['"]?`),
	},
}

// CheckAllTokens procura todos os tokens definidos em tokenPatterns, agrupa por serviço e só exibe
// os tokens dos serviços que não dependem de múltiplos campos ou somente se todos os campos obrigatórios
// forem encontrados (ex.: Cielo e Getnet).
func CheckAllTokens(content string, url string) {
	// Mapa para agrupar os tokens encontrados: serviço -> campo -> valor
	found := make(map[string]map[string]string)

	// Itera por cada padrão, buscando as correspondências
	for _, tp := range tokenPatterns {
		// Usa FindAllStringSubmatch para capturar grupos, se houver
		matches := tp.Pattern.FindAllStringSubmatch(content, -1)
		if len(matches) > 0 {
			// Usa apenas a primeira correspondência para cada padrão
			var tokenValue string
			// Se existir um grupo capturado, usa-o; caso contrário, usa a string encontrada
			if len(matches[0]) > 1 {
				tokenValue = matches[0][1]
			} else {
				tokenValue = matches[0][0]
			}
			// Inicializa o mapa do serviço se necessário
			if found[tp.ItemTitle] == nil {
				found[tp.ItemTitle] = make(map[string]string)
			}
			// Registra o token encontrado para o campo
			found[tp.ItemTitle][tp.FieldTitle] = tokenValue
		}
	}

	// Agora, para serviços com múltiplos campos obrigatórios, só exibe se todos forem encontrados
	// Exemplo: Cielo precisa de Merchant ID e Merchant Key; Getnet precisa de Client ID, Client Secret e Seller ID
	requiredFields := map[string][]string{
		"Cielo":  {"Merchant ID", "Merchant Key"},
		"Getnet": {"Client ID", "Client Secret", "Seller ID"},
	}

	for service, fields := range found {
		// Se o serviço possui campos obrigatórios, verifica se todos foram encontrados
		if req, exists := requiredFields[service]; exists {
			missing := false
			for _, field := range req {
				if _, ok := fields[field]; !ok {
					missing = true
					break
				}
			}
			// Se algum campo estiver faltando, ignora os tokens deste serviço
			if missing {
				continue
			}
		}
		// Exibe os tokens encontrados para o serviço
		for _, tokenValue := range fields {
			registro := fmt.Sprintf("%s|%s|%s", service, tokenValue, url)
			utils.Warning("%s", registro)
			utils.BeepAlert()
			utils.LogSave(registro, "tokens.txt")
		}
	}
}
