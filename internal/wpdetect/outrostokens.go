package wpdetect

import (
	"fmt"
	"regexp"
	"strings"

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
		Pattern:    regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*([0-9a-zA-Z/+=]{40})`),
	},
	{
		ItemTitle:  "AWS",
		FieldTitle: "Session Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)aws_session_token\s*=\s*([A-Za-z0-9/+=]{16,})`),
	},
	{
		ItemTitle:  "Azure",
		FieldTitle: "Shared Key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(?i)SharedKey\s+[^\s]+:[A-Za-z0-9+/=]+`),
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
	{
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
	},
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
	/* {
		ItemTitle:  "Twilio",
		FieldTitle: "Auth Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`[0-9a-fA-F]{32}`), // Possível confusão com chaves genéricas, mas comum no Twilio
	}, */
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
		Pattern:    regexp.MustCompile(`(?i)heroku_api_key\s*=\s*([0-9a-fA-F]{32})`),
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
		Pattern:    regexp.MustCompile(`pat-(na|eu)1-[a-fA-F\\d]{4}(?:[a-fA-F\\d]{4}-){4}[a-fA-F\\d]{12}`),
	},
	{
		ItemTitle:  "SSH Key",
		FieldTitle: "Private Key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`[-]{3,}BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE)? ?(PRIVATE)? KEY[-]{3,}[\\D\\d\\s]*[-]{3,}END (RSA|DSA|EC|OPENSSH|PRIVATE)? ?(PRIVATE)? KEY[-]{3,}(\\n)?`),
	},
	/* {
		ItemTitle:  "UUID (genérico)",
		FieldTitle: "uuid",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`[a-fA-F\\d]{4}(?:[a-fA-F\\d]{4}-){4}[a-fA-F\\d]{12}`),
	}, */
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
	// Zoom JWT token (exemplo)
	{
		ItemTitle:  "Zoom",
		FieldTitle: "JWT Token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+`),
	},
	/* // Basic auth no formato user:pass (cuidado com falsos positivos)
	{
		ItemTitle:  "BasicAuth",
		FieldTitle: "Credentials",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`[A-Za-z0-9+\/=]+:[A-Za-z0-9+\/=]+`), // Pode gerar falsos positivos
	}, */
}

// CheckAllTokens procura todos os tokens definidos em tokenPatterns e salva em tokens.txt
// no formato "NOME_DO_TOKEN|TOKEN_ENCONTRADO".
func CheckAllTokens(content string, url string) {
	for _, tp := range tokenPatterns {
		// Se o ItemTitle não estiver preenchido, usamos o FieldTitle.
		tokenName := tp.ItemTitle
		if strings.TrimSpace(tokenName) == "" {
			tokenName = tp.FieldTitle
		}

		matches := tp.Pattern.FindAllString(content, -1)
		if len(matches) > 0 {
			for _, match := range matches {
				registro := fmt.Sprintf("%s|%s|%s", tokenName, match, url)
				utils.Warning(registro)
				utils.BeepAlert()
				utils.LogSave(registro, "tokens.txt")
			}
		}
	}
}
