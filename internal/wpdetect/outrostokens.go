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

// Definimos nossa lista de tokens importantes.
var tokenPatterns = []TokenPattern{
	{
		ItemTitle:  "GCP",
		FieldTitle: "client id",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
	},
	{
		ItemTitle:  "Mailchimp",
		FieldTitle: "api key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`),
	},
	{
		ItemTitle:  "PayPal Braintree",
		FieldTitle: "access token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`access_token\$(production|sandbox)\[0-9a-z]{16}\$[0-9a-f]{32}`),
	},
	{
		ItemTitle:  "PayPal Braintree",
		FieldTitle: "client id",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`client_id\$(production|sandbox)\$[0-9a-z]{16}`),
	},
	{
		ItemTitle:  "PayPal Braintree",
		FieldTitle: "client secret",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`client_secret\$(production|sandbox)\$[0-9a-z]{32}`),
	},
	{
		ItemTitle:  "PayPal Braintree",
		FieldTitle: "tokenization key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(production|sandbox)_[0-9a-z]{8}_[0-9a-z]{16}`),
	},
	{
		ItemTitle:  "SendGrid",
		FieldTitle: "api key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`SG.[0-9A-Za-z-._]{66}`),
	},
	{
		ItemTitle:  "Slack",
		FieldTitle: "api token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`xox[p|b|o|a]-[0-9]{12}-[0-9]{12,13}-[a-zA-Z0-9]{23,32}`),
	},
	{
		ItemTitle:  "Slack",
		FieldTitle: "webhook",
		FieldType:  "url",
		Pattern:    regexp.MustCompile(`https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]{9}\/[A-Z0-9]{9,11}\/[a-zA-Z0-9]+`),
	},
	{
		ItemTitle:  "DigitalOcean",
		FieldTitle: "access token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`dop_v1_[a-z0-9]{64}`),
	},
	{
		ItemTitle:  "Supabase",
		FieldTitle: "api-key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`sbp_[a-zA-Z0-9]{40}`),
	},
	{
		ItemTitle:  "Typeform",
		FieldTitle: "personal access token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`tfp_[a-zA-Z0-9]{44}_[a-zA-Z0-9]{14}`),
	},
	{
		ItemTitle:  "Stripe",
		FieldTitle: "publishable key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`pk_(test|live)_[0-9a-zA-Z]{24,99}`),
	},
	{
		ItemTitle:  "Stripe",
		FieldTitle: "secret key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`sk_(test|live)_[0-9a-zA-Z]{24,99}`),
	},
	{
		ItemTitle:  "Twilio",
		FieldTitle: "api key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
	},
	{
		ItemTitle:  "GitHub",
		FieldTitle: "token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`(gh[pous]_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{76})`),
	},
	{
		ItemTitle:  "HubSpot",
		FieldTitle: "webhook",
		FieldType:  "url",
		Pattern:    regexp.MustCompile(`https://api\.hubapi\.com/webhooks/v1/[a-z0-9]+/`),
	},
	{
		ItemTitle:  "HubSpot",
		FieldTitle: "private app token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`pat-(na|eu)1-[a-fA-F\d]{4}(?:[a-fA-F\d]{4}-){4}[a-fA-F\d]{12}`),
	},
	{
		ItemTitle:  "SSH Key",
		FieldTitle: "private key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`[-]{3,}BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE)? ?(PRIVATE)? KEY[-]{3,}[\D\d\s]*[-]{3,}END (RSA|DSA|EC|OPENSSH|PRIVATE)? ?(PRIVATE)? KEY[-]{3,}(\n)?`),
	},
	{
		ItemTitle:  "UUID (genérico)",
		FieldTitle: "uuid",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`[a-fA-F\d]{4}(?:[a-fA-F\d]{4}-){4}[a-fA-F\d]{12}`),
	},
	{
		ItemTitle:  "Amazon MWS",
		FieldTitle: "auth token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	},
	{
		ItemTitle:  "Google",
		FieldTitle: "oauth token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`ya29\.[0-9A-Za-z-_]+`),
	},
	{
		ItemTitle:  "Mailgun",
		FieldTitle: "api key",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
	},
	{
		ItemTitle:  "Square",
		FieldTitle: "access token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`sq0atp-[0-9A-Za-z-_]{22}`),
	},
	{
		ItemTitle:  "Square",
		FieldTitle: "oauth token",
		FieldType:  "concealed",
		Pattern:    regexp.MustCompile(`sq0csp-[0-9A-Za-z-_]{43}`),
	},
	{
		ItemTitle:  "Twilio",
		FieldTitle: "webhook",
		FieldType:  "url",
		Pattern:    regexp.MustCompile(`https://chat\.twilio\.com/v2/Services/[A-Z0-9]{32}`),
	},
	// Exemplos adicionais de tokens importantes:
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
				// Salvamos no arquivo tokens.txt
				utils.LogSave(registro, "tokens.txt")
			}
		}
	}
}
